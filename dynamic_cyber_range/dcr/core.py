"""Agent state, action parsing, and the tool executor (scope-enforced).

The executor is the trust boundary: every side effect an agent can have on the
range goes through here, and here is where scope, dry-run and timeouts are
enforced -- mirroring the scope constraints the paper added iteratively
(Appendix A.2: "OpenStack infrastructure is out of scope", anti-cheating rules).
"""

from __future__ import annotations

import base64
import json
import re
import shutil
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from .llm import LLMClient

_ACTION_RE = re.compile(r"```action\s*(\{.*?\})\s*```", re.DOTALL)
_ANY_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


def parse_action(text: str) -> dict | None:
    """Extract the single action object from a model message.

    Prefers a ```action fenced block; falls back to the first JSON object in the
    message so slightly-misformatted real-model output still drives the loop.
    """
    m = _ACTION_RE.search(text)
    raw = m.group(1) if m else None
    if raw is None:
        m2 = _ANY_JSON_RE.search(text)
        raw = m2.group(0) if m2 else None
    if raw is None:
        return None
    try:
        obj = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(obj, dict) or "tool" not in obj:
        return None
    obj.setdefault("args", {})
    if not isinstance(obj["args"], dict):
        obj["args"] = {}
    return obj


@dataclass
class Agent:
    role: str                 # "red" | "blue"
    model: str
    system_prompt: str
    client: LLMClient
    temperature: float = 0.6
    max_tokens: int = 4096
    reasoning_mode: str = "log"      # "log" | "off" | "ignore"
    messages: list[dict] = field(default_factory=list)
    done: bool = False
    turns: int = 0
    last_reasoning: str | None = None

    def __post_init__(self):
        if not self.messages:
            self.messages = [{"role": "system", "content": self.system_prompt}]

    def _user(self, text: str) -> str:
        # In "off" mode, suppress model thinking at the source (Qwen soft switch).
        return f"/no_think {text}" if self.reasoning_mode == "off" else text

    def kickoff(self, operator_message: str):
        self.messages.append({"role": "user", "content": self._user(operator_message)})

    def ask(self) -> str:
        content, reasoning = self.client.chat(
            self.model, self.messages,
            temperature=self.temperature, max_tokens=self.max_tokens,
        )
        # Keep the (clean) answer in context; never feed thinking back in.
        self.messages.append({"role": "assistant", "content": content})
        self.last_reasoning = None if self.reasoning_mode in ("off", "ignore") else reasoning
        self.turns += 1
        return content

    def observe(self, observation: str):
        self.messages.append({"role": "user", "content": self._user(f"OBSERVATION:\n{observation}")})


class Executor:
    """Runs tool actions against the live range, enforcing per-role scope."""

    RED_TOOLS = {"think", "shell", "report", "finish"}
    BLUE_TOOLS = {"think", "shell", "wazuh_query", "report", "finish"}

    def __init__(self, scenario: dict, *, dry_run: bool = False):
        self.scenario = scenario
        self.dry_run = dry_run
        limits = scenario.get("limits", {})
        self.shell_timeout = int(limits.get("shell_timeout_sec", 60))
        self.obs_limit = int(limits.get("observation_char_limit", 4000))

        self.red_scope = set(scenario["red"].get("scope_containers", ["kali"]))
        self.red_default_host = scenario["red"].get("platform_container", "kali")
        blue = scenario.get("blue", {}) or {}
        self.blue_scope = set(blue.get("manage_containers", []))
        self.blue_default_host = next(iter(blue.get("manage_containers", ["router"])), "router")

        mon = (blue.get("monitoring") or {})
        self.wazuh_api = mon.get("wazuh_api", "https://localhost:55000")
        self.wazuh_user = mon.get("wazuh_user", "wazuh")
        self.wazuh_pass = mon.get("wazuh_pass", "wazuh")
        self._wazuh_token: str | None = None

        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE
        self._docker = shutil.which("docker")

    # -- dispatch -----------------------------------------------------------
    def run(self, role: str, action: dict) -> tuple[str, bool]:
        """Execute one action. Returns (observation, finished)."""
        tool = str(action.get("tool", "")).strip()
        args = action.get("args", {}) or {}
        allowed = self.RED_TOOLS if role == "red" else self.BLUE_TOOLS
        if tool not in allowed:
            return (f"[refused] tool '{tool}' is not permitted for the {role} role. "
                    f"Allowed: {sorted(allowed)}", False)

        if tool == "think":
            return (f"[noted] {args.get('note', '').strip()[:200]}", False)
        if tool == "report":
            return ("[report recorded]", False)
        if tool == "finish":
            return (f"[session finished] {args.get('summary', '').strip()[:300]}", True)
        if tool == "shell":
            return (self._shell(role, args), False)
        if tool == "wazuh_query":
            return (self._wazuh(args), False)
        return (f"[refused] unknown tool '{tool}'", False)

    # -- tools --------------------------------------------------------------
    def _in_scope(self, role: str, host: str) -> bool:
        return host in (self.red_scope if role == "red" else self.blue_scope)

    def _shell(self, role: str, args: dict) -> str:
        cmd = str(args.get("cmd", "")).strip()
        host = str(args.get("host") or (
            self.red_default_host if role == "red" else self.blue_default_host)).strip()
        if not cmd:
            return "[error] shell action needs a 'cmd'."
        if not self._in_scope(role, host):
            scope = sorted(self.red_scope if role == "red" else self.blue_scope)
            return (f"[refused:scope] host '{host}' is out of scope for {role}. "
                    f"In scope: {scope}")
        if self.dry_run:
            return f"[dry-run] would run on {host}:\n$ {cmd}"
        if not self._docker:
            return "[error] docker CLI not found on the orchestration host."
        # sh -c for portability across the different base images; augment PATH so
        # admin tools (iptables, etc.) resolve in a non-login shell.
        wrapped = f"export PATH=$PATH:/usr/sbin:/sbin:/usr/local/sbin; {cmd}"
        try:
            proc = subprocess.run(
                [self._docker, "exec", host, "sh", "-c", wrapped],
                capture_output=True, text=True, timeout=self.shell_timeout,
            )
        except subprocess.TimeoutExpired:
            return f"[timeout] command exceeded {self.shell_timeout}s on {host}"
        except Exception as exc:  # pragma: no cover
            return f"[error] docker exec failed: {exc}"
        out = (proc.stdout or "") + (proc.stderr or "")
        return self._truncate(f"($ on {host}, rc={proc.returncode})\n{out.strip()}")

    def _wazuh(self, args: dict) -> str:
        if self.dry_run:
            return f"[dry-run] would query Wazuh {args.get('method','GET')} {args.get('path','')}"
        path = str(args.get("path", "/")).strip()
        method = str(args.get("method", "GET")).upper()
        params = args.get("params") or {}
        if not path.startswith("/"):
            path = "/" + path
        try:
            if self._wazuh_token is None:
                self._wazuh_token = self._wazuh_auth()
            url = self.wazuh_api.rstrip("/") + path
            if params:
                url += "?" + urllib.parse.urlencode(params)
            req = urllib.request.Request(
                url, method=method,
                headers={"Authorization": f"Bearer {self._wazuh_token}"},
            )
            with urllib.request.urlopen(req, timeout=15, context=self._ssl_ctx) as resp:
                body = resp.read().decode("utf-8", "replace")
            return self._truncate(f"(Wazuh {method} {path})\n{body}")
        except urllib.error.HTTPError as exc:
            return f"[wazuh error] HTTP {exc.code}: {exc.read().decode('utf-8','replace')[:300]}"
        except Exception as exc:
            return (f"[wazuh error] {exc}. Endpoint {self.wazuh_api} -- is the "
                    f"'siem' profile up (docker compose --profile siem up -d)?")

    def _wazuh_auth(self) -> str:
        url = self.wazuh_api.rstrip("/") + "/security/user/authenticate?raw=true"
        # Send Basic auth preemptively: Wazuh's authenticate endpoint answers 401
        # with a JSON body and no standard WWW-Authenticate challenge, so urllib's
        # reactive HTTPBasicAuthHandler never attaches the credentials.
        token = base64.b64encode(
            f"{self.wazuh_user}:{self.wazuh_pass}".encode()).decode()
        req = urllib.request.Request(
            url, method="POST", headers={"Authorization": f"Basic {token}"})
        with urllib.request.urlopen(req, timeout=15, context=self._ssl_ctx) as resp:
            return resp.read().decode("utf-8", "replace").strip()

    def _truncate(self, text: str) -> str:
        if len(text) <= self.obs_limit:
            return text
        return text[: self.obs_limit] + f"\n...[truncated {len(text) - self.obs_limit} chars]"
