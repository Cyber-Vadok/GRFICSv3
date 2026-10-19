"""Minimal OpenAI-compatible chat client (stdlib only).

Works against any server that implements POST {base_url}/chat/completions:
the bundled mock model, a local vLLM / Ollama / llama.cpp server exposing a
Qwen3 model, or a hosted endpoint. No third-party packages required, so it
runs on a resource-limited machine without `pip install`.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request


class LLMError(RuntimeError):
    pass


class LLMClient:
    def __init__(self, base_url: str, api_key: str = "", *, timeout: int = 300):
        # base_url is expected to already include the "/v1" suffix.
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or "not-needed"
        self.timeout = timeout
        # Local inference servers frequently use self-signed TLS or plain HTTP;
        # don't let certificate verification break a lab run.
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

    def chat(
        self,
        model: str,
        messages: list[dict],
        *,
        temperature: float = 0.6,
        max_tokens: int = 1536,
    ) -> str:
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=data,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx) as resp:
                body = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:  # pragma: no cover - network dependent
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise LLMError(f"HTTP {exc.code} from {self.base_url}: {detail}") from exc
        except urllib.error.URLError as exc:  # pragma: no cover - network dependent
            raise LLMError(
                f"Cannot reach LLM endpoint {self.base_url}: {exc.reason}. "
                f"Is the model server (or --mock) running?"
            ) from exc

        try:
            obj = json.loads(body)
            return obj["choices"][0]["message"]["content"] or ""
        except (ValueError, KeyError, IndexError) as exc:
            raise LLMError(f"Unexpected response shape: {body[:500]}") from exc

    def ping(self) -> bool:
        """True if {base_url}/models answers."""
        req = urllib.request.Request(
            f"{self.base_url}/models",
            headers={"Authorization": f"Bearer {self.api_key}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=5, context=self._ssl_ctx) as resp:
                return resp.status == 200
        except Exception:
            return False
