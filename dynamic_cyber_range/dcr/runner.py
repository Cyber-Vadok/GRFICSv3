"""Session orchestration: static (red only) and dynamic (red + blue) modes.

Static  = conventional cyber range: the APT agent operates alone.
Dynamic = Dynamic Cyber Range: a Defender agent runs concurrently with the APT
          agent (here: interleaved single-step turns, with a blue head start,
          to produce a readable correlated timeline). See the paper, Section 3.
"""

from __future__ import annotations

import datetime as _dt
import json
import pathlib
import sys

from . import metrics
from .core import Agent, Executor, parse_action
from .llm import LLMClient
from .prompts import blue_system_prompt, red_system_prompt


def load_scenario(path: str) -> dict:
    p = pathlib.Path(path)
    text = p.read_text()
    if p.suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover
            raise SystemExit(
                "PyYAML not installed and scenario is YAML. Either `pip install pyyaml` "
                "or convert the scenario to .json."
            ) from exc
        return yaml.safe_load(text)
    return json.loads(text)


class Transcript:
    def __init__(self, run_dir: pathlib.Path):
        self.run_dir = run_dir
        run_dir.mkdir(parents=True, exist_ok=True)
        self.jsonl = (run_dir / "transcript.jsonl").open("w")
        self.events: list[dict] = []

    def log(self, **event):
        event["ts"] = _dt.datetime.now().isoformat(timespec="seconds")
        self.events.append(event)
        self.jsonl.write(json.dumps(event, ensure_ascii=False) + "\n")
        self.jsonl.flush()

    def close(self):
        self.jsonl.close()


COLORS = {"red": "\033[91m", "blue": "\033[94m", "sys": "\033[90m", "off": "\033[0m"}


def _say(role: str, kind: str, text: str):
    c = COLORS.get(role, "")
    tag = {"red": "RED ", "blue": "BLUE", "sys": "SYS "}.get(role, role)
    print(f"{c}[{tag}] {kind}:{COLORS['off']} {text}")


def _one_turn(agent: Agent, executor: Executor, tx: Transcript) -> None:
    """Advance a single agent by one TRACE step."""
    if agent.done:
        return
    max_turns = _max_turns(executor.scenario, agent.role)
    if agent.turns >= max_turns:
        agent.done = True
        _say(agent.role, "limit", f"reached max turns ({max_turns})")
        return

    reply = agent.ask()
    reasoning = agent.last_reasoning
    if reasoning:
        _say(agent.role, "reason", reasoning.replace("\n", " ")[:200])
    action = parse_action(reply)
    if action is None:
        _say(agent.role, "no-action", reply.strip()[:160] or "(empty content - thinking may have used all max_tokens)")
        tx.log(role=agent.role, turn=agent.turns, kind="no_action", message=reply, reasoning=reasoning)
        agent.observe("No valid ```action block found. Emit exactly one action block.")
        return

    tool = action.get("tool")
    rationale = str(action.get("rationale", "")).strip()
    preview = json.dumps(action.get("args", {}), ensure_ascii=False)
    _say(agent.role, tool, f"{rationale[:100]}  {preview[:160]}")

    observation, finished = executor.run(agent.role, action)
    tx.log(role=agent.role, turn=agent.turns, kind="action", action=action,
           observation=observation, finished=finished, reasoning=reasoning)
    _say(agent.role, "obs", observation.replace("\n", " ")[:200])

    if finished:
        agent.done = True
    else:
        agent.observe(observation)


def _max_turns(scenario: dict, role: str) -> int:
    return int(scenario.get("limits", {}).get("max_turns_per_agent", 8))


def run(scenario: dict, options: dict) -> pathlib.Path:
    mode = scenario.get("mode", "static")
    name = scenario.get("name", "scenario")
    base_url = options["base_url"]
    api_key = options.get("api_key", "")
    dry_run = options.get("dry_run", False)

    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    slug = "".join(c if c.isalnum() else "-" for c in name.lower())[:40].strip("-")
    run_dir = pathlib.Path(options["runs_dir"]) / f"{stamp}_{slug}"
    tx = Transcript(run_dir)

    _say("sys", "scenario", f"{name}  (mode={mode}, dry_run={dry_run})")
    _say("sys", "backend", f"{base_url}  red={options['red_model']}"
         + (f"  blue={options['blue_model']}" if mode == "dynamic" else ""))
    tx.log(role="sys", kind="start", scenario=name, mode=mode, options={
        k: options[k] for k in ("base_url", "red_model", "blue_model", "dry_run")})

    executor = Executor(scenario, dry_run=dry_run)
    temperature = float(options.get("temperature", 0.6))
    # reasoning: CLI overrides scenario; scenario key `reasoning:` else default "log".
    reasoning_mode = options.get("reasoning_mode") or scenario.get("reasoning", "log")
    cli_max = options.get("max_tokens")
    max_tokens = int(cli_max) if cli_max else int(scenario.get("limits", {}).get("max_tokens", 4096))
    _say("sys", "reasoning", f"mode={reasoning_mode}, max_tokens={max_tokens}")

    red_client = LLMClient(base_url, api_key)
    red = Agent("red", options["red_model"], red_system_prompt(scenario), red_client,
                temperature=temperature, max_tokens=max_tokens, reasoning_mode=reasoning_mode)
    red.kickoff(scenario["red"]["operator_message"])

    if mode == "static":
        while not red.done:
            _one_turn(red, executor, tx)
    elif mode == "dynamic":
        blue_client = LLMClient(base_url, api_key)
        blue = Agent("blue", options["blue_model"], blue_system_prompt(scenario),
                     blue_client, temperature=temperature, max_tokens=max_tokens,
                     reasoning_mode=reasoning_mode)
        blue.kickoff(scenario["blue"]["operator_message"])

        head_start = int(scenario.get("blue", {}).get("head_start_turns", 2))
        _say("sys", "schedule", f"blue head start = {head_start} turn(s), then interleaved")
        for _ in range(head_start):
            if blue.done:
                break
            _one_turn(blue, executor, tx)
        # Interleave until both finish or both hit their turn caps.
        while not (red.done and blue.done):
            _one_turn(red, executor, tx)
            _one_turn(blue, executor, tx)
    else:
        raise SystemExit(f"Unknown mode '{mode}' (expected 'static' or 'dynamic').")

    # Score the run against the flag scheme + OT process state.
    base_dir = pathlib.Path(options.get("base_dir", run_dir.parent.parent))
    flags_state = metrics.load_flags_state(scenario, base_dir)
    if flags_state is None:
        _say("sys", "metrics", "no flag manifest/state found; scoring skipped "
             "(run flags/plant_flags.py and add a flags: block to the scenario)")
        m = None
    else:
        m = metrics.compute(tx.events, scenario, flags_state, dry_run=dry_run)
        (run_dir / "metrics.json").write_text(json.dumps(m, ensure_ascii=False, indent=2))
        a = m["attacker"]
        line = (f"attacker {a['flags_captured']}/{a['flags_total']} flags "
                f"({a['attacker_success_pct']}% success), OT impact={'YES' if a['ot_impact'] else 'no'}"
                f", 1st flag={a['time_to_first_flag_min']} min")
        if "defender" in m:
            line += f" | defender denied {m['defender']['defender_success_pct']}%"
        _say("sys", "metrics", line)

    _write_summary(run_dir, scenario, tx, m)
    tx.close()
    _say("sys", "done", f"transcript + summary + metrics in {run_dir}")
    return run_dir


def _write_summary(run_dir: pathlib.Path, scenario: dict, tx: Transcript, m: dict | None = None):
    lines = [f"# Run summary — {scenario.get('name','')}", "",
             f"- mode: `{scenario.get('mode')}`",
             f"- events: {len(tx.events)}", ""]
    if m is not None:
        lines.append(metrics.to_markdown(m))
        lines.append("")
    for role in ("red", "blue"):
        actions = [e for e in tx.events if e.get("role") == role and e.get("kind") == "action"]
        if not actions:
            continue
        lines.append(f"## {role.upper()} — {len(actions)} actions")
        for e in actions:
            a = e["action"]
            lines.append(f"- `{a.get('tool')}` — {a.get('rationale','').strip()[:110]}")
            if e.get("reasoning"):
                lines.append(f"    _reasoning:_ {e['reasoning'].strip()[:400].replace(chr(10), ' ')}")
            if a.get("tool") == "report":
                lines.append(f"    > {a.get('args',{}).get('text','').strip()[:300]}")
            if e.get("finished"):
                lines.append(f"    _finish:_ {a.get('args',{}).get('summary','').strip()[:300]}")
        lines.append("")
    (run_dir / "summary.md").write_text("\n".join(lines))
