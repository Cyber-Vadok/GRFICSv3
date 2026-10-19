#!/usr/bin/env python3
"""Entry point for the GRFICSv3 Dynamic Cyber Range scenarios.

Examples
--------
  # Smoke-test the lab wiring with the bundled mock model (no GPU):
  python3 run.py scenarios/scenario1_static_red.yaml --mock
  python3 run.py scenarios/scenario2_dynamic_redblue.yaml --mock

  # Dry run (print intended commands, touch nothing):
  python3 run.py scenarios/scenario1_static_red.yaml --mock --dry-run

  # Run for real against a local Qwen3 served by vLLM / Ollama (OpenAI API):
  python3 run.py scenarios/scenario2_dynamic_redblue.yaml \
      --base-url http://127.0.0.1:8000/v1 \
      --red-model Qwen/Qwen3-30B-A3B --blue-model Qwen/Qwen3-30B-A3B
"""

from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
import sys
import time

BASE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

from dcr import runner  # noqa: E402
from dcr.llm import LLMClient  # noqa: E402

MOCK_DEFAULT_PORT = 8900


def _start_mock(port: int) -> subprocess.Popen:
    script = BASE / "mock_model" / "mock_server.py"
    proc = subprocess.Popen(
        [sys.executable, str(script), "--port", str(port)],
        stdout=sys.stderr, stderr=sys.stderr,
    )
    base_url = f"http://127.0.0.1:{port}/v1"
    client = LLMClient(base_url, "mock")
    for _ in range(50):
        if proc.poll() is not None:
            raise SystemExit("mock model server exited during startup")
        if client.ping():
            return proc
        time.sleep(0.1)
    proc.terminate()
    raise SystemExit("mock model server did not become ready")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenario", help="path to a scenario .yaml/.json file")
    ap.add_argument("--mock", action="store_true",
                    help="launch and use the bundled mock model (smoke test)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print intended commands/queries without executing them")
    ap.add_argument("--base-url", default=os.environ.get("LLM_BASE_URL", "http://127.0.0.1:8000/v1"),
                    help="OpenAI-compatible base URL (ignored with --mock)")
    ap.add_argument("--api-key", default=os.environ.get("LLM_API_KEY", ""))
    ap.add_argument("--red-model", default=os.environ.get("RED_MODEL", "Qwen/Qwen3-30B-A3B"))
    ap.add_argument("--blue-model", default=os.environ.get("BLUE_MODEL", "Qwen/Qwen3-30B-A3B"))
    ap.add_argument("--temperature", type=float, default=float(os.environ.get("LLM_TEMPERATURE", "0.6")))
    ap.add_argument("--mock-port", type=int, default=MOCK_DEFAULT_PORT)
    ap.add_argument("--max-steps", type=int, default=None,
                    help="override limits.max_turns_per_agent in the scenario")
    ap.add_argument("--plant-flags", action="store_true",
                    help="(re)plant fresh flag tokens into the containers before running")
    args = ap.parse_args()

    if args.plant_flags:
        subprocess.run([sys.executable, str(BASE / "flags" / "plant_flags.py")], check=True)

    scenario_path = args.scenario
    if not pathlib.Path(scenario_path).exists():
        alt = BASE / args.scenario
        if alt.exists():
            scenario_path = str(alt)
        else:
            raise SystemExit(f"scenario file not found: {args.scenario}")

    scenario = runner.load_scenario(scenario_path)
    if args.max_steps is not None:
        scenario.setdefault("limits", {})["max_turns_per_agent"] = args.max_steps

    mock_proc = None
    if args.mock:
        mock_proc = _start_mock(args.mock_port)
        base_url, api_key = f"http://127.0.0.1:{args.mock_port}/v1", "mock"
        red_model = blue_model = "mock-mini"
    else:
        base_url, api_key = args.base_url, args.api_key
        red_model, blue_model = args.red_model, args.blue_model

    options = {
        "base_url": base_url,
        "api_key": api_key,
        "red_model": red_model,
        "blue_model": blue_model,
        "temperature": args.temperature,
        "dry_run": args.dry_run,
        "runs_dir": str(BASE / "runs"),
        "base_dir": str(BASE),
    }

    try:
        runner.run(scenario, options)
    finally:
        if mock_proc is not None:
            mock_proc.terminate()
            try:
                mock_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                mock_proc.kill()


if __name__ == "__main__":
    main()
