#!/usr/bin/env python3
"""Plant fresh flag tokens into the running GRFICSv3 containers.

Generates a new random token per host flag, writes it into each target container
(via `docker exec`), and records the ground truth in flags_state.json for the
scorer. Re-run it before each experiment so tokens never repeat.

Usage:
  python3 flags/plant_flags.py                 # plant using flags_manifest.yaml
  python3 flags/plant_flags.py --clear         # remove planted flags (same as clear_flags.py)
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import pathlib
import secrets
import subprocess
import sys

import yaml

HERE = pathlib.Path(__file__).resolve().parent


def _docker_write(container: str, path: str, content: str) -> tuple[bool, str]:
    # -u 0 so we can write /root even if the image sets a non-root USER.
    script = f"umask 077; printf '%s\\n' {sh_quote(content)} > {sh_quote(path)} && echo OK"
    proc = subprocess.run(
        ["docker", "exec", "-u", "0", container, "sh", "-c", script],
        capture_output=True, text=True, timeout=30,
    )
    out = (proc.stdout + proc.stderr).strip()
    return (proc.returncode == 0 and "OK" in proc.stdout, out)


def _docker_rm(container: str, path: str) -> tuple[bool, str]:
    proc = subprocess.run(
        ["docker", "exec", "-u", "0", container, "sh", "-c", f"rm -f {sh_quote(path)} && echo OK"],
        capture_output=True, text=True, timeout=30,
    )
    return (proc.returncode == 0, (proc.stdout + proc.stderr).strip())


def sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def load_manifest(path: pathlib.Path) -> dict:
    return yaml.safe_load(path.read_text())


def plant(manifest: dict, state_path: pathlib.Path) -> dict:
    prefix = manifest.get("token_prefix", "GRFICS")
    planted = []
    print("Planting host flags:")
    for f in manifest.get("host_flags", []):
        token = f"{prefix}{{{f['label']}_{secrets.token_hex(4)}}}"
        ok, msg = _docker_write(f["container"], f["path"], token)
        status = "ok" if ok else f"FAILED ({msg[:60]})"
        print(f"  [{status:>20}] {f['container']:<11} {f['path']}  -> {token if ok else '-'}")
        planted.append({
            "label": f["label"], "container": f["container"], "path": f["path"],
            "points": f.get("points", 10), "note": f.get("note", ""),
            "token": token if ok else None, "planted": ok,
        })
    state = {
        "planted_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "token_prefix": prefix,
        "host_flags": planted,
        "impact_flags": manifest.get("impact_flags", []),
    }
    state_path.write_text(json.dumps(state, indent=2))
    n_ok = sum(1 for p in planted if p["planted"])
    print(f"\nPlanted {n_ok}/{len(planted)} host flags. "
          f"{len(state['impact_flags'])} impact flag(s) are scored live (not planted).")
    print(f"Ground truth written to {state_path}")
    return state


def clear(manifest: dict, state_path: pathlib.Path) -> None:
    # Prefer the recorded state (exact paths actually planted); fall back to manifest.
    targets = []
    if state_path.exists():
        st = json.loads(state_path.read_text())
        targets = [(h["container"], h["path"]) for h in st.get("host_flags", [])]
    else:
        targets = [(f["container"], f["path"]) for f in manifest.get("host_flags", [])]
    print("Clearing host flags:")
    for container, path in targets:
        ok, msg = _docker_rm(container, path)
        print(f"  [{'ok' if ok else 'FAILED':>6}] {container}:{path}")
    if state_path.exists():
        state_path.unlink()
        print(f"Removed {state_path}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifest", default=str(HERE / "flags_manifest.yaml"))
    ap.add_argument("--state", default=str(HERE / "flags_state.json"))
    ap.add_argument("--clear", action="store_true", help="remove planted flags instead of planting")
    args = ap.parse_args()

    manifest = load_manifest(pathlib.Path(args.manifest))
    state_path = pathlib.Path(args.state)
    if args.clear:
        clear(manifest, state_path)
    else:
        plant(manifest, state_path)


if __name__ == "__main__":
    main()
