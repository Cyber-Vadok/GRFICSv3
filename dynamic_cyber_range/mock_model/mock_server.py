#!/usr/bin/env python3
"""A tiny OpenAI-compatible "model" for smoke-testing the lab, no GPU needed.

It implements just enough of the Chat Completions API to drive the Red/Blue
TRACE loop, and returns a short, SAFE, scripted sequence of actions (recon and
read-only checks only) so you can confirm the whole pipeline wires up against a
live GRFICSv3 range before pointing the agents at a real Qwen3 model.

Run:  python3 mock_model/mock_server.py --port 8900
API:  GET /v1/models   POST /v1/chat/completions   GET /health
"""

from __future__ import annotations

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _action(tool: str, args: dict, rationale: str) -> str:
    block = json.dumps({"tool": tool, "args": args, "rationale": rationale}, ensure_ascii=False)
    return f"(mock) {rationale}\n\n```action\n{block}\n```"


# Scripted, read-only smoke-test paths. The red script stops at reconnaissance;
# it never exploits or writes to the PLC. The blue script only inspects.
RED_SCRIPT = [
    _action("think", {"note": "First-turn protocol: confirm my foothold in the DMZ and what OT assets I can reach before any active step."},
            "orient on the attack platform"),
    _action("shell", {"host": "kali", "cmd": "id; hostname; (hostname -I 2>/dev/null || true)"},
            "identify my position"),
    _action("shell", {"host": "kali", "cmd": "nmap -sn -n 192.168.90.0/24 -oG - 2>/dev/null | awk '/Up/{print $2}'"},
            "sweep the DMZ for live hosts"),
    _action("shell", {"host": "kali", "cmd": "curl -s -m5 -o /dev/null -w 'plc_web_8080=%{http_code}\\n' http://192.168.95.2:8080/; curl -s -m5 -o /dev/null -w 'sim_web_80=%{http_code}\\n' http://192.168.95.45/"},
            "probe reachability of the ICS zone from the DMZ"),
    _action("shell", {"host": "kali", "cmd": "nmap -Pn -n -p 502,8080 192.168.95.2 2>/dev/null | grep -E '502|8080|Nmap done'"},
            "fingerprint OpenPLC: Modbus/502 and web/8080"),
    _action("report", {"text": "Foothold confirmed in DMZ (kali). ICS zone reachable: PLC 192.168.95.2 (OpenPLC web 8080, Modbus 502), process sim 192.168.95.45. A capable model's next step would be a Modbus write / OpenPLC manual-mode abuse (attacker/cyber_injects/setpoint_inject.py) to move the valve; MOCK stops at recon."},
            "record situational report"),
    _action("finish", {"summary": "Mock red smoke test OK: foothold + OT asset enumeration + impact path identified. No exploitation performed."},
            "end the mock engagement"),
]

BLUE_SCRIPT = [
    _action("think", {"note": "Pre-attack window. Establish SIEM visibility and current DMZ<->ICS segmentation, then plan hardening."},
            "orient as hostmanager"),
    _action("wazuh_query", {"method": "GET", "path": "/agents", "params": {"select": "name,ip,status", "limit": 10}},
            "confirm the SIEM sees every node"),
    _action("shell", {"host": "router", "cmd": "iptables -S FORWARD 2>/dev/null | head -n 12"},
            "inspect DMZ<->ICS segmentation"),
    _action("wazuh_query", {"method": "GET", "path": "/manager/status"},
            "verify the Wazuh manager is healthy"),
    _action("shell", {"host": "plc", "cmd": "curl -s -m5 -o /dev/null -w 'plc_local_web=%{http_code}\\n' http://localhost:8080/; echo 'plan: restrict Modbus/502 to HMI source only'"},
            "reach the PLC host and note a hardening step (no change applied)"),
    _action("report", {"text": "Baseline: Wazuh monitoring all agents; router FORWARD policy present (DMZ/ICS segmented). Hardening plan: restrict Modbus/502 to the HMI source, enable OpenPLC auth, keep Wazuh Modbus-write alerting active. MOCK applies no changes."},
            "record defensive baseline + plan"),
    _action("finish", {"summary": "Mock blue smoke test OK: SIEM reachable, segmentation verified, hardening plan drafted. No changes applied."},
            "end the mock shift"),
]


def _role_and_step(messages: list[dict]) -> tuple[str, int]:
    system = next((m.get("content", "") for m in messages if m.get("role") == "system"), "")
    role = "blue" if "AGENT-ROLE: blue" in system else "red"
    step = sum(1 for m in messages if m.get("role") == "assistant")
    return role, step


def _reply_for(messages: list[dict]) -> str:
    role, step = _role_and_step(messages)
    script = BLUE_SCRIPT if role == "blue" else RED_SCRIPT
    if step < len(script):
        return script[step]
    return _action("finish", {"summary": f"mock {role} script exhausted"}, "nothing left to do")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # keep the console clean
        pass

    def _send(self, code: int, obj: dict):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.rstrip("/") == "/health":
            return self._send(200, {"status": "ok"})
        if self.path.startswith("/v1/models"):
            return self._send(200, {"object": "list", "data": [
                {"id": "mock-mini", "object": "model", "owned_by": "grfics-dcr"}]})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self.path.startswith("/v1/chat/completions"):
            return self._send(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._send(400, {"error": "bad json"})
        content = _reply_for(payload.get("messages", []))
        self._send(200, {
            "id": f"mock-{int(time.time()*1000)}",
            "object": "chat.completion",
            "model": payload.get("model", "mock-mini"),
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        })


def main():
    ap = argparse.ArgumentParser(description="Mock OpenAI-compatible model for GRFICSv3 DCR smoke tests")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8900)
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"[mock] OpenAI-compatible mock model on http://{args.host}:{args.port}/v1 (model: mock-mini)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
