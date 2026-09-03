#!/usr/bin/env python3
# hooks/handler.py
"""Thin hook client. Stdlib only (Global Constraint) — every import here is
paid on every tool call and is a new way to break a user's session.

Forwards the hook payload to the daemon over a unix socket and relays the
reply. All policy lives in the daemon.
"""
import json
import os
import socket
import sys

TIMEOUT = 0.12  # seconds; see architecture.md §10 latency budget
EGRESS_EVENTS = {"PreToolUse"}


def _deny(reason):
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": "deny",
                                   "permissionDecisionReason": reason}}


def _looks_like_egress(payload):
    if payload.get("hook_event_name") not in EGRESS_EVENTS:
        return False
    ti = payload.get("tool_input") or {}
    blob = json.dumps(ti) if isinstance(ti, dict) else str(ti)
    return "://" in blob or payload.get("tool_name", "").startswith("mcp")


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return {}
    sock_path = os.path.join(os.environ.get("PLUGIN_DATA", "/tmp"), "daemon.sock")
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect(sock_path)
        s.sendall((json.dumps({"v": 1, "op": "event", "payload": payload}) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf.decode())
    except Exception:
        # I6: fail open on ingress, fail closed on egress.
        if _looks_like_egress(payload):
            return _deny("Privacy HUD could not verify this call. "
                         "Run $privacy to review, or allow once.")
        return {"systemMessage": "Privacy HUD unavailable — disclosure unverified."}


if __name__ == "__main__":
    try:
        out = main()
    except Exception:
        out = {}
    sys.stdout.write(json.dumps(out) if out else "")
    sys.exit(0)
