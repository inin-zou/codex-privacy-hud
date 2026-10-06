import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MARKETPLACE = "codex-privacy-hud"
PLUGIN = "codex-privacy-hud"

VECTORS = {
    "SessionStart": (
        "session_start",
        "538932c67bc3c510c3025d20639f65d27e39012c0454cf3ad67184c9609d1825",
    ),
    "UserPromptSubmit": (
        "user_prompt_submit",
        "96990c96d42350fe675c2cb20e9df7679a88e4b4a337207068e0c9b037a7d1e3",
    ),
    "PreToolUse": (
        "pre_tool_use",
        "751a0d28f1a3e9404e76ccdb85e6b534d1668a03a6ca5f5d0e9c13359c25e8e6",
    ),
    "PostToolUse": (
        "post_tool_use",
        "b0957bb0244f7fcc79868c02ee1e0a5ec5949658e26e0680c906c279d0f85f6a",
    ),
    "SubagentStart": (
        "subagent_start",
        "bc5046344ef6f050d1b535c8c2aa769e394857a1787b55bf4febbef1cbc92e32",
    ),
    "SubagentStop": (
        "subagent_stop",
        "b196552e437f09b657b110891f7e132b65ddd34b693a442e622c7b296c14ba8d",
    ),
    "PreCompact": (
        "pre_compact",
        "1eb1a0368148af0c5b2afcb236bfa65e0f9d7808147b12080ac4e7b0b2c26115",
    ),
    "SessionEnd": (
        "session_end",
        "8038157553d371236acc972802bc3d767f1bdeb10ea560d9a68fb476fa5dcf23",
    ),
}


def expected_trust(marketplace=MARKETPLACE):
    return {
        f"{PLUGIN}@{marketplace}:hooks/hooks.json:{label}:0:0":
        f"sha256:{digest}"
        for label, digest in VECTORS.values()
    }


def copy_hooks(bundle):
    target = bundle / "hooks" / "hooks.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((ROOT / "hooks" / "hooks.json").read_bytes())


def write_trust(config, hashes=None, *, disabled=()):
    if hashes is None:
        hashes = expected_trust()
    config.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for key, value in hashes.items():
        lines.extend([
            f"[hooks.state.{json.dumps(key)}]",
            f"trusted_hash = {json.dumps(value)}",
        ])
        if key in disabled:
            lines.append("enabled = false")
    with config.open("a", encoding="utf-8") as handle:
        handle.write("\n" + "\n".join(lines) + "\n")
