import hashlib
import json
import os
import stat
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

HOOKS_ONLY_CONTENT = (
    "sha256:"
    "394ca2da683d43fbf5b8cdf60cac6edf90fafe62560e28efb9ee420e957a68c4"
)
TREE_CONTENT = (
    "sha256:"
    "5754b5e069df68420e4491d568c9dd30b2a4fbf53c34b67c98cb9b2314cd1d59"
)
LEGACY_FILENAME = (
    "45a4f356800f937df8557bd4c117cfd5257a95706a36d9392ded0b68dde51125"
)


def reference_content_hash(root):
    """Independent fixture encoder: materialize records in tuple-path order."""
    records = []
    paths = [root, *root.rglob("*")]
    paths.sort(key=lambda p: tuple(
        os.fsencode(part) for part in p.relative_to(root).parts
    ))
    for path in paths:
        relative = path.relative_to(root)
        excluded = False
        for part in relative.parts:
            try:
                name = os.fsencode(part).decode("utf-8")
            except UnicodeDecodeError:
                continue
            if (
                name in {"__pycache__", ".venv"}
                or name.endswith(".pyc")
                or name.endswith(".egg-info")
            ):
                excluded = True
                break
        if excluded:
            continue

        name = b"" if path == root else os.fsencode(str(relative))
        mode = path.lstat().st_mode
        record = len(name).to_bytes(8, "little") + name
        if stat.S_ISDIR(mode):
            record += b"directory"
        elif stat.S_ISREG(mode):
            data = path.read_bytes()
            record += b"file" + len(data).to_bytes(8, "little") + data
        else:
            raise ValueError("unsupported synthetic entry")
        records.append(record)

    stream = b"codex-plugin-bundle-v1" + b"".join(records)
    return "sha256:" + hashlib.sha256(stream).hexdigest()


def reference_legacy_path(config, marketplace=MARKETPLACE):
    parts = (
        os.fsencode(str(config)),
        f"{PLUGIN}@{marketplace}".encode("utf-8"),
    )
    stream = b"".join(
        len(part).to_bytes(8, "little") + part for part in parts
    )
    return config.parent / ".hook-trust" / hashlib.sha256(stream).hexdigest()


def seed_legacy(config, bundle, marketplace=MARKETPLACE):
    path = reference_legacy_path(config, marketplace)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(reference_content_hash(bundle).encode("ascii"))
    return path


def write_trust(
    config, hashes=None, *, disabled=(), content_hash=None,
):
    if hashes is None:
        hashes = expected_trust()
    config.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for key, value in hashes.items():
        lines.extend([
            f"[hooks.state.{json.dumps(key)}]",
            f"trusted_hash = {json.dumps(value)}",
        ])
        if content_hash is not None:
            lines.append(
                f"trusted_content_hash = {json.dumps(content_hash)}"
            )
        if key in disabled:
            lines.append("enabled = false")
    with config.open("a", encoding="utf-8") as handle:
        handle.write("\n" + "\n".join(lines) + "\n")
