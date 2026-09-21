"""I2's offline guarantee, owned in one place.

CLAUDE.md §3 I2: no network calls except `127.0.0.1`. The model stack is
the only dependency here that can reach the network, and whether it does is
decided by environment variables it reads — some of them once, at import.
This module forces those variables and checks what an already-imported
stack has cached. It is a stdlib-only leaf and imports nothing from the
package, so every entry point can use it before anything else loads.

Two copies of `FORCED_ENV` live outside this module, because their files
cannot import it: `hooks/handler.py` is stdlib-only (CLAUDE.md §4) and
`mcp/server.py`'s launcher half runs before the package is importable.
`tests/test_offline.py` pins both to this one.

Forcing, never defaulting. `os.environ.setdefault` kept an inherited
`HF_HUB_OFFLINE=0`, so any parent process could turn the guarantee off
(#49 item 6). There is no runtime option to go online.

What this does not do: repair a stack that is already imported.
`huggingface_hub.constants.HF_HUB_OFFLINE` is computed when that module is
imported, so setting the environment afterwards changes nothing it has
cached. `loaded_stack_is_offline` reports that case and the caller treats
tier 3 as unavailable; a fresh process loads it offline.

The one legitimate online step is the explicit weights download
(`install.sh` step 3, `docs/installing-by-hand.md`, doctor's printed
recipe). It runs as its own process with `download_env_prefix()` on that
command only, and nothing at runtime triggers it.
"""
from __future__ import annotations

import os
import sys
from collections.abc import MutableMapping

#: Assigned, not defaulted, in every process and child environment that can
#: load the model stack. The first three are the offline switches (datasets
#: is defensive: this project does not load it); the rest suppress telemetry,
#: update checks and transformers' safetensors conversion, which supplement
#: offline mode and do not replace it.
FORCED_ENV: dict[str, str] = {
    "HF_HUB_OFFLINE": "1",
    "TRANSFORMERS_OFFLINE": "1",
    "HF_DATASETS_OFFLINE": "1",
    "HF_HUB_DISABLE_TELEMETRY": "1",
    "DO_NOT_TRACK": "1",
    "HF_HUB_DISABLE_UPDATE_CHECK": "1",
    "DISABLE_SAFETENSORS_CONVERSION": "1",
}

#: The offline switches the weights download turns off, for that one
#: command. Telemetry suppression stays on.
DOWNLOAD_OVERRIDE: tuple[str, ...] = (
    "HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_DATASETS_OFFLINE")


def force_offline(env: MutableMapping[str, str]) -> MutableMapping[str, str]:
    """Assign every `FORCED_ENV` value into `env`, whatever it held.

    Returns `env` itself. Cache locations (`HF_HOME`, `HF_HUB_CACHE`) are
    left alone: where the weights are is not a network question.
    """
    env.update(FORCED_ENV)
    return env


def loaded_stack_is_offline() -> bool:
    """Whether the model stack, if already imported, is in offline mode.

    Reads `sys.modules` only; never imports anything. True when nothing is
    imported yet (the forced environment will then be read at import).
    False when the hub cached online mode, when `transformers` is loaded but
    the hub's cached state cannot be read, or when a legacy `transformers`
    cached its own online flag.
    """
    hub = sys.modules.get("huggingface_hub.constants")
    if hub is not None and getattr(hub, "HF_HUB_OFFLINE", None) is not True:
        return False
    if hub is None and "transformers" in sys.modules:
        return False
    legacy = sys.modules.get("transformers.utils.hub")
    if getattr(legacy, "_is_offline_mode", True) is not True:
        return False
    return True


def prepare_process() -> bool:
    """Force this process offline before any model-stack import.

    Returns whether it is safe to load the model: False means a stack
    imported earlier in this process cached online mode (or its state
    cannot be established), and the caller must not load.
    """
    force_offline(os.environ)
    return loaded_stack_is_offline()


def download_env_prefix() -> str:
    """The shell prefix the explicit weights download runs under.

    Scoped to one command, so neither the installer's shell nor the user's
    is changed: `HF_HUB_OFFLINE=0 ... python3 -c "..."`.
    """
    parts = [f"{name}=0" for name in DOWNLOAD_OVERRIDE]
    parts.append("HF_HUB_DISABLE_TELEMETRY=1")
    return " ".join(parts)
