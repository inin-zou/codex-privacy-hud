# tests/test_hud_contract.py
"""Contract A (spec §4.1) and the shared rendering golden, pinned.

Two files under tests/matrix/ are read by code in two languages. This test is
what makes a change to either of them a deliberate act: the schema is checked
with a stdlib-only validator (the plugin has no dependencies and jsonschema is
not going to become one), and the golden is checked for the two properties the
Rust side depends on -- ten cells, and Python's round-half-to-even fill.

The last section does the same for the three constants the Rust status-line
item cannot import: `SNAPSHOT_VERSION`, `STALE_AFTER_SECS` and
`PLUGIN_DATA_DIRNAME`. Every one of them fails silently when it drifts -- the
item renders nothing rather than complaining -- so they are compared to their
Python and manifest sources here instead of being trusted.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from privacy_hud import codex, doctor, hud_snapshot
from runtime_helpers import writer_ledger

MATRIX = Path(__file__).parent / "matrix"
SCHEMA = json.loads((MATRIX / "hud_snapshot.schema.json").read_text())
GOLDEN = json.loads((MATRIX / "hud_golden.json").read_text())

VALID = {"v": 2, "accounting_version": 1, "percent": 28,
         "confirmed_points": None, "denials_issued": None,
         "legacy_prevented_rows": 2, "unresolved_actions": None,
         "unverified": False, "hidden": False, "updated_at": 1757900000.0}


def validate(doc: dict, schema: dict = SCHEMA) -> list[str]:
    """Minimal validator for exactly the subset of JSON Schema the contract
    uses: object, additionalProperties=false, required, integer/number/boolean
    (optionally nullable, as a two-element type list), const, enum, minimum,
    maximum. Returns a list of problems; empty means valid."""
    problems = []
    if not isinstance(doc, dict):
        return ["not an object"]
    props = schema["properties"]
    for key in schema["required"]:
        if key not in doc:
            problems.append(f"missing {key}")
    for key in doc:
        if key not in props:
            problems.append(f"unexpected {key}")
    for key, rule in props.items():
        if key not in doc:
            continue
        val = doc[key]
        t = rule["type"]
        if isinstance(t, list):
            if val is None and "null" in t:
                continue
            t = next(x for x in t if x != "null")
        if t == "integer" and not (isinstance(val, int) and not isinstance(val, bool)):
            problems.append(f"{key} not integer")
        elif t == "number" and not (isinstance(val, (int, float)) and not isinstance(val, bool)):
            problems.append(f"{key} not number")
        elif t == "boolean" and not isinstance(val, bool):
            problems.append(f"{key} not boolean")
        if "const" in rule and val != rule["const"]:
            problems.append(f"{key} != {rule['const']}")
        if "enum" in rule and val not in rule["enum"]:
            problems.append(f"{key} not in {rule['enum']}")
        if "minimum" in rule and isinstance(val, (int, float)) and val < rule["minimum"]:
            problems.append(f"{key} below minimum")
        if "maximum" in rule and isinstance(val, (int, float)) and val > rule["maximum"]:
            problems.append(f"{key} above maximum")
    return problems


def test_schema_accepts_the_canonical_sample():
    assert validate(VALID) == []


@pytest.mark.parametrize("mutation", [
    {"v": 1},
    {"v": 3},
    {"accounting_version": 3},
    {"percent": 101},
    {"percent": -1},
    {"percent": 28.5},
    {"legacy_prevented_rows": -1},
    {"legacy_prevented_rows": 2**53},
    {"unverified": "no"},
    {"hidden": 0},
    {"updated_at": "now"},
    {"note": "hello"},          # any string field is a contract violation (I1)
])
def test_schema_rejects_each_violation(mutation):
    doc = {**VALID, **mutation}
    assert validate(doc) != []


def test_schema_has_no_string_typed_field():
    types = [t for v in SCHEMA["properties"].values()
             for t in (v["type"] if isinstance(v["type"], list)
                       else [v["type"]])]
    assert "string" not in types
    assert SCHEMA["additionalProperties"] is False


def test_golden_covers_every_rounding_tie():
    # Python's round() is half-to-even; every x5 percent is a tie and the Rust
    # port must reproduce all ten of them.
    percents = {g["percent"] for g in GOLDEN}
    assert {5, 15, 25, 35, 45, 55, 65, 75, 85, 95} <= percents
    assert {0, 100} <= percents


def test_golden_core_shape():
    for g in GOLDEN:
        bar, pct = g["core"].split(" ", 1)
        assert len(bar) == 10 and set(bar) <= {"█", "░"}
        assert pct == f"{g['percent']:>2}%"
        assert bar.count("█") == round(g["percent"] / 10)


def test_patch_embeds_the_same_golden_file():
    """The copy of the golden inside the Codex patch is byte-identical to ours.

    Reconstructs the added file from its hunk rather than checking line
    membership, so a reordering or a dropped duplicate line fails too.
    """
    patch = (Path(__file__).parents[1] / "patches" / "privacy-status-line.patch").read_text()
    lines = patch.splitlines()
    starts = [i for i, line in enumerate(lines)
              if line.startswith("+++ ") and line.endswith("privacy_status_golden.json")]
    assert len(starts) == 1, "patch must add privacy_status_golden.json exactly once"
    body = lines[starts[0] + 1:]
    end = next((i for i, line in enumerate(body) if line.startswith("diff --git")), len(body))
    embedded = [line[1:] for line in body[:end] if line.startswith("+")]
    assert "\n".join(embedded) + "\n" == (MATRIX / "hud_golden.json").read_text()


# --------------------------------------------------------------------- #
# the three constants the Rust status-line item restates
# --------------------------------------------------------------------- #

ROOT = Path(__file__).parents[1]
PATCH = (ROOT / "patches" / "privacy-status-line.patch").read_text()


def _rust_const(name: str) -> str:
    """The right-hand side of `const <name> ... = <value>;` as the patch adds it.

    Read out of the patch text rather than out of a built Codex tree: the
    patch is what CI applies and what a release ships, and it is the only
    copy of the Rust side this repository owns.
    """
    matches = re.findall(rf"^\+.*\bconst {name}\s*:[^=]+=\s*(.+?);\s*$",
                         PATCH, re.M)
    assert len(matches) == 1, f"{name} must be defined exactly once in the patch"
    return matches[0].strip()


def test_rust_snapshot_version_matches_the_python_writer():
    """Contract A's schema version. The Rust reader drops any snapshot whose
    `v` is not this number, so a bump made on the Python side alone would
    empty the status line silently — there is no error path for it, by
    design (`hud_snapshot.py:13-14`)."""
    assert int(_rust_const("SNAPSHOT_VERSION")) == hud_snapshot.SNAPSHOT_VERSION


def test_rust_legacy_version_and_count_ceiling_match_the_python_reader():
    """The legacy version both readers still accept, and the largest count
    either accepts. A count one reader clamps and the other rejects would
    make the two surfaces disagree about the same file."""
    assert int(_rust_const("LEGACY_SNAPSHOT_VERSION")) == \
        hud_snapshot.LEGACY_SNAPSHOT_VERSION
    assert int(_rust_const("MAX_COUNT").replace("_", "")) == \
        hud_snapshot.MAX_COUNT
    assert SCHEMA["properties"]["legacy_prevented_rows"]["maximum"] == \
        hud_snapshot.MAX_COUNT


def test_published_snapshots_satisfy_the_schema(tmp_path):
    from privacy_hud.matrix.loader import load_matrix
    led = writer_ledger(tmp_path / "ledger.db", load_matrix())
    led.start_session("s1", cwd="/w", model="m")
    pub = hud_snapshot.HudPublisher(tmp_path)
    for sid, summary in (("s1", led.summary("s1")),
                         ("s2", led.summary("missing"))):
        pub.publish(sid, summary=summary, unverified=False)
        doc = json.loads(hud_snapshot.snapshot_path(tmp_path, sid).read_text())
        assert validate(doc) == [], (sid, doc)
    led.conn.close()


def test_rust_stale_after_matches_the_python_reader():
    """Both ends must call a snapshot stale at the same age, or the status
    line and `privacy.status` disagree about whether the daemon is alive.
    Compared numerically: the Rust side is an `f64` literal and the Python
    side a float, and it is the seconds that have to agree, not the spelling.
    """
    assert float(_rust_const("STALE_AFTER_SECS")) == float(hud_snapshot.STALE_AFTER)


def _manifest(path: str) -> dict:
    return json.loads((ROOT / path).read_text())


def _plugin_data_dirname() -> str:
    """`<marketplace>-<plugin>`, the directory name Codex derives from the two
    manifests and hands the plugin as `$PLUGIN_DATA`."""
    marketplace = _manifest(".agents/plugins/marketplace.json")
    plugin = _manifest(".codex-plugin/plugin.json")
    return f"{marketplace['name']}-{plugin['name']}"


def test_plugin_manifests_agree_on_the_plugin_name():
    """`codex.PLUGIN_NAME` (re-exported as `doctor.PLUGIN_NAME`) is what
    `codex.codex_data_candidates` matches a directory on; it is a restatement
    of the manifest and nothing checks it against the manifest anywhere
    else."""
    plugin = _manifest(".codex-plugin/plugin.json")
    marketplace = _manifest(".agents/plugins/marketplace.json")
    assert codex.PLUGIN_NAME == plugin["name"]
    assert doctor.PLUGIN_NAME == plugin["name"]
    assert [p["name"] for p in marketplace["plugins"]] == [plugin["name"]]


def test_codex_module_derives_the_plugin_data_dirname_from_the_manifests():
    """`codex.py` carries the marketplace name and the `<marketplace>-<plugin>`
    directory Codex derives from it as constants, because the runtime cannot
    rely on the checkout existing (Codex runs a copy out of its own cache, and
    a wheel install ships no manifests at all). This is the pin that makes the
    constants a restatement rather than a guess -- the same treatment the Rust
    literal and `install.sh` get in the two tests below."""
    assert codex.MARKETPLACE_NAME == \
        _manifest(".agents/plugins/marketplace.json")["name"]
    assert codex.PLUGIN_DATA_DIRNAME == _plugin_data_dirname()


def test_rust_plugin_data_dirname_matches_the_manifests():
    """The Rust item resolves `$PLUGIN_DATA` itself — it is linked into Codex
    and gets no environment from the hook — so it carries the directory name
    as a literal. Nothing at runtime relates it to the manifests it was
    derived from: a rename of the plugin or the marketplace would leave the
    status line reading an empty directory forever."""
    assert _rust_const("PLUGIN_DATA_DIRNAME").strip('"') == _plugin_data_dirname()


def test_installer_writes_the_same_plugin_data_dirname():
    """`install.sh` restates the directory twice (the manifest it writes, and
    the doctor run at the end of an install). A disagreement there points the
    uninstaller and the doctor at a directory Codex never uses."""
    install = (ROOT / "install.sh").read_text()
    found = set(re.findall(r"plugins/data/([A-Za-z0-9._-]+)", install))
    assert found == {_plugin_data_dirname()}
