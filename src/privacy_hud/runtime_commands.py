# src/privacy_hud/runtime_commands.py
"""The commands every Privacy HUD surface runs (#66, Pair 6).

Before this module, each surface answered the same three questions for
itself and they drifted: *which ledger*, *which session*, and *how do I
write a policy rule*. The skill opened `$PLUGIN_DATA/ledger.db` from a
heredoc, the MCP server opened its own, the browser opened a third and
wrote to it directly, and the audit resolved its session twice — once for
the table and once for the browser tab beside it, which is how one
machine ended up showing two different sessions at once.

One answer each, here:

* **Which ledger.** `codex.ledger_path` resolves it, and it is opened
  read-only and schema-validated first. History is a record; showing it
  never depends on the runtime matching, but it does depend on the
  schema being one this build understands (§A).
* **Which session.** `mcp_tools.resolve_audit_session`, called once, and
  the resulting `ResolvedSession` is what reaches the renderer and the
  browser. Two separately timed resolutions can name two sessions.
* **How to write a rule.** Over the socket, to the daemon that owns the
  ledger. A surface that opened its own writable connection would be
  writing behind the writer's back, which is what Pair 3 removed.

The failure distinction in `update_policy` is the load-bearing part of
this file. A refusal *before* the request is transmitted means nothing
was saved, and that is a fact. A reply that never comes back *after*
transmission means the outcome is unknown — the daemon may have written
the rule and died on the way back — and claiming otherwise, or retrying,
would each be a different way of lying about it (I5, §D).

I1: sessions, ids, rule types and selectors. No hook content, no ledger
values beyond what the renderer already prints, and no peer text is ever
re-raised to a caller.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from . import codex, ledger_schema, mcp_tools, render, runtime_messages
from .ledger import Ledger
from .matrix.loader import load_matrix
from .runtime_client import OP_POLICY_UPDATE, connect_runtime
from .runtime_contract import Activation, JSONObject, RuntimeRefusal

#: How long a policy mutation may take end to end. Generous compared with
#: a hook's two seconds: nobody is waiting on a tool call here, and the
#: daemon may be holding its state lock for another session's write.
POLICY_TIMEOUT = 10.0

#: How long the alignment probe may take. Only a hello travels.
ALIGNMENT_TIMEOUT = 2.0

#: The fields a successful policy result carries, unchanged from the
#: shape the MCP tool and the browser already return.
POLICY_RESULT_FIELDS = ("saved", "enforcement", "rule_type", "selector",
                        "conditions")


class PolicyOutcomeUnknown(RuntimeError):
    """The request was transmitted and no reply came back.

    Whether the rule was saved is not knowable from here. It is not
    retried: a retry risks writing a second time something that already
    happened, and the honest answer is the one the caller can act on.
    """


@dataclass(frozen=True)
class AuditResult:
    resolved: mcp_tools.ResolvedSession
    text: str
    banner: str
    runtime_mismatch: bool


# --------------------------------------------------------------------- #
# readers
# --------------------------------------------------------------------- #

def validated_schema_version(path: Path) -> int:
    """The ledger's accounting generation, read on its own read-only
    connection, refusing anything this build does not understand.

    Independent of the runtime check and ahead of every read: history is
    only shown after this, because a schema this build cannot interpret
    renders as numbers that mean something else.
    """
    try:
        conn = sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro",
                               uri=True, isolation_level=None)
    except sqlite3.Error:
        raise RuntimeRefusal("ledger_unsupported") from None
    try:
        return ledger_schema.validate_schema(conn)
    except (ledger_schema.UnsupportedAccounting, sqlite3.Error):
        raise RuntimeRefusal("ledger_unsupported") from None
    finally:
        conn.close()


def open_reader(data_dir: Path) -> Ledger:
    """A read-only `Ledger` at the canonical path, schema validated.

    `initialize=False` and no lease: this opens `mode=ro`, so whatever
    SQL a caller runs, the file cannot change (#66 Pair 3).
    """
    path = codex.ledger_path(data_dir)
    if not path.is_file():
        raise RuntimeRefusal("ledger_unsupported")
    validated_schema_version(path)
    return Ledger(path, load_matrix(), initialize=False)


def runtime_matches(data_dir: Path, *, activation: Activation) -> bool:
    """Does a daemon matching the selected build answer right now?

    A hello and nothing else. Used to decide whether to show the mismatch
    banner, never to decide whether history may be read.
    """
    try:
        connect_runtime(data_dir, activation=activation,
                        timeout=ALIGNMENT_TIMEOUT).close()
    except RuntimeRefusal:
        return False
    return True


# --------------------------------------------------------------------- #
# the policy client
# --------------------------------------------------------------------- #

def update_policy(data_dir: Path, *, activation: Activation,
                  session_id: str, rule_type: str, selector: str
                  ) -> JSONObject:
    """Ask the selected daemon to save a policy rule.

    Raises, and which exception it is says what is known:

    * `ValueError` — the rule is one no engine could ever match. Checked
      here, before anything is sent, so the refusal is about the request
      rather than about the runtime.
    * `RuntimeRefusal` — no compatible daemon answered. Nothing was
      transmitted, so nothing was saved.
    * `PolicyOutcomeUnknown` — the request went out and no valid reply
      came back. The outcome is unknown and it is not retried.
    """
    mcp_tools.validate_policy_rule(rule_type=rule_type, selector=selector)
    connection = connect_runtime(data_dir, activation=activation,
                                 timeout=POLICY_TIMEOUT)
    try:
        reply = connection.request(OP_POLICY_UPDATE, {
            "session_id": session_id, "rule_type": rule_type,
            "selector": selector})
    except RuntimeRefusal:
        # `RuntimeConnection.request` hands the socket away as it sends,
        # so every failure it reports is a failure after transmission.
        raise PolicyOutcomeUnknown() from None
    finally:
        connection.close()
    return {name: reply[name] for name in POLICY_RESULT_FIELDS
            if name in reply}


# --------------------------------------------------------------------- #
# the audit
# --------------------------------------------------------------------- #

def audit(data_dir: Path, *, activation: Activation,
          session_id: str | None = None, tab: str = "Exposed") -> AuditResult:
    """Resolve the session once and render its audit.

    The resolution is returned beside the text so the caller that also
    opens the browser hands it the same session rather than resolving a
    second time.
    """
    mismatch = not runtime_matches(data_dir, activation=activation)
    banner = runtime_messages.AUDIT_RUNTIME_MISMATCH if mismatch else ""
    ledger = open_reader(data_dir)
    try:
        resolved = mcp_tools.resolve_audit_session(ledger, data_dir,
                                                   explicit=session_id)
        chosen = resolved.session_id
        if chosen is None:
            return AuditResult(resolved=resolved,
                               text=render.empty_message(tab, None),
                               banner=banner, runtime_mismatch=mismatch)
        summary = mcp_tools.get_session_summary(ledger, chosen)
        rows = mcp_tools.list_exposures(ledger, chosen, tab)
        coverage = mcp_tools.get_session_coverage(ledger, chosen)
        text = render.audit(summary, rows, tab, coverage=coverage,
                            resolved=resolved)
    finally:
        ledger.conn.close()
    return AuditResult(resolved=resolved, text=text, banner=banner,
                       runtime_mismatch=mismatch)


def detail(data_dir: Path, *, session_id: str, event_id: int) -> str:
    """The L3 row detail, at the canonical path."""
    ledger = open_reader(data_dir)
    try:
        row = mcp_tools.get_exposure_detail(ledger, session_id, event_id)
    finally:
        ledger.conn.close()
    return render.detail(row)


def hud(data_dir: Path, *, session_id: str, action: str) -> JSONObject:
    """`$privacy hud <id> on|off|status`. Display state, not accounting:
    it writes the HUD's own file and never the ledger."""
    if action == "status":
        return mcp_tools.hud_status(data_dir, session_id)
    if action in ("on", "off"):
        return mcp_tools.hud_set_hidden(data_dir, session_id, action == "off")
    raise ValueError("action must be on, off or status")


def read_guard(data_dir: Path, *, action: str) -> JSONObject:
    """`$privacy read on|off|status`. `settings.json` in `$PLUGIN_DATA`,
    which is no longer the ledger's parent directory."""
    if action == "status":
        return mcp_tools.read_guard_status(data_dir)
    if action in ("on", "off"):
        return mcp_tools.read_guard_set(data_dir, action == "on")
    raise ValueError("action must be on, off or status")
