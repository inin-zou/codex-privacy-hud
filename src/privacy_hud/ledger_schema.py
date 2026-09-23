"""The ledger's schema generations and their validation (#54).

`ledger.py` owns connections and transactions and executes what this module
returns; this module holds the SQL and checks a database against it. It
imports nothing from the package.

Three generations, recorded in `PRAGMA user_version`:

- 0: the legacy schema. `events` is the legacy table.
- 5401: prepared. The legacy events table is preserved as
  `events_legacy_v1`. Production sessions remain legacy-accounted;
  isolated synthetic tests and the private-copy rehearsal may exercise
  version-2 accounting without activating production session creation.
- 5402: activated (#54 Phase 4). A daemon of this version refuses it.

The rebuild is the one structural change CLAUDE.md §4 permits. It runs
only inside a write transaction the daemon owns at a genuine new-session
boundary (`Ledger.prepare_session_boundary`), so a crash leaves the complete
old schema or the complete new one. Readers never run it.
"""
from __future__ import annotations

import sqlite3
from typing import Literal

#: The legacy schema, applied only to a genuinely new or legacy database.
#: `CREATE ... IF NOT EXISTS` throughout, so it adds a table an older
#: legacy ledger lacks and changes nothing that exists.
LEGACY_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
  session_id   TEXT PRIMARY KEY,
  started_at   INTEGER NOT NULL,
  ended_at     INTEGER,
  cwd          TEXT,
  model        TEXT,
  budget_score REAL NOT NULL DEFAULT 0,
  budget_cap   REAL NOT NULL DEFAULT 120
);

-- Legacy schema; CLAUDE.md §4 governs #54's approved, not-yet-implemented rebuild.
CREATE TABLE IF NOT EXISTS events (       -- legacy UPDATEs: count increments; value_hash NULL at session end
  id            INTEGER PRIMARY KEY,
  session_id    TEXT NOT NULL REFERENCES sessions,
  turn_id       TEXT,
  ts            INTEGER NOT NULL,
  kind          TEXT NOT NULL,            -- exposed|prevented|local_access|detected|retention
  data_type     TEXT NOT NULL,            -- email|credential|person|hostname|path|...
  source        TEXT NOT NULL,            -- support.log | user prompt | tool input
  source_kind   TEXT,                     -- path|command; NULL when source is a bare label
  destination   TEXT NOT NULL,            -- model_context|subagent:<id>|mcp:<server>|net:<host>
  boundary      TEXT NOT NULL,            -- B0..B4
  count         INTEGER NOT NULL DEFAULT 1,
  value_hash    BLOB,                     -- salted, session-scoped; NULL after SessionEnd
  masked_example TEXT,                    -- 'jo•••@acme.com'; NULL for credentials
  budget_delta  REAL NOT NULL DEFAULT 0,
  protection    TEXT,                     -- none|masked|minimized|blocked
  tool_name     TEXT,
  UNIQUE(session_id, value_hash, destination)
);

CREATE TABLE IF NOT EXISTS flows (        -- multi-hop chains for the L3 flow line
  id         INTEGER PRIMARY KEY,
  session_id TEXT NOT NULL,
  value_hash BLOB NOT NULL,
  hop_index  INTEGER NOT NULL,
  node       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy (
  id         INTEGER PRIMARY KEY,
  scope      TEXT NOT NULL,               -- session:<id>
  rule_type  TEXT NOT NULL,               -- mask|block_path|block_command
  selector   TEXT NOT NULL,               -- data_type / destination / origin (#40)
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS coverage (     -- append-only; who was watching, when
  id          INTEGER PRIMARY KEY,
  session_id  TEXT NOT NULL,            -- '' when the gap is not attributable
  ts          INTEGER NOT NULL,
  observer    TEXT NOT NULL,            -- opaque per-Ledger-instance id
  reason      TEXT NOT NULL,            -- session_start|attached|unobserved_hooks
  UNIQUE(session_id, observer)          -- one row per observer per session
);

CREATE TABLE IF NOT EXISTS scan_gaps (   -- append-only; one row per observed scan gap
  id          INTEGER PRIMARY KEY,
  session_id  TEXT NOT NULL,
  ts          INTEGER NOT NULL,
  boundary    TEXT NOT NULL,            -- B0..B4
  reason      TEXT NOT NULL             -- oversize|unavailable|busy|timeout
);

-- `coverage()` counts this table per session on every HUD publish, under
-- `State.lock`. Without the index that is a full scan over every session's
-- history the ledger has ever accumulated, on the hook path.
CREATE INDEX IF NOT EXISTS scan_gaps_session ON scan_gaps(session_id);

CREATE TABLE IF NOT EXISTS policy_tokens (  -- one-shot consent, §8
  token      TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  tool_name  TEXT NOT NULL,
  args_hash  BLOB NOT NULL,
  mode       TEXT NOT NULL,               -- allow_once|minimize
  expires_at INTEGER NOT NULL
);
"""

PREPARED_VERSION = 5401
ACTIVATED_VERSION = 5402

#: The structural migration, in order (#54 Phase 2).
_STRUCTURAL_SQL = """
ALTER TABLE events RENAME TO events_legacy_v1;

CREATE TABLE scoring_profiles (
    profile_id TEXT NOT NULL PRIMARY KEY
        CHECK (
            length(profile_id) = 64
            AND profile_id NOT GLOB '*[^0-9a-f]*'
        ),
    format_version INTEGER NOT NULL CHECK (format_version = 1),
    matrix_version TEXT NOT NULL,
    created_at INTEGER NOT NULL CHECK (typeof(created_at) = 'integer'),
    budget_cap REAL NOT NULL
        CHECK (budget_cap > 0 AND budget_cap < 1.0e100),
    parameters_json TEXT NOT NULL
        CHECK (
            json_valid(parameters_json)
            AND json_type(parameters_json) = 'object'
        )
);

ALTER TABLE sessions
    ADD COLUMN accounting_version INTEGER NOT NULL DEFAULT 1
        CHECK (accounting_version IN (1, 2));

ALTER TABLE sessions
    ADD COLUMN accounting_status TEXT NOT NULL DEFAULT 'legacy'
        CHECK (accounting_status IN ('legacy', 'available', 'unavailable'));

ALTER TABLE sessions
    ADD COLUMN profile_id TEXT REFERENCES scoring_profiles(profile_id);

CREATE TABLE observations (
    observation_id TEXT NOT NULL PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    delivery_key TEXT NOT NULL,
    action_id TEXT NOT NULL,
    turn_id TEXT,
    ts INTEGER NOT NULL CHECK (typeof(ts) = 'integer'),
    hook_event TEXT NOT NULL CHECK (hook_event IN (
        'SessionStart', 'SessionEnd', 'UserPromptSubmit',
        'PreToolUse', 'PostToolUse', 'SubagentStart',
        'SubagentStop', 'PreCompact'
    )),
    phase TEXT NOT NULL CHECK (phase IN ('pre', 'post', 'lifecycle')),
    action_kind TEXT NOT NULL CHECK (action_kind IN (
        'read', 'tool', 'prompt', 'subagent', 'lifecycle', 'other'
    )),
    boundary TEXT NOT NULL CHECK (boundary IN ('B0', 'B1', 'B2', 'B3', 'B4')),
    decision TEXT NOT NULL CHECK (decision IN ('none', 'allow', 'deny', 'rewrite')),
    evidence INTEGER NOT NULL
        CHECK (typeof(evidence) = 'integer' AND evidence BETWEEN 0 AND 2047),
    resolution_scope TEXT NOT NULL DEFAULT 'none'
        CHECK (resolution_scope IN ('none', 'pairs', 'boundary')),
    potential_crossing INTEGER NOT NULL
        CHECK (potential_crossing IN (0, 1)),
    scan_gap TEXT CHECK (scan_gap IN ('oversize', 'unavailable', 'busy', 'timeout')),
    UNIQUE (session_id, delivery_key),
    UNIQUE (session_id, observation_id),
    CHECK ((evidence & 2) = 0 OR decision = 'deny'),
    CHECK ((evidence & 8) = 0 OR decision = 'rewrite'),
    CHECK ((evidence & 1) = 0 OR decision IN ('allow', 'rewrite')),
    CHECK (resolution_scope = 'none' OR (evidence & 212) <> 0),
    CHECK (scan_gap IS NULL OR phase <> 'lifecycle')
);

CREATE INDEX observations_action
    ON observations(session_id, action_id, boundary, ts, observation_id);

CREATE TABLE subjects (
    subject_id TEXT NOT NULL PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    subject_kind TEXT NOT NULL CHECK (subject_kind IN ('value', 'file')),
    resolution TEXT NOT NULL CHECK (resolution IN ('resolved', 'unresolved')),
    identity_hash BLOB CHECK (
        identity_hash IS NULL
        OR (typeof(identity_hash) = 'blob' AND length(identity_hash) = 32)
    ),
    label TEXT NOT NULL,
    unresolved_observation_id TEXT,
    UNIQUE (session_id, subject_id),
    FOREIGN KEY (session_id, unresolved_observation_id)
        REFERENCES observations(session_id, observation_id),
    CHECK (
        (resolution = 'resolved' AND unresolved_observation_id IS NULL)
        OR
        (resolution = 'unresolved'
         AND identity_hash IS NULL
         AND unresolved_observation_id IS NOT NULL)
    )
);

CREATE UNIQUE INDEX subjects_identity
    ON subjects(session_id, subject_kind, identity_hash)
    WHERE identity_hash IS NOT NULL;

CREATE TABLE recipients (
    recipient_id TEXT NOT NULL PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    destination_kind TEXT NOT NULL CHECK (destination_kind IN (
        'local', 'model_context', 'subagent', 'mcp_tool', 'external_net'
    )),
    resolution TEXT NOT NULL CHECK (resolution IN ('resolved', 'unresolved')),
    identity_hash BLOB CHECK (
        identity_hash IS NULL
        OR (typeof(identity_hash) = 'blob' AND length(identity_hash) = 32)
    ),
    label TEXT NOT NULL,
    unresolved_observation_id TEXT,
    UNIQUE (session_id, recipient_id),
    FOREIGN KEY (session_id, unresolved_observation_id)
        REFERENCES observations(session_id, observation_id),
    CHECK (
        (resolution = 'resolved' AND unresolved_observation_id IS NULL)
        OR
        (resolution = 'unresolved'
         AND identity_hash IS NULL
         AND unresolved_observation_id IS NOT NULL)
    )
);

CREATE UNIQUE INDEX recipients_identity
    ON recipients(session_id, destination_kind, identity_hash)
    WHERE identity_hash IS NOT NULL;

CREATE TABLE events (
    id INTEGER PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    observation_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    recipient_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN (
        'detected', 'local_access', 'permitted',
        'exposed', 'prevented', 'retention'
    )),
    evidence INTEGER NOT NULL
        CHECK (typeof(evidence) = 'integer' AND evidence BETWEEN 0 AND 2047),
    data_type TEXT NOT NULL CHECK (data_type IN (
        'credential', 'financial', 'health', 'email', 'phone',
        'person', 'address', 'ssn', 'account', 'url', 'date',
        'hostname', 'path', 'ip', 'repo'
    )),
    rule_id TEXT,
    occurrences INTEGER NOT NULL DEFAULT 1
        CHECK (typeof(occurrences) = 'integer' AND occurrences >= 1),
    source_label TEXT NOT NULL,
    source_kind TEXT CHECK (source_kind IN ('path', 'command')),
    boundary TEXT NOT NULL CHECK (boundary IN ('B0', 'B1', 'B2', 'B3', 'B4')),
    masked_example TEXT,
    FOREIGN KEY (session_id, observation_id)
        REFERENCES observations(session_id, observation_id),
    FOREIGN KEY (session_id, subject_id)
        REFERENCES subjects(session_id, subject_id),
    FOREIGN KEY (session_id, recipient_id)
        REFERENCES recipients(session_id, recipient_id),
    UNIQUE (observation_id, subject_id, recipient_id, kind),
    UNIQUE (session_id, id, subject_id, recipient_id),
    CHECK (kind <> 'exposed' OR (boundary <> 'B0' AND (evidence & 64) <> 0)),
    CHECK (kind <> 'permitted' OR (evidence & 1) <> 0),
    CHECK (kind <> 'prevented' OR (evidence & 150) <> 0),
    CHECK (kind <> 'local_access' OR (boundary = 'B0' AND (evidence & 32) <> 0)),
    CHECK (kind <> 'detected' OR (evidence & 256) <> 0),
    CHECK (kind <> 'retention' OR (evidence & 512) <> 0),
    CHECK (data_type NOT IN ('credential', 'path') OR masked_example IS NULL)
);

CREATE INDEX events_session_kind
    ON events(session_id, kind, id);

CREATE INDEX events_session_subject_recipient
    ON events(session_id, subject_id, recipient_id, id);

CREATE TABLE disclosures (
    disclosure_id INTEGER PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    subject_id TEXT NOT NULL,
    recipient_id TEXT NOT NULL,
    first_event_id INTEGER NOT NULL,
    charged_data_type TEXT NOT NULL CHECK (charged_data_type IN (
        'credential', 'financial', 'health', 'email', 'phone',
        'person', 'address', 'ssn', 'account', 'url', 'date',
        'hostname', 'path', 'ip', 'repo'
    )),
    profile_id TEXT NOT NULL REFERENCES scoring_profiles(profile_id),
    group_n INTEGER NOT NULL
        CHECK (typeof(group_n) = 'integer' AND group_n >= 1),
    budget_delta REAL NOT NULL
        CHECK (budget_delta >= 0 AND budget_delta < 1.0e100),
    FOREIGN KEY (session_id, subject_id)
        REFERENCES subjects(session_id, subject_id),
    FOREIGN KEY (session_id, recipient_id)
        REFERENCES recipients(session_id, recipient_id),
    FOREIGN KEY (session_id, first_event_id, subject_id, recipient_id)
        REFERENCES events(session_id, id, subject_id, recipient_id),
    UNIQUE (session_id, subject_id, recipient_id),
    UNIQUE (session_id, charged_data_type, recipient_id, group_n),
    UNIQUE (first_event_id)
);
"""

#: Guards on the new tables and on session accounting.
_GUARD_SQL = """
CREATE TRIGGER scoring_profiles_no_update
BEFORE UPDATE ON scoring_profiles
BEGIN
    SELECT RAISE(ABORT, 'scoring profiles are immutable');
END;

CREATE TRIGGER scoring_profiles_no_delete
BEFORE DELETE ON scoring_profiles
BEGIN
    SELECT RAISE(ABORT, 'scoring profiles are immutable');
END;

CREATE TRIGGER sessions_accounting_insert
BEFORE INSERT ON sessions
WHEN
    (NEW.accounting_version = 1 AND
        (NEW.accounting_status <> 'legacy' OR NEW.profile_id IS NOT NULL))
    OR
    (NEW.accounting_version = 2 AND
        (NEW.accounting_status <> 'available'
         OR NEW.profile_id IS NULL
         OR NEW.budget_score <> 0
         OR NOT EXISTS (
             SELECT 1 FROM scoring_profiles p
             WHERE p.profile_id = NEW.profile_id
               AND p.budget_cap = NEW.budget_cap
         )))
BEGIN
    SELECT RAISE(ABORT, 'invalid session accounting');
END;

CREATE TRIGGER sessions_accounting_frozen
BEFORE UPDATE ON sessions
WHEN
    NEW.accounting_version IS NOT OLD.accounting_version
    OR NEW.profile_id IS NOT OLD.profile_id
    OR NEW.budget_cap IS NOT OLD.budget_cap
    OR NEW.started_at IS NOT OLD.started_at
    OR NEW.budget_score < OLD.budget_score
    OR (OLD.accounting_status = 'legacy'
        AND NEW.accounting_status <> 'legacy')
    OR (OLD.accounting_status = 'unavailable'
        AND NEW.accounting_status <> 'unavailable')
    OR (OLD.accounting_status = 'available'
        AND NEW.accounting_status NOT IN ('available', 'unavailable'))
    OR (OLD.ended_at IS NOT NULL AND NEW.ended_at IS NOT OLD.ended_at)
    OR (OLD.ended_at IS NOT NULL AND NEW.budget_score IS NOT OLD.budget_score)
    OR (NEW.accounting_version = 2 AND
        (typeof(NEW.budget_score) NOT IN ('integer', 'real')
         OR NEW.budget_score < 0
         OR NEW.budget_score >= 1.0e100))
BEGIN
    SELECT RAISE(ABORT, 'session accounting is frozen or monotonic');
END;

CREATE TRIGGER observations_v2_only
BEFORE INSERT ON observations
WHEN NOT EXISTS (
    SELECT 1 FROM sessions
    WHERE session_id = NEW.session_id AND accounting_version = 2
)
BEGIN
    SELECT RAISE(ABORT, 'observation requires accounting version 2');
END;

CREATE TRIGGER events_observation_evidence
BEFORE INSERT ON events
WHEN NOT EXISTS (
    SELECT 1 FROM observations o
    WHERE o.session_id = NEW.session_id
      AND o.observation_id = NEW.observation_id
      AND o.boundary = NEW.boundary
      AND (NEW.evidence & o.evidence) = NEW.evidence
)
BEGIN
    SELECT RAISE(ABORT, 'event evidence does not match observation');
END;

CREATE TRIGGER disclosures_chargeable
BEFORE INSERT ON disclosures
WHEN NOT EXISTS (
    SELECT 1
    FROM sessions s
    JOIN events e ON e.session_id = s.session_id
    JOIN subjects u
      ON u.session_id = e.session_id AND u.subject_id = e.subject_id
    JOIN recipients r
      ON r.session_id = e.session_id AND r.recipient_id = e.recipient_id
    WHERE s.session_id = NEW.session_id
      AND s.accounting_version = 2
      AND s.accounting_status = 'available'
      AND s.ended_at IS NULL
      AND s.profile_id = NEW.profile_id
      AND e.id = NEW.first_event_id
      AND e.subject_id = NEW.subject_id
      AND e.recipient_id = NEW.recipient_id
      AND e.data_type = NEW.charged_data_type
      AND e.kind = 'exposed'
      AND (e.evidence & 64) <> 0
      AND u.resolution = 'resolved'
      AND u.identity_hash IS NOT NULL
      AND r.resolution = 'resolved'
      AND r.identity_hash IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'disclosure requires chargeable crossing evidence');
END;
"""

#: The legacy columns the legacy readers and writer require; `source_kind`
#: is the one a historical table may lack.
LEGACY_REQUIRED_COLUMNS = frozenset({
    "id", "session_id", "turn_id", "ts", "kind", "data_type", "source",
    "destination", "boundary", "count", "value_hash", "masked_example",
    "budget_delta", "protection", "tool_name",
})
LEGACY_OPTIONAL_COLUMNS = frozenset({"source_kind"})

_NEW_TABLES = ("scoring_profiles", "observations", "subjects", "recipients",
               "events", "disclosures")
_SESSION_COLUMNS = frozenset({"accounting_version", "accounting_status",
                              "profile_id"})


class UnsupportedAccounting(RuntimeError):
    """A session or schema the running code cannot describe or write
    honestly: an unknown schema version, an incomplete rebuild, a legacy
    layout this reader does not know, or a session under accounting it does
    not implement. Raised rather than repaired or guessed around."""


def split_statements(sql: str) -> tuple[str, ...]:
    """Complete SQL statements in `sql`, in order, without their final
    semicolon. Uses SQLite's own completeness test, so a semicolon inside a
    comment or a trigger body does not split a statement."""
    statements: list[str] = []
    pending = ""
    for line in sql.splitlines(keepends=True):
        pending += line
        if sqlite3.complete_statement(pending):
            text = pending.strip()
            if text.rstrip(";").strip() and not _is_comment_only(text):
                statements.append(text.rstrip().rstrip(";").rstrip())
            pending = ""
    if pending.strip() and not _is_comment_only(pending.strip()):
        raise ValueError("incomplete SQL statement")
    return tuple(statements)


def _is_comment_only(text: str) -> bool:
    return all(not line.strip() or line.strip().startswith("--")
               for line in text.splitlines())


def legacy_statements() -> tuple[str, ...]:
    return split_statements(LEGACY_SCHEMA)


def history_trigger_statements() -> tuple[str, ...]:
    result: list[str] = []

    for table in (
        "observations", "events", "disclosures", "coverage", "scan_gaps"
    ):
        for operation in ("UPDATE", "DELETE"):
            result.append(
                f"CREATE TRIGGER {table}_no_{operation.lower()} "
                f"BEFORE {operation} ON {table} BEGIN "
                "SELECT RAISE(ABORT, 'append-only history'); END"
            )

    metadata_columns = {
        "subjects": (
            "subject_id", "session_id", "subject_kind",
            "resolution", "label", "unresolved_observation_id",
        ),
        "recipients": (
            "recipient_id", "session_id", "destination_kind",
            "resolution", "label", "unresolved_observation_id",
        ),
    }

    for table, columns in metadata_columns.items():
        result.append(
            f"CREATE TRIGGER {table}_no_delete "
            f"BEFORE DELETE ON {table} BEGIN "
            "SELECT RAISE(ABORT, 'identity metadata is immutable'); END"
        )
        result.append(
            f"CREATE TRIGGER {table}_metadata_immutable "
            f"BEFORE UPDATE OF {', '.join(columns)} ON {table} BEGIN "
            "SELECT RAISE(ABORT, 'identity metadata is immutable'); END"
        )
        result.append(
            f"CREATE TRIGGER {table}_identity_erasure_only "
            f"BEFORE UPDATE OF identity_hash ON {table} "
            "WHEN NEW.identity_hash IS NOT NULL OR NOT EXISTS ("
            "SELECT 1 FROM sessions "
            "WHERE session_id = OLD.session_id AND ended_at IS NOT NULL"
            ") BEGIN "
            "SELECT RAISE(ABORT, 'identity erasure requires an ended session'); END"
        )
        result.append(
            f"CREATE TRIGGER {table}_identity_insert "
            f"BEFORE INSERT ON {table} "
            "WHEN NOT EXISTS (SELECT 1 FROM sessions "
            "WHERE session_id = NEW.session_id AND accounting_version = 2) "
            "OR (NEW.resolution = 'resolved' AND "
            "(NEW.identity_hash IS NULL OR NOT EXISTS ("
            "SELECT 1 FROM sessions WHERE session_id = NEW.session_id "
            "AND ended_at IS NULL AND accounting_status = 'available'"
            "))) BEGIN "
            "SELECT RAISE(ABORT, 'invalid accounting identity'); END"
        )

    return tuple(result)


def migration_statements() -> tuple[str, ...]:
    """The Phase 2 structural migration, in execution order, ending with
    the schema marker. Executed statement by statement inside the caller's
    write transaction; never `executescript`."""
    return (split_statements(_STRUCTURAL_SQL)
            + split_statements(_GUARD_SQL)
            + history_trigger_statements()
            + (f"PRAGMA user_version = {PREPARED_VERSION}",))


def _norm(sql: str | None) -> str:
    return " ".join((sql or "").split())


def _reference() -> dict[tuple[str, str], str]:
    """Every object the migration creates, as (type, name) -> SQL, from a
    legacy schema migrated in memory."""
    ref = sqlite3.connect(":memory:", isolation_level=None)
    try:
        for statement in legacy_statements():
            ref.execute(statement)
        before = {(t, n) for t, n in ref.execute(
            "SELECT type, name FROM sqlite_master")}
        for statement in migration_statements():
            ref.execute(statement)
        return {(t, n): _norm(sql) for t, n, sql in ref.execute(
            "SELECT type, name, sql FROM sqlite_master")
            if sql is not None and (
                (t, n) not in before
                or (t, n) in {
                    ("table", "events"),
                    ("table", "sessions"),
                }
            )}
    finally:
        ref.close()


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}


def _require_legacy_layout(conn: sqlite3.Connection, table: str) -> None:
    present = _columns(conn, table)
    if LEGACY_REQUIRED_COLUMNS - present or \
            present - LEGACY_REQUIRED_COLUMNS - LEGACY_OPTIONAL_COLUMNS:
        raise UnsupportedAccounting(
            "the legacy events table does not have the required layout")


def validate_schema(conn: sqlite3.Connection
                    ) -> Literal[0, 5401, 5402]:
    """The schema generation of `conn`'s database, after checking that its
    structure is exactly that generation's. Raises `UnsupportedAccounting`
    for an unknown version, an incomplete or altered rebuild, or a legacy
    table this code does not know. Never repairs.

    A legacy (0) database may lack the legacy tables entirely (a new file)
    or lack `source_kind`; it must not already hold `events_legacy_v1`.
    A prepared or activated database must hold every object the migration
    creates, with the same definition, and the added session columns.
    """
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    tables = _tables(conn)
    if version == 0:
        if (
            "events_legacy_v1" in tables
            or (set(_NEW_TABLES) - {"events"}) & tables
            or _SESSION_COLUMNS & _columns(conn, "sessions")
        ):
            raise UnsupportedAccounting(
                "the ledger holds a partial rebuild without a schema marker")
        if "events" in tables:
            _require_legacy_layout(conn, "events")
        return 0
    if version not in (PREPARED_VERSION, ACTIVATED_VERSION):
        raise UnsupportedAccounting("unknown ledger schema version")
    if "events_legacy_v1" not in tables:
        raise UnsupportedAccounting("the rebuilt ledger lacks its legacy table")
    _require_legacy_layout(conn, "events_legacy_v1")
    if _SESSION_COLUMNS - _columns(conn, "sessions"):
        raise UnsupportedAccounting("the rebuilt ledger's sessions are incomplete")
    actual = {(t, n): _norm(sql) for t, n, sql in conn.execute(
        "SELECT type, name, sql FROM sqlite_master")}
    reference = _reference()
    session_suffix = ", accounting_version" + reference[
        ("table", "sessions")
    ].split(", accounting_version", 1)[1]
    if not actual.get(("table", "sessions"), "").endswith(session_suffix):
        raise UnsupportedAccounting(
            "the rebuilt ledger's session accounting definitions are invalid")

    for key, sql in reference.items():
        # Preserve the historical session definition preceding the added
        # accounting columns and the renamed legacy table's actual layout.
        if key in (("table", "sessions"), ("table", "events_legacy_v1")):
            continue
        if actual.get(key) != sql:
            raise UnsupportedAccounting(
                "the rebuilt ledger's schema does not match its version")
    return version  # type: ignore[return-value]
