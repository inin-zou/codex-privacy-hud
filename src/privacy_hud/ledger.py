"""Append-only disclosure ledger. Metadata only — see architecture.md §5.

The schema is the privacy guarantee: there is no `content`, `prompt`,
`raw_value`, `snippet`, or `text` column anywhere. A column that does not
exist cannot leak.

Dedupe key is (session_id, value_hash, destination): the same value reaching
the same destination twice is one disclosure — increment `count`, budget
delta is 0.0. The same value reaching a NEW destination is a new disclosure.
This makes replayed hook events idempotent.

Only `kind == "exposed"` rows move the budget. `prevented`, `local_access`,
`detected` and `retention` rows are recorded but always score 0.0.

Append-only: the only permitted UPDATEs are incrementing `count` and, at
`end_session`, nulling `value_hash` for the session. No deletes, no rewrites.
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from .budget import contribution, percent
from .matrix.loader import Matrix

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
  session_id   TEXT PRIMARY KEY,
  started_at   INTEGER NOT NULL,
  ended_at     INTEGER,
  cwd          TEXT,
  model        TEXT,
  budget_score REAL NOT NULL DEFAULT 0,
  budget_cap   REAL NOT NULL DEFAULT 120
);

CREATE TABLE IF NOT EXISTS events (       -- append-only; never UPDATE except count
  id            INTEGER PRIMARY KEY,
  session_id    TEXT NOT NULL REFERENCES sessions,
  turn_id       TEXT,
  ts            INTEGER NOT NULL,
  kind          TEXT NOT NULL,            -- exposed|prevented|local_access|detected|retention
  data_type     TEXT NOT NULL,            -- email|credential|person|hostname|path|...
  source        TEXT NOT NULL,            -- support.log | user prompt | tool input
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
  scope      TEXT NOT NULL,               -- global|session:<id>
  rule_type  TEXT NOT NULL,               -- mask|block_source|allow_dest
  selector   TEXT NOT NULL,               -- data_type / path glob / destination
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_tokens (  -- one-shot consent, §8
  token      TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  tool_name  TEXT NOT NULL,
  args_hash  BLOB NOT NULL,
  mode       TEXT NOT NULL,               -- allow_once|minimize
  expires_at INTEGER NOT NULL,
  consumed   INTEGER NOT NULL DEFAULT 0
);
"""


class Ledger:
    def __init__(self, path: Path, matrix: Matrix):
        self.matrix = matrix
        self.conn = sqlite3.connect(path, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        Path(path).chmod(0o600)

    def start_session(self, session_id: str, *, cwd: str, model: str) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO sessions(session_id,started_at,cwd,model,budget_cap)"
            " VALUES(?,?,?,?,?)",
            (session_id, int(time.time()), cwd, model, self.matrix.budget_cap))

    def record(self, session_id: str, *, turn_id, kind, data_type, source,
               destination, value_hash, masked_example, tool_name,
               protection) -> float:
        # I2: unmapped destinations must raise (UnknownKey), never silently
        # score zero — propagate rather than catch.
        boundary = self.matrix.boundary_for(destination)

        existing = self.conn.execute(
            "SELECT id FROM events WHERE session_id=? AND value_hash=? AND destination=?",
            (session_id, value_hash, destination)).fetchone()
        if existing is not None:
            self.conn.execute("UPDATE events SET count=count+1 WHERE id=?",
                               (existing["id"],))
            return 0.0

        # I3: only `exposed` events move the budget.
        delta = (contribution(self.matrix, data_type, 1, destination)
                 if kind == "exposed" else 0.0)

        self.conn.execute(
            "INSERT INTO events(session_id,turn_id,ts,kind,data_type,source,"
            "destination,boundary,value_hash,masked_example,budget_delta,"
            "protection,tool_name) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (session_id, turn_id, int(time.time()), kind, data_type, source,
             destination, boundary, value_hash, masked_example, delta,
             protection, tool_name))
        if delta:
            self.conn.execute(
                "UPDATE sessions SET budget_score=budget_score+? WHERE session_id=?",
                (delta, session_id))
        return delta

    def summary(self, session_id: str) -> dict:
        row = self.conn.execute(
            "SELECT budget_score, budget_cap FROM sessions WHERE session_id=?",
            (session_id,)).fetchone()
        score = row["budget_score"] if row else 0.0
        cap = row["budget_cap"] if row else self.matrix.budget_cap

        exposed_items = self.conn.execute(
            "SELECT COUNT(*) FROM events WHERE session_id=? AND kind='exposed'",
            (session_id,)).fetchone()[0]
        destinations = self.conn.execute(
            "SELECT COUNT(DISTINCT destination) FROM events"
            " WHERE session_id=? AND kind='exposed'",
            (session_id,)).fetchone()[0]
        prevented = self.conn.execute(
            "SELECT COUNT(*) FROM events WHERE session_id=? AND kind='prevented'",
            (session_id,)).fetchone()[0]

        return {
            "percent": percent(score, cap),
            "exposed_items": exposed_items,
            "destinations": destinations,
            "prevented": prevented,
        }

    def list_events(self, session_id: str, kind: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM events WHERE session_id=? AND kind=? ORDER BY id",
            (session_id, kind)).fetchall()
        return [dict(r) for r in rows]

    def end_session(self, session_id: str) -> None:
        self.conn.execute(
            "UPDATE sessions SET ended_at=? WHERE session_id=?",
            (int(time.time()), session_id))
        self.conn.execute(
            "UPDATE events SET value_hash=NULL WHERE session_id=?",
            (session_id,))
