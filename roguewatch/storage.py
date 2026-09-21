from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .models import CaseEntry, CaseLog, Event, HuntingMode, ScanMode, ScanTarget, Severity


class EventStore:
    def __init__(self, path: str = "roguewatch.db") -> None:
        self.path = Path(path)
        self._init()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _init(self) -> None:
        with self.connect() as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    text TEXT NOT NULL,
                    url TEXT,
                    parent_actor_id TEXT,
                    reply_to_event_id TEXT,
                    metadata_json TEXT NOT NULL
                )
                """
            )
            con.execute("CREATE INDEX IF NOT EXISTS idx_events_actor_time ON events(actor_id, timestamp)")
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    status TEXT NOT NULL,
                    target TEXT,
                    severity TEXT NOT NULL DEFAULT 'informational',
                    disposition TEXT NOT NULL DEFAULT 'new',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            self._ensure_column(con, "cases", "target", "TEXT")
            self._ensure_column(con, "cases", "severity", "TEXT NOT NULL DEFAULT 'informational'")
            self._ensure_column(con, "cases", "disposition", "TEXT NOT NULL DEFAULT 'new'")
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS case_entries (
                    id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    message TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            con.execute("CREATE INDEX IF NOT EXISTS idx_case_entries_case_time ON case_entries(case_id, created_at)")
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_targets (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    allowed_hosts_json TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    hunting_mode TEXT NOT NULL,
                    interval_seconds INTEGER NOT NULL,
                    enabled INTEGER NOT NULL,
                    case_id TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_run_at TEXT,
                    last_status TEXT NOT NULL,
                    last_error TEXT NOT NULL
                )
                """
            )

    def _ensure_column(self, con: sqlite3.Connection, table: str, column: str, definition: str) -> None:
        columns = {row["name"] for row in con.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in columns:
            con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def add(self, event: Event) -> None:
        with self.connect() as con:
            con.execute(
                """INSERT OR REPLACE INTO events
                (id, source, actor_id, timestamp, kind, text, url, parent_actor_id, reply_to_event_id, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (event.id, event.source, event.actor_id, event.timestamp.isoformat(), event.kind, event.text, event.url, event.parent_actor_id, event.reply_to_event_id, json.dumps(event.metadata, sort_keys=True)),
            )

    def all(self, limit: int = 5000) -> list[Event]:
        with self.connect() as con:
            rows = con.execute("SELECT * FROM events ORDER BY timestamp ASC LIMIT ?", (limit,)).fetchall()
        return [Event(id=row["id"], source=row["source"], actor_id=row["actor_id"], timestamp=row["timestamp"], kind=row["kind"], text=row["text"], url=row["url"], parent_actor_id=row["parent_actor_id"], reply_to_event_id=row["reply_to_event_id"], metadata=json.loads(row["metadata_json"])) for row in rows]

    def count(self) -> int:
        with self.connect() as con:
            return int(con.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def add_case(self, case: CaseLog) -> None:
        with self.connect() as con:
            con.execute(
                """INSERT OR REPLACE INTO cases
                (id, title, summary, status, target, severity, disposition, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    case.id,
                    case.title,
                    case.summary,
                    case.status,
                    case.target,
                    case.severity.value,
                    case.disposition,
                    case.created_at.isoformat(),
                    case.updated_at.isoformat(),
                ),
            )

    def cases(self, limit: int = 200) -> list[CaseLog]:
        with self.connect() as con:
            rows = con.execute("SELECT * FROM cases ORDER BY updated_at DESC LIMIT ?", (limit,)).fetchall()
        return [self._case_from_row(row) for row in rows]

    def get_case(self, case_id: str) -> CaseLog | None:
        with self.connect() as con:
            row = con.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        return self._case_from_row(row) if row is not None else None

    def _case_from_row(self, row: sqlite3.Row) -> CaseLog:
        return CaseLog(
            id=row["id"],
            title=row["title"],
            summary=row["summary"],
            status=row["status"],
            target=row["target"],
            severity=Severity(row["severity"]),
            disposition=row["disposition"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def add_case_entry(self, entry: CaseEntry) -> None:
        with self.connect() as con:
            con.execute(
                """INSERT OR REPLACE INTO case_entries
                (id, case_id, kind, message, metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    entry.id,
                    entry.case_id,
                    entry.kind,
                    entry.message,
                    json.dumps(entry.metadata, sort_keys=True),
                    entry.created_at.isoformat(),
                ),
            )
            con.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (entry.created_at.isoformat(), entry.case_id))

    def case_entries(self, case_id: str, limit: int = 500) -> list[CaseEntry]:
        with self.connect() as con:
            rows = con.execute(
                "SELECT * FROM case_entries WHERE case_id = ? ORDER BY created_at ASC LIMIT ?",
                (case_id, limit),
            ).fetchall()
        return [
            CaseEntry(
                id=row["id"],
                case_id=row["case_id"],
                kind=row["kind"],
                message=row["message"],
                metadata=json.loads(row["metadata_json"]),
                created_at=row["created_at"],
            )
            for row in rows
        ]

    def save_scan_target(self, target: ScanTarget) -> None:
        with self.connect() as con:
            con.execute(
                """INSERT OR REPLACE INTO scan_targets
                (id, name, url, allowed_hosts_json, mode, hunting_mode, interval_seconds, enabled, case_id,
                 created_at, updated_at, last_run_at, last_status, last_error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    target.id,
                    target.name,
                    target.url,
                    json.dumps(target.allowed_hosts),
                    target.mode.value,
                    target.hunting_mode.value,
                    target.interval_seconds,
                    1 if target.enabled else 0,
                    target.case_id,
                    target.created_at.isoformat(),
                    target.updated_at.isoformat(),
                    target.last_run_at.isoformat() if target.last_run_at else None,
                    target.last_status,
                    target.last_error,
                ),
            )

    def scan_targets(self) -> list[ScanTarget]:
        with self.connect() as con:
            rows = con.execute("SELECT * FROM scan_targets ORDER BY created_at DESC").fetchall()
        return [self._target_from_row(row) for row in rows]

    def get_scan_target(self, target_id: str) -> ScanTarget | None:
        with self.connect() as con:
            row = con.execute("SELECT * FROM scan_targets WHERE id = ?", (target_id,)).fetchone()
        return self._target_from_row(row) if row is not None else None

    def _target_from_row(self, row: sqlite3.Row) -> ScanTarget:
        return ScanTarget(
            id=row["id"],
            name=row["name"],
            url=row["url"],
            allowed_hosts=json.loads(row["allowed_hosts_json"]),
            mode=ScanMode(row["mode"]),
            hunting_mode=HuntingMode(row["hunting_mode"]),
            interval_seconds=int(row["interval_seconds"]),
            enabled=bool(row["enabled"]),
            case_id=row["case_id"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            last_run_at=row["last_run_at"],
            last_status=row["last_status"],
            last_error=row["last_error"],
        )
