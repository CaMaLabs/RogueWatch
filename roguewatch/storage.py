from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .models import Event


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
