"""SQLite persistence for committed rule revisions and admission records.

Rules are revisioned and append-only. Every CONNECT is judged against exactly
one snapshot (the latest committed revision read in a single statement at
decision time) and the revision number is written into the admission record,
so an audit can tell which policy version applied to each connection.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from typing import Any, Iterable

import aiosqlite

from .rules import RuleSetSnapshot, build_snapshot, validate_rules

SCHEMA = """
CREATE TABLE IF NOT EXISTS rule_revisions (
    revision     INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   TEXT    NOT NULL,
    note         TEXT    NOT NULL DEFAULT '',
    rules_json   TEXT    NOT NULL,
    rules_count  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS admissions (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at            TEXT    NOT NULL,
    finished_at           TEXT,
    kind                  TEXT    NOT NULL DEFAULT 'connect',
    client                TEXT    NOT NULL DEFAULT '',
    target_host           TEXT    NOT NULL DEFAULT '',
    target_port           INTEGER NOT NULL DEFAULT 0,
    resolved_addresses    TEXT    NOT NULL DEFAULT '[]',
    revision              INTEGER,
    decision              TEXT    NOT NULL,
    reason                TEXT    NOT NULL DEFAULT '',
    detail                TEXT    NOT NULL DEFAULT '',
    rule_index            INTEGER,
    rule_host             TEXT,
    dial_address          TEXT,
    status                TEXT    NOT NULL DEFAULT 'closed',
    close_reason          TEXT,
    bytes_client_to_target INTEGER NOT NULL DEFAULT 0,
    bytes_target_to_client INTEGER NOT NULL DEFAULT 0,
    duration_ms           INTEGER
);

CREATE INDEX IF NOT EXISTS idx_admissions_created ON admissions (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admissions_decision ON admissions (decision);
CREATE INDEX IF NOT EXISTS idx_admissions_revision ON admissions (revision);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Storage:
    """Two SQLite connections: a writer and a reader.

    The reader is a separate connection so a concurrent read can never observe
    the uncommitted rows of a rule revision that is still being written. In WAL
    mode each read statement sees the last committed snapshot, which is exactly
    the guarantee connection admission relies on.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._writer: aiosqlite.Connection | None = None
        self._reader: aiosqlite.Connection | None = None
        self._write_lock = asyncio.Lock()

    async def open(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.db_path))
        os.makedirs(directory, exist_ok=True)
        writer = await aiosqlite.connect(self.db_path, isolation_level=None)
        writer.row_factory = aiosqlite.Row
        await writer.execute("PRAGMA journal_mode=WAL")
        await writer.execute("PRAGMA synchronous=NORMAL")
        await writer.execute("PRAGMA busy_timeout=5000")
        await writer.executescript(SCHEMA)

        reader = await aiosqlite.connect(self.db_path, isolation_level=None)
        reader.row_factory = aiosqlite.Row
        await reader.execute("PRAGMA query_only=ON")
        await reader.execute("PRAGMA busy_timeout=5000")

        self._writer = writer
        self._reader = reader

    async def close(self) -> None:
        for attr in ("_writer", "_reader"):
            conn = getattr(self, attr)
            if conn is not None:
                await conn.close()
                setattr(self, attr, None)

    @property
    def writer(self) -> aiosqlite.Connection:
        if self._writer is None:
            raise RuntimeError("storage is not open")
        return self._writer

    @property
    def reader(self) -> aiosqlite.Connection:
        if self._reader is None:
            raise RuntimeError("storage is not open")
        return self._reader

    # -- rules -------------------------------------------------------------

    async def latest_snapshot(self) -> RuleSetSnapshot | None:
        """Read the newest committed revision in one statement."""

        async with self.reader.execute(
            "SELECT revision, created_at, note, rules_json FROM rule_revisions "
            "ORDER BY revision DESC LIMIT 1"
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return None
        return build_snapshot(
            revision=row["revision"],
            created_at=row["created_at"],
            note=row["note"],
            normalized_rules=json.loads(row["rules_json"]),
        )

    async def commit_rules(
        self, raw_rules: Any, note: str = ""
    ) -> tuple[RuleSetSnapshot, int | None]:
        """Validate and append a new revision.

        Returns the new snapshot and the previous revision number (or ``None``
        when this is the first revision). Validation happens before the write,
        so an invalid submission never becomes visible to connections.
        """

        normalized = validate_rules(raw_rules)
        async with self._write_lock:
            await self.writer.execute("BEGIN IMMEDIATE")
            try:
                async with self.writer.execute(
                    "SELECT COALESCE(MAX(revision), 0) AS max_rev FROM rule_revisions"
                ) as cursor:
                    row = await cursor.fetchone()
                previous = int(row["max_rev"]) or None
                created_at = utc_now()
                await self.writer.execute(
                    "INSERT INTO rule_revisions (created_at, note, rules_json, rules_count) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        created_at,
                        note,
                        json.dumps(normalized, separators=(",", ":"), sort_keys=True),
                        len(normalized),
                    ),
                )
                async with self.writer.execute(
                    "SELECT last_insert_rowid() AS revision"
                ) as cursor:
                    row = await cursor.fetchone()
                revision = int(row["revision"])
                await self.writer.execute("COMMIT")
            except BaseException:
                await self.writer.execute("ROLLBACK")
                raise
        return (
            build_snapshot(revision, created_at, note, normalized),
            previous,
        )

    async def seed_if_empty(self, raw_rules: Iterable[dict[str, Any]]) -> RuleSetSnapshot:
        snapshot = await self.latest_snapshot()
        if snapshot is not None:
            return snapshot
        snapshot, _ = await self.commit_rules(
            list(raw_rules), note="bootstrap: default demo rule"
        )
        return snapshot

    async def list_revisions(self, limit: int = 50) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 200))
        async with self.reader.execute(
            "SELECT revision, created_at, note, rules_json, rules_count FROM rule_revisions "
            "ORDER BY revision DESC LIMIT ?",
            (limit,),
        ) as cursor:
            rows = await cursor.fetchall()
        out = []
        for row in rows:
            out.append(
                {
                    "revision": row["revision"],
                    "created_at": row["created_at"],
                    "note": row["note"],
                    "rules_count": row["rules_count"],
                    "rules": json.loads(row["rules_json"]),
                }
            )
        return out

    async def revision_exists(self, revision: int) -> bool:
        async with self.reader.execute(
            "SELECT 1 FROM rule_revisions WHERE revision = ?", (revision,)
        ) as cursor:
            return await cursor.fetchone() is not None

    # -- admissions --------------------------------------------------------

    async def begin_admission(
        self,
        *,
        kind: str,
        client: str,
        target_host: str,
        target_port: int,
        resolved_addresses: Iterable[str],
        revision: int | None,
        decision: str,
        reason: str,
        detail: str = "",
        rule_index: int | None = None,
        rule_host: str | None = None,
        dial_address: str | None = None,
        status: str = "closed",
        close_reason: str | None = None,
        finished: bool = True,
    ) -> int:
        finished_at = utc_now() if finished else None
        async with self._write_lock:
            cursor = await self.writer.execute(
                "INSERT INTO admissions (created_at, finished_at, kind, client, target_host, "
                "target_port, resolved_addresses, revision, decision, reason, detail, rule_index, "
                "rule_host, dial_address, status, close_reason) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    utc_now(),
                    finished_at,
                    kind,
                    client[:255],
                    (target_host or "")[:255],
                    target_port or 0,
                    json.dumps(list(resolved_addresses))[:8192],
                    revision,
                    decision,
                    (reason or "")[:100],
                    (detail or "")[:2000],
                    rule_index,
                    (rule_host or "")[:255] or None,
                    dial_address,
                    status,
                    (close_reason or "")[:100] or None,
                ),
            )
            return int(cursor.lastrowid)

    async def finish_admission(
        self,
        admission_id: int,
        *,
        status: str,
        close_reason: str,
        bytes_client_to_target: int,
        bytes_target_to_client: int,
        duration_ms: int,
        decision: str | None = None,
        reason: str | None = None,
        detail: str | None = None,
    ) -> None:
        fields = [
            "finished_at = ?",
            "status = ?",
            "close_reason = ?",
            "bytes_client_to_target = ?",
            "bytes_target_to_client = ?",
            "duration_ms = ?",
        ]
        params: list[Any] = [
            utc_now(),
            status,
            close_reason,
            bytes_client_to_target,
            bytes_target_to_client,
            duration_ms,
        ]
        if decision is not None:
            fields.append("decision = ?")
            params.append(decision)
        if reason is not None:
            fields.append("reason = ?")
            params.append(reason)
        if detail is not None:
            fields.append("detail = ?")
            params.append(detail)
        params.append(admission_id)
        async with self._write_lock:
            await self.writer.execute(
                f"UPDATE admissions SET {', '.join(fields)} WHERE id = ?", params
            )

    async def mark_connected(self, admission_id: int, dial_address: str, revision: int) -> None:
        async with self._write_lock:
            await self.writer.execute(
                "UPDATE admissions SET status = 'connected', dial_address = ?, revision = ? "
                "WHERE id = ?",
                (dial_address, revision, admission_id),
            )

    async def get_admission(self, admission_id: int) -> dict[str, Any] | None:
        async with self.reader.execute(
            "SELECT * FROM admissions WHERE id = ?", (admission_id,)
        ) as cursor:
            row = await cursor.fetchone()
        return self._row_to_admission(row) if row else None

    async def list_admissions(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        decision: str | None = None,
        kind: str | None = None,
        query: str | None = None,
    ) -> dict[str, Any]:
        limit = max(1, min(limit, 200))
        offset = max(0, offset)
        where: list[str] = []
        params: list[Any] = []
        if decision:
            where.append("decision = ?")
            params.append(decision)
        if kind:
            where.append("kind = ?")
            params.append(kind)
        if query:
            where.append("(target_host LIKE ? OR detail LIKE ? OR client LIKE ?)")
            like = f"%{query}%"
            params.extend([like, like, like])
        clause = f" WHERE {' AND '.join(where)}" if where else ""
        async with self.reader.execute(
            f"SELECT COUNT(*) AS total FROM admissions{clause}", params
        ) as cursor:
            row = await cursor.fetchone()
            total = int(row["total"])
        async with self.reader.execute(
            f"SELECT * FROM admissions{clause} ORDER BY id DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ) as cursor:
            rows = await cursor.fetchall()
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": [self._row_to_admission(row) for row in rows],
        }

    async def summary(self) -> dict[str, Any]:
        async with self.reader.execute(
            "SELECT decision, COUNT(*) AS count FROM admissions GROUP BY decision"
        ) as cursor:
            rows = await cursor.fetchall()
        counts = {row["decision"]: row["count"] for row in rows}
        async with self.reader.execute(
            "SELECT COUNT(*) AS count FROM admissions WHERE status = 'connected'"
        ) as cursor:
            row = await cursor.fetchone()
        return {
            "total": sum(counts.values()),
            "allowed": counts.get("allowed", 0),
            "denied": counts.get("denied", 0),
            "error": counts.get("error", 0),
            "open_tunnels_recorded": int(row["count"]),
        }

    @staticmethod
    def _row_to_admission(row: aiosqlite.Row) -> dict[str, Any]:
        try:
            addresses = json.loads(row["resolved_addresses"])
        except (TypeError, json.JSONDecodeError):
            addresses = []
        return {
            "id": row["id"],
            "created_at": row["created_at"],
            "finished_at": row["finished_at"],
            "kind": row["kind"],
            "client": row["client"],
            "target_host": row["target_host"],
            "target_port": row["target_port"],
            "resolved_addresses": addresses,
            "revision": row["revision"],
            "decision": row["decision"],
            "reason": row["reason"],
            "detail": row["detail"],
            "rule_index": row["rule_index"],
            "rule_host": row["rule_host"],
            "dial_address": row["dial_address"],
            "status": row["status"],
            "close_reason": row["close_reason"],
            "bytes_client_to_target": row["bytes_client_to_target"],
            "bytes_target_to_client": row["bytes_target_to_client"],
            "duration_ms": row["duration_ms"],
        }
