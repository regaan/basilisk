"""
Basilisk Database — SQLite persistence with a worker-backed async API.

The public surface stays async for the rest of the application, but SQLite work
runs on a dedicated per-database worker thread. That keeps the event loop
responsive while avoiding unstable ad-hoc handoff patterns and preserving a
single, predictable WAL-backed connection for each database path.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import queue
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 3

ACTIVE_RUNTIME_STATUSES = (
    "initializing",
    "running",
    "recon",
    "attacking",
    "evolving",
    "stopping",
    "resuming",
)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    target_url TEXT NOT NULL,
    provider TEXT NOT NULL,
    mode TEXT NOT NULL,
    profile_json TEXT,
    config_json TEXT,
    status TEXT DEFAULT 'running',
    started_at TEXT NOT NULL,
    finished_at TEXT,
    summary_json TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    attack_module TEXT NOT NULL,
    payload TEXT,
    response TEXT,
    conversation_json TEXT,
    evolution_generation INTEGER,
    confidence REAL DEFAULT 0.0,
    remediation TEXT,
    references_json TEXT,
    tags_json TEXT,
    timestamp TEXT NOT NULL,
    metadata_json TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS evolution_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    best_fitness REAL,
    avg_fitness REAL,
    population_size INTEGER,
    mutations_applied INTEGER,
    breakthroughs INTEGER DEFAULT 0,
    best_payload TEXT,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    attack_module TEXT NOT NULL,
    messages_json TEXT NOT NULL,
    result TEXT,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS scan_runtime (
    session_id TEXT PRIMARY KEY,
    db_path TEXT NOT NULL,
    target_url TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT,
    status TEXT NOT NULL,
    current_phase TEXT DEFAULT '',
    progress_json TEXT,
    config_json TEXT,
    campaign_json TEXT,
    policy_json TEXT,
    last_error TEXT DEFAULT '',
    stop_requested INTEGER DEFAULT 0,
    resumable INTEGER DEFAULT 1,
    started_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_evolution_session ON evolution_log(session_id);
CREATE INDEX IF NOT EXISTS idx_conversations_session ON conversations(session_id);
CREATE INDEX IF NOT EXISTS idx_scan_runtime_status ON scan_runtime(status);
"""


class BasiliskDatabase:
    """
    Async SQLite database for persisting scan data.

    Each DB path is served by a shared dedicated worker thread. Multiple
    BasiliskDatabase instances pointing at the same path reuse that worker and
    its WAL-enabled connection, which avoids blocking the main event loop while
    keeping SQLite access serialized and predictable.
    """

    _workers: dict[str, _DatabaseWorker] = {}
    _registry_lock = threading.Lock()

    def __init__(self, db_path: str = "./basilisk-sessions.db") -> None:
        self.db_path = Path(db_path)
        self._worker: _DatabaseWorker | None = None

    async def connect(self) -> None:
        """Open database connection and initialize schema."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if self._worker is not None:
            await self._worker.wait_until_ready()
            return

        key = str(self.db_path.resolve())
        with self._registry_lock:
            worker = self._workers.get(key)
            if worker is None:
                worker = _DatabaseWorker(self.db_path)
                self._workers[key] = worker
                worker.start()
            worker.refcount += 1
            self._worker = worker

        try:
            await worker.wait_until_ready()
        except Exception:
            with self._registry_lock:
                worker.refcount = max(0, worker.refcount - 1)
                if worker.refcount == 0 and self._workers.get(key) is worker:
                    self._workers.pop(key, None)
            self._worker = None
            raise

    async def close(self) -> None:
        """Close database connection."""
        worker = self._worker
        if worker is None:
            return

        self._worker = None
        should_shutdown = False
        key = str(self.db_path.resolve())
        with self._registry_lock:
            worker.refcount = max(0, worker.refcount - 1)
            if worker.refcount == 0 and self._workers.get(key) is worker:
                self._workers.pop(key, None)
                should_shutdown = True

        if should_shutdown:
            worker.shutdown()

    @property
    def db(self) -> sqlite3.Connection:
        raise RuntimeError("Direct SQLite access is not exposed; use the async BasiliskDatabase methods.")

    async def _write(self, query: str, params: tuple[Any, ...]) -> None:
        def operation(conn: sqlite3.Connection) -> None:
            conn.execute(query, params)
            conn.commit()

        await self._run(operation)

    async def _fetchone(self, query: str, params: tuple[Any, ...]) -> dict[str, Any] | None:
        def operation(conn: sqlite3.Connection) -> dict[str, Any] | None:
            cursor = conn.execute(query, params)
            try:
                row = cursor.fetchone()
                if row is None:
                    return None
                return dict(row)
            finally:
                cursor.close()

        return await self._run(operation)

    async def _fetchall(self, query: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        def operation(conn: sqlite3.Connection) -> list[dict[str, Any]]:
            cursor = conn.execute(query, params)
            try:
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
            finally:
                cursor.close()

        return await self._run(operation)

    # --- Sessions ---

    async def save_session(self, session_data: dict[str, Any]) -> None:
        await self._write(
            """INSERT OR REPLACE INTO sessions
               (id, target_url, provider, mode, profile_json, config_json, status, started_at, finished_at, summary_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                session_data["id"],
                session_data["target_url"],
                session_data["provider"],
                session_data["mode"],
                json.dumps(session_data.get("profile")),
                json.dumps(session_data.get("config")),
                session_data.get("status", "running"),
                session_data["started_at"],
                session_data.get("finished_at"),
                json.dumps(session_data.get("summary")),
            ),
        )

    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        data = await self._fetchone(
            "SELECT * FROM sessions WHERE id = ?",
            (session_id,),
        )
        if not data:
            return None
        for key in ("profile_json", "config_json", "summary_json"):
            if data.get(key):
                data[key.replace("_json", "")] = json.loads(data[key])
        return data

    async def list_sessions(self, limit: int = 50) -> list[dict[str, Any]]:
        results = await self._fetchall(
            """SELECT id, target_url, provider, mode, status, started_at, finished_at, config_json, summary_json
               FROM sessions
               ORDER BY started_at DESC
               LIMIT ?""",
            (limit,),
        )
        for data in results:
            for key in ("config_json", "summary_json"):
                if data.get(key):
                    data[key.replace("_json", "")] = json.loads(data[key])
        return results

    async def update_session_status(
        self,
        session_id: str,
        status: str,
        finished_at: str | None = None,
        summary: dict[str, Any] | None = None,
    ) -> None:
        await self._write(
            "UPDATE sessions SET status = ?, finished_at = ?, summary_json = ? WHERE id = ?",
            (status, finished_at, json.dumps(summary) if summary else None, session_id),
        )

    async def purge_sessions_before(self, cutoff_iso: str) -> int:
        """Delete session rows and dependent artifacts older than the cutoff."""
        rows = await self._fetchall(
            "SELECT id FROM sessions WHERE started_at < ?",
            (cutoff_iso,),
        )
        session_ids = [row["id"] for row in rows]
        for session_id in session_ids:
            await self._write("DELETE FROM findings WHERE session_id = ?", (session_id,))
            await self._write("DELETE FROM evolution_log WHERE session_id = ?", (session_id,))
            await self._write("DELETE FROM conversations WHERE session_id = ?", (session_id,))
            await self._write("DELETE FROM sessions WHERE id = ?", (session_id,))
        return len(session_ids)

    async def clear_history(self) -> int:
        """Remove all persisted session history and runtime state."""
        count_row = await self._fetchone("SELECT COUNT(*) AS count FROM sessions", ())
        session_count = int((count_row or {}).get("count", 0))
        def operation(conn: sqlite3.Connection) -> None:
            conn.execute("DELETE FROM findings")
            conn.execute("DELETE FROM evolution_log")
            conn.execute("DELETE FROM conversations")
            conn.execute("DELETE FROM scan_runtime")
            conn.execute("DELETE FROM sessions")
            conn.commit()

        await self._run(operation)
        return session_count

    # --- Findings ---

    async def save_finding(self, session_id: str, finding_data: dict[str, Any]) -> None:
        await self._write(
            """INSERT OR REPLACE INTO findings
               (id, session_id, title, severity, category, attack_module, payload, response,
                conversation_json, evolution_generation, confidence, remediation,
                references_json, tags_json, timestamp, metadata_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding_data["id"],
                session_id,
                finding_data["title"],
                finding_data["severity"],
                finding_data["category"],
                finding_data["attack_module"],
                finding_data.get("payload", ""),
                finding_data.get("response", ""),
                json.dumps(finding_data.get("conversation", [])),
                finding_data.get("evolution_generation"),
                finding_data.get("confidence", 0.0),
                finding_data.get("remediation", ""),
                json.dumps(finding_data.get("references", [])),
                json.dumps(finding_data.get("tags", [])),
                finding_data["timestamp"],
                json.dumps(finding_data.get("metadata", {})),
            ),
        )

    async def get_findings(self, session_id: str) -> list[dict[str, Any]]:
        results = await self._fetchall(
            """SELECT * FROM findings
               WHERE session_id = ?
               ORDER BY CASE severity
                   WHEN 'critical' THEN 4
                   WHEN 'high' THEN 3
                   WHEN 'medium' THEN 2
                   WHEN 'low' THEN 1
                   ELSE 0
               END DESC, timestamp""",
            (session_id,),
        )
        for data in results:
            for key in ("conversation_json", "references_json", "tags_json", "metadata_json"):
                if data.get(key):
                    data[key.replace("_json", "")] = json.loads(data[key])
        return results

    # --- Evolution Log ---

    async def save_evolution_entry(self, session_id: str, entry: dict[str, Any]) -> None:
        await self._write(
            """INSERT INTO evolution_log
               (session_id, generation, best_fitness, avg_fitness, population_size,
                mutations_applied, breakthroughs, best_payload, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                session_id,
                entry["generation"],
                entry.get("best_fitness", 0.0),
                entry.get("avg_fitness", 0.0),
                entry.get("population_size", 0),
                entry.get("mutations_applied", 0),
                entry.get("breakthroughs", 0),
                entry.get("best_payload", ""),
                entry["timestamp"],
            ),
        )

    async def get_evolution_log(self, session_id: str) -> list[dict[str, Any]]:
        return await self._fetchall(
            "SELECT * FROM evolution_log WHERE session_id = ? ORDER BY generation",
            (session_id,),
        )

    # --- Conversations ---

    async def save_conversation(
        self,
        session_id: str,
        attack_module: str,
        messages: list[dict[str, Any]],
        result: str,
        timestamp: str,
    ) -> None:
        await self._write(
            "INSERT INTO conversations (session_id, attack_module, messages_json, result, timestamp) VALUES (?, ?, ?, ?, ?)",
            (session_id, attack_module, json.dumps(messages), result, timestamp),
        )

    async def get_conversations(
        self,
        session_id: str,
        attack_module: str | None = None,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM conversations WHERE session_id = ?"
        params: list[Any] = [session_id]
        if attack_module:
            query += " AND attack_module = ?"
            params.append(attack_module)
        query += " ORDER BY timestamp"
        results = await self._fetchall(query, tuple(params))
        for data in results:
            if data.get("messages_json"):
                data["messages"] = json.loads(data["messages_json"])
        return results

    # --- Runtime State ---

    async def save_scan_runtime(self, runtime_data: dict[str, Any]) -> None:
        await self._write(
            """INSERT OR REPLACE INTO scan_runtime
               (session_id, db_path, target_url, provider, model, status, current_phase,
                progress_json, config_json, campaign_json, policy_json, last_error,
                stop_requested, resumable, started_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                runtime_data["session_id"],
                runtime_data["db_path"],
                runtime_data["target_url"],
                runtime_data["provider"],
                runtime_data.get("model", ""),
                runtime_data["status"],
                runtime_data.get("current_phase", ""),
                json.dumps(runtime_data.get("progress", {})),
                json.dumps(runtime_data.get("config", {})),
                json.dumps(runtime_data.get("campaign", {})),
                json.dumps(runtime_data.get("policy", {})),
                runtime_data.get("last_error", ""),
                1 if runtime_data.get("stop_requested") else 0,
                1 if runtime_data.get("resumable", True) else 0,
                runtime_data["started_at"],
                runtime_data["updated_at"],
            ),
        )

    async def get_scan_runtime(self, session_id: str) -> dict[str, Any] | None:
        data = await self._fetchone(
            "SELECT * FROM scan_runtime WHERE session_id = ?",
            (session_id,),
        )
        return self._decode_runtime(data)

    async def list_scan_runtimes(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = await self._fetchall(
            "SELECT * FROM scan_runtime ORDER BY updated_at DESC LIMIT ?",
            (limit,),
        )
        return [self._decode_runtime(row) for row in rows if row]

    async def delete_scan_runtime(self, session_id: str) -> None:
        await self._write("DELETE FROM scan_runtime WHERE session_id = ?", (session_id,))

    async def mark_stale_scan_runtimes_interrupted(self, active_session_ids: set[str]) -> int:
        placeholders = ", ".join("?" for _ in ACTIVE_RUNTIME_STATUSES)
        rows = await self._fetchall(
            f"SELECT session_id, last_error FROM scan_runtime WHERE status IN ({placeholders})",
            ACTIVE_RUNTIME_STATUSES,
        )
        stale_ids = [row["session_id"] for row in rows if row["session_id"] not in active_session_ids]
        if not stale_ids:
            return 0

        now = datetime.now(timezone.utc).isoformat()
        for row in rows:
            session_id = row["session_id"]
            if session_id in active_session_ids:
                continue
            last_error = row.get("last_error") or "Process restart interrupted the scan."
            await self._write(
                """UPDATE scan_runtime
                   SET status = ?, current_phase = ?, last_error = ?, updated_at = ?, resumable = 1
                   WHERE session_id = ?""",
                ("interrupted", "interrupted", last_error, now, session_id),
            )
            await self._write(
                "UPDATE sessions SET status = ? WHERE id = ?",
                ("interrupted", session_id),
            )
        return len(stale_ids)

    def _decode_runtime(self, data: dict[str, Any] | None) -> dict[str, Any] | None:
        if not data:
            return None
        for key in ("progress_json", "config_json", "campaign_json", "policy_json"):
            if data.get(key):
                data[key.replace("_json", "")] = json.loads(data[key])
            else:
                data[key.replace("_json", "")] = {}
        data["stop_requested"] = bool(data.get("stop_requested"))
        data["resumable"] = bool(data.get("resumable"))
        return data

    async def _run(self, operation):
        if self._worker is None:
            await self.connect()
        if self._worker is None:
            raise RuntimeError("Database worker not initialized")
        return await self._worker.submit(operation)


class _DatabaseWorker:
    """Single SQLite worker thread shared by all handles for one DB path."""

    _STOP = object()

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.refcount = 0
        self._queue: queue.Queue[Any] = queue.Queue()
        self._ready = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name=f"basilisk-sqlite-{db_path.stem}",
            daemon=True,
        )
        self._startup_error: Exception | None = None

    def start(self) -> None:
        if not self._thread.is_alive():
            self._thread.start()

    async def wait_until_ready(self) -> None:
        while not self._ready.is_set():
            await asyncio.sleep(0.01)
        if self._startup_error:
            raise self._startup_error

    async def submit(self, operation):
        await self.wait_until_ready()
        future: concurrent.futures.Future[Any] = concurrent.futures.Future()
        self._queue.put((future, operation))
        while not future.done():
            await asyncio.sleep(0.001)
        return future.result()

    def shutdown(self) -> None:
        self._queue.put(self._STOP)
        self._thread.join(timeout=5)

    def _run(self) -> None:
        conn: sqlite3.Connection | None = None
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.executescript(SCHEMA_SQL)
            conn.execute(
                "INSERT OR REPLACE INTO schema_version (version) VALUES (?)",
                (SCHEMA_VERSION,),
            )
            conn.commit()
        except Exception as exc:
            self._startup_error = exc
            self._ready.set()
            return

        self._ready.set()
        try:
            while True:
                item = self._queue.get()
                if item is self._STOP:
                    break
                future, operation = item
                if future.cancelled():
                    continue
                try:
                    result = operation(conn)
                except Exception as exc:
                    future.set_exception(exc)
                else:
                    future.set_result(result)
        finally:
            if conn is not None:
                conn.close()
