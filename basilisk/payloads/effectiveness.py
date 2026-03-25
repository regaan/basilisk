"""
Basilisk Probe Effectiveness Tracker -- per-probe, per-model success tracking.

Records which probes historically succeed against which models,
building a knowledge base that makes the probe library smarter
over time. Backed by SQLite for zero-dependency persistence.

Example:
    "INJ-001 has 73% bypass rate against GPT-4o but only 12% against Claude."
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("basilisk.payloads.effectiveness")

_DB_DIR = Path.home() / ".basilisk"
_DB_PATH = _DB_DIR / "probe_effectiveness.db"


def _get_connection(db_path: Path | None = None) -> sqlite3.Connection:
    """Get or create the SQLite database connection."""
    path = db_path or _DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    """Create tables if they don't exist."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS probe_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            probe_id TEXT NOT NULL,
            probe_name TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT '',
            subcategory TEXT NOT NULL DEFAULT '',
            objective TEXT NOT NULL DEFAULT '',
            provider TEXT NOT NULL,
            model TEXT NOT NULL,
            target_archetype TEXT NOT NULL DEFAULT '',
            operator_family TEXT NOT NULL DEFAULT '',
            posture_key TEXT NOT NULL DEFAULT '',
            passed INTEGER NOT NULL,
            compliance_score REAL DEFAULT 0.0,
            evidence_confidence REAL DEFAULT 0.0,
            verified INTEGER NOT NULL DEFAULT 0,
            replayable INTEGER NOT NULL DEFAULT 0,
            response_snippet TEXT DEFAULT '',
            duration_ms REAL DEFAULT 0.0,
            timestamp TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_probe_model
            ON probe_results(probe_id, provider, model);

        CREATE INDEX IF NOT EXISTS idx_model
            ON probe_results(provider, model);

        CREATE INDEX IF NOT EXISTS idx_category
            ON probe_results(category);

        CREATE INDEX IF NOT EXISTS idx_subcategory
            ON probe_results(subcategory);

        CREATE INDEX IF NOT EXISTS idx_timestamp
            ON probe_results(timestamp);
    """)
    _ensure_column(conn, "probe_results", "subcategory", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "probe_results", "objective", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "probe_results", "target_archetype", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "probe_results", "operator_family", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "probe_results", "posture_key", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "probe_results", "evidence_confidence", "REAL DEFAULT 0.0")
    _ensure_column(conn, "probe_results", "verified", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(conn, "probe_results", "replayable", "INTEGER NOT NULL DEFAULT 0")
    conn.commit()


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {
        row[1]
        for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
    }
    if column in columns:
        return
    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


@dataclass
class ProbeOutcome:
    """Single probe execution outcome for tracking."""
    probe_id: str
    probe_name: str
    category: str
    provider: str
    model: str
    passed: bool
    subcategory: str = ""
    objective: str = ""
    target_archetype: str = ""
    operator_family: str = ""
    posture_key: str = ""
    compliance_score: float = 0.0
    evidence_confidence: float = 0.0
    verified: bool = False
    replayable: bool = False
    response_snippet: str = ""
    duration_ms: float = 0.0


def record_outcome(
    outcome: ProbeOutcome,
    db_path: Path | None = None,
) -> None:
    """Record a single probe outcome to the effectiveness database."""
    conn = _get_connection(db_path)
    try:
        conn.execute(
            """INSERT INTO probe_results
               (probe_id, probe_name, category, subcategory, objective, provider, model,
                target_archetype, operator_family, posture_key, passed, compliance_score,
                evidence_confidence, verified, replayable, response_snippet, duration_ms, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                outcome.probe_id,
                outcome.probe_name,
                outcome.category,
                outcome.subcategory,
                outcome.objective,
                outcome.provider,
                outcome.model,
                outcome.target_archetype,
                outcome.operator_family,
                outcome.posture_key,
                1 if outcome.passed else 0,
                outcome.compliance_score,
                outcome.evidence_confidence,
                1 if outcome.verified else 0,
                1 if outcome.replayable else 0,
                outcome.response_snippet[:500],
                outcome.duration_ms,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def record_batch(
    outcomes: list[ProbeOutcome],
    db_path: Path | None = None,
) -> int:
    """Record multiple probe outcomes in a single transaction.

    Returns the number of records inserted.
    """
    if not outcomes:
        return 0

    conn = _get_connection(db_path)
    ts = datetime.now(timezone.utc).isoformat()
    try:
        conn.executemany(
            """INSERT INTO probe_results
               (probe_id, probe_name, category, subcategory, objective, provider, model,
                target_archetype, operator_family, posture_key, passed, compliance_score,
                evidence_confidence, verified, replayable, response_snippet, duration_ms, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    o.probe_id, o.probe_name, o.category, o.subcategory, o.objective,
                    o.provider, o.model,
                    o.target_archetype, o.operator_family, o.posture_key,
                    1 if o.passed else 0, o.compliance_score,
                    o.evidence_confidence, 1 if o.verified else 0, 1 if o.replayable else 0,
                    o.response_snippet[:500], o.duration_ms, ts,
                )
                for o in outcomes
            ],
        )
        conn.commit()
        return len(outcomes)
    finally:
        conn.close()


def probe_effectiveness(
    probe_id: str,
    db_path: Path | None = None,
) -> dict[str, Any]:
    """Get effectiveness stats for a specific probe across all models.

    Returns:
        {
            "probe_id": "INJ-001",
            "total_runs": 100,
            "overall_bypass_rate": 0.45,
            "by_model": {
                "openai/gpt-4o": {"runs": 30, "bypasses": 22, "bypass_rate": 0.733},
                "anthropic/claude-3-opus": {"runs": 20, "bypasses": 2, "bypass_rate": 0.10},
            }
        }
    """
    conn = _get_connection(db_path)
    try:
        rows = conn.execute(
            """SELECT provider, model, COUNT(*) as runs,
                      SUM(CASE WHEN passed = 0 THEN 1 ELSE 0 END) as bypasses
               FROM probe_results
               WHERE probe_id = ?
               GROUP BY provider, model
               ORDER BY runs DESC""",
            (probe_id,),
        ).fetchall()

        total_runs = sum(r[2] for r in rows)
        total_bypasses = sum(r[3] for r in rows)

        by_model: dict[str, dict[str, Any]] = {}
        for provider, model, runs, bypasses in rows:
            key = f"{provider}/{model}"
            by_model[key] = {
                "runs": runs,
                "bypasses": bypasses,
                "bypass_rate": round(bypasses / runs, 4) if runs > 0 else 0.0,
            }

        archetype_rows = conn.execute(
            """SELECT target_archetype, COUNT(*) as runs,
                      SUM(CASE WHEN passed = 0 THEN 1 ELSE 0 END) as bypasses
               FROM probe_results
               WHERE probe_id = ? AND target_archetype != ''
               GROUP BY target_archetype
               ORDER BY runs DESC""",
            (probe_id,),
        ).fetchall()
        by_archetype = {
            archetype: {
                "runs": runs,
                "bypasses": bypasses,
                "bypass_rate": round(bypasses / runs, 4) if runs > 0 else 0.0,
            }
            for archetype, runs, bypasses in archetype_rows
        }

        return {
            "probe_id": probe_id,
            "total_runs": total_runs,
            "overall_bypass_rate": round(total_bypasses / total_runs, 4) if total_runs > 0 else 0.0,
            "by_model": by_model,
            "by_archetype": by_archetype,
        }
    finally:
        conn.close()


def model_effectiveness(
    provider: str,
    model: str,
    db_path: Path | None = None,
) -> dict[str, Any]:
    """Get effectiveness stats for a specific model across all probes.

    Returns:
        {
            "provider": "openai",
            "model": "gpt-4o",
            "total_runs": 500,
            "overall_block_rate": 0.67,
            "by_category": {
                "injection": {"runs": 100, "blocked": 55, "block_rate": 0.55},
                "extraction": {"runs": 50, "blocked": 45, "block_rate": 0.90},
            },
            "weakest_probes": [...],
        }
    """
    conn = _get_connection(db_path)
    try:
        # By category
        cat_rows = conn.execute(
            """SELECT category, COUNT(*) as runs,
                      SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as blocked
               FROM probe_results
               WHERE provider = ? AND model = ?
               GROUP BY category
               ORDER BY runs DESC""",
            (provider, model),
        ).fetchall()

        total_runs = sum(r[1] for r in cat_rows)
        total_blocked = sum(r[2] for r in cat_rows)

        by_category: dict[str, dict[str, Any]] = {}
        for category, runs, blocked in cat_rows:
            by_category[category] = {
                "runs": runs,
                "blocked": blocked,
                "block_rate": round(blocked / runs, 4) if runs > 0 else 0.0,
            }

        # Weakest probes (lowest block rate, min 3 runs)
        weak_rows = conn.execute(
            """SELECT probe_id, probe_name, COUNT(*) as runs,
                      SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as blocked
               FROM probe_results
               WHERE provider = ? AND model = ?
               GROUP BY probe_id
               HAVING runs >= 3
               ORDER BY (CAST(blocked AS REAL) / runs) ASC
               LIMIT 10""",
            (provider, model),
        ).fetchall()

        weakest = [
            {
                "probe_id": r[0],
                "probe_name": r[1],
                "runs": r[2],
                "blocked": r[3],
                "block_rate": round(r[3] / r[2], 4) if r[2] > 0 else 0.0,
            }
            for r in weak_rows
        ]

        return {
            "provider": provider,
            "model": model,
            "total_runs": total_runs,
            "overall_block_rate": round(total_blocked / total_runs, 4) if total_runs > 0 else 0.0,
            "by_category": by_category,
            "weakest_probes": weakest,
        }
    finally:
        conn.close()


def category_leaderboard(
    category: str = "",
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """Rank probes by bypass rate across all models.

    Args:
        category: Filter by category. Empty = all categories.

    Returns list sorted by bypass rate (highest first):
        [{"probe_id": "INJ-001", "runs": 50, "bypass_rate": 0.73, ...}, ...]
    """
    conn = _get_connection(db_path)
    try:
        query = """
            SELECT probe_id, probe_name, category, COUNT(*) as runs,
                   SUM(CASE WHEN passed = 0 THEN 1 ELSE 0 END) as bypasses
            FROM probe_results
        """
        params: list[str] = []
        if category:
            query += " WHERE category = ?"
            params.append(category)

        query += """
            GROUP BY probe_id
            HAVING runs >= 2
            ORDER BY (CAST(bypasses AS REAL) / runs) DESC
            LIMIT 50
        """

        rows = conn.execute(query, params).fetchall()
        return [
            {
                "probe_id": r[0],
                "probe_name": r[1],
                "category": r[2],
                "runs": r[3],
                "bypasses": r[4],
                "bypass_rate": round(r[4] / r[3], 4) if r[3] > 0 else 0.0,
            }
            for r in rows
        ]
    finally:
        conn.close()


def stats_summary(db_path: Path | None = None) -> dict[str, Any]:
    """High-level summary of the effectiveness database."""
    conn = _get_connection(db_path)
    try:
        total = conn.execute("SELECT COUNT(*) FROM probe_results").fetchone()[0]
        probes = conn.execute("SELECT COUNT(DISTINCT probe_id) FROM probe_results").fetchone()[0]
        models = conn.execute(
            "SELECT COUNT(DISTINCT provider || '/' || model) FROM probe_results"
        ).fetchone()[0]
        categories = conn.execute(
            "SELECT COUNT(DISTINCT category) FROM probe_results"
        ).fetchone()[0]
        archetypes = conn.execute(
            "SELECT COUNT(DISTINCT target_archetype) FROM probe_results WHERE target_archetype != ''"
        ).fetchone()[0]

        bypasses = conn.execute(
            "SELECT SUM(CASE WHEN passed = 0 THEN 1 ELSE 0 END) FROM probe_results"
        ).fetchone()[0] or 0
        verified_runs = conn.execute(
            "SELECT SUM(CASE WHEN verified = 1 THEN 1 ELSE 0 END) FROM probe_results"
        ).fetchone()[0] or 0

        return {
            "total_records": total,
            "unique_probes": probes,
            "unique_models": models,
            "unique_categories": categories,
            "unique_archetypes": archetypes,
            "verified_runs": verified_runs,
            "overall_bypass_rate": round(bypasses / total, 4) if total > 0 else 0.0,
        }
    finally:
        conn.close()
