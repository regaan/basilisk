"""Retention helpers for local reports and session data."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

_ARTIFACT_TS_RE = re.compile(r"_(\d{8}_\d{6})(?:\.[^.]+)?$")


def retention_deadline(*, retain_days: int, now: datetime | None = None) -> datetime | None:
    if retain_days <= 0:
        return None
    current = now or datetime.now(timezone.utc)
    return current - timedelta(days=retain_days)


def artifact_timestamp(path: str | Path) -> datetime | None:
    """Prefer embedded UTC timestamps over mutable filesystem mtimes."""
    candidate = Path(path)
    match = _ARTIFACT_TS_RE.search(candidate.name)
    if match:
        try:
            return datetime.strptime(match.group(1), "%Y%m%d_%H%M%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def prune_artifact_dir(path: str | Path, *, retain_days: int, now: datetime | None = None) -> list[str]:
    """Delete local Basilisk artifacts older than the configured retention window."""
    deadline = retention_deadline(retain_days=retain_days, now=now)
    if deadline is None:
        return []
    root = Path(path)
    if not root.exists():
        return []

    removed: list[str] = []
    for child in root.iterdir():
        if not child.is_file():
            continue
        if child.name.startswith(("basilisk_", "audit_")):
            created_at = artifact_timestamp(child)
            observed_time = created_at or datetime.fromtimestamp(child.stat().st_mtime, tz=timezone.utc)
            if observed_time < deadline:
                child.unlink(missing_ok=True)
                removed.append(str(child))
    return removed
