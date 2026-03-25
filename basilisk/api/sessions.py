"""Session history routes."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException

from basilisk.core.database import BasiliskDatabase
from basilisk.core.session import ScanSession
from basilisk.api.shared import (
    SessionClearResponse,
    SessionDetailResponse,
    SessionListResponse,
    active_scans,
    scan_results,
    verify_token,
)

router = APIRouter()
DEFAULT_SESSION_DB = "./basilisk-sessions.db"


@router.get("/api/sessions", response_model=SessionListResponse, dependencies=[Depends(verify_token)])
async def list_sessions():
    sessions = []
    for sid, data in active_scans.items():
        sessions.append({
            "id": sid,
            "status": data["status"],
            "target": data["config"]["target"],
            "started_at": data["started_at"],
            "campaign": data.get("campaign", {}),
            "policy": data.get("policy", {}),
            "resumable": True,
            "current_phase": data.get("session").current_phase if data.get("session") else "",
        })
    for sid, data in scan_results.items():
        sessions.append({
            "id": sid,
            "status": "completed",
            "target": data.get("target", ""),
            "total_findings": data.get("total_findings", 0),
            "campaign": data.get("summary", {}).get("campaign", {}),
            "policy": data.get("summary", {}).get("policy", {}),
            "resumable": False,
            "current_phase": "completed",
        })
    seen = {entry["id"] for entry in sessions}
    db = BasiliskDatabase(DEFAULT_SESSION_DB)
    await db.connect()
    try:
        await db.mark_stale_scan_runtimes_interrupted(set(active_scans))
        runtime_index = {
            row["session_id"]: row
            for row in await db.list_scan_runtimes(limit=200)
        }
        for row in await db.list_sessions(limit=200):
            sid = row["id"]
            if sid in seen:
                continue
            runtime = runtime_index.get(sid, {})
            config = row.get("config", {})
            summary = row.get("summary", {})
            sessions.append({
                "id": sid,
                "status": runtime.get("status", row.get("status", "unknown")),
                "target": row.get("target_url", ""),
                "started_at": row.get("started_at"),
                "total_findings": summary.get("total_findings", 0),
                "campaign": runtime.get("campaign") or config.get("campaign", {}),
                "policy": runtime.get("policy") or summary.get("policy", {}),
                "resumable": runtime.get("resumable", False),
                "current_phase": runtime.get("current_phase", ""),
            })
    finally:
        await db.close()
    return {"sessions": sessions}


@router.get("/api/sessions/{session_id}", response_model=SessionDetailResponse, dependencies=[Depends(verify_token)])
async def get_session(session_id: str):
    if session_id in scan_results:
        return scan_results[session_id]
    if session_id in active_scans:
        scan = active_scans[session_id]
        session = scan["session"]
        return {
            "session_id": session_id,
            "status": scan["status"],
            "findings": [f.to_dict() for f in session.findings],
            "summary": session.summary,
            "profile": session.profile.to_dict(),
            "runtime_state": {
                "current_phase": session.current_phase,
                "progress": session.last_progress,
                "resumable": True,
            },
        }
    db = BasiliskDatabase(DEFAULT_SESSION_DB)
    await db.connect()
    try:
        await db.mark_stale_scan_runtimes_interrupted(set(active_scans))
        runtime = await db.get_scan_runtime(session_id)
    finally:
        await db.close()
    db_path = runtime.get("db_path") if runtime else DEFAULT_SESSION_DB
    try:
        session = await ScanSession.resume(session_id, db_path=db_path)
    except ValueError:
        raise HTTPException(404, {"error": "Session not found"}) from None
    if runtime:
        session.status = runtime.get("status", session.status)
    return {
        "session_id": session_id,
        "status": session.status,
        "findings": [f.to_dict() for f in session.findings],
        "summary": session.summary,
        "profile": session.profile.to_dict(),
        "runtime_state": runtime or {},
    }


@router.post("/api/sessions/clear", response_model=SessionClearResponse, dependencies=[Depends(verify_token)])
async def clear_session_history():
    if active_scans:
        raise HTTPException(409, {"error": "Stop active scans before clearing session history"})

    runtime_db_paths = {
        str(Path(data.get("session_db")).resolve())
        for data in scan_results.values()
        if data.get("session_db")
    }
    runtime_db_paths.add(str(Path(DEFAULT_SESSION_DB).resolve()))

    cleared_sessions = 0
    cleared_runtime_dbs = 0
    for db_path in sorted(path for path in runtime_db_paths if path):
        db = BasiliskDatabase(db_path)
        await db.connect()
        try:
            cleared_sessions += await db.clear_history()
        finally:
            await db.close()
        cleared_runtime_dbs += 1
        if "basilisk-e2e-" in db_path:
            try:
                Path(db_path).unlink(missing_ok=True)
            except OSError:
                pass

    cleared_memory_sessions = len(scan_results)
    scan_results.clear()
    return {
        "cleared_sessions": cleared_sessions,
        "cleared_memory_sessions": cleared_memory_sessions,
        "cleared_runtime_dbs": cleared_runtime_dbs,
    }
