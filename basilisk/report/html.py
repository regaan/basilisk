"""
Basilisk HTML Report Generator — Jinja2-based vulnerability reports.

Uses the shared Jinja templates under `report/templates/` so HTML rendering
stays autoescaped, consistent with the rest of the report stack, and easy to
evolve without manual string concatenation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from basilisk import __version__
from basilisk.core.finding import Finding
from basilisk.core.session import ScanSession

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(enabled_extensions=("html", "xml", "j2"), default=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def generate_html(
    session: ScanSession,
    path: Path,
    *,
    include_raw_content: bool = False,
    include_conversations: bool = False,
) -> None:
    """Generate a styled HTML report from scan findings."""
    template = _environment().get_template("report.html.j2")
    summary = session.summary
    generated_at = datetime.now(timezone.utc)

    context = {
        "session_id": session.id,
        "generated_at": generated_at.strftime("%Y-%m-%d %H:%M UTC"),
        "basilisk_version": __version__,
        "target": session.config.target.url,
        "summary": summary,
        "severity_data": _severity_data(summary),
        "findings": [
            _finding_context(
                finding,
                include_raw_content=include_raw_content,
                include_conversations=include_conversations,
            )
            for finding in sorted(session.findings, key=lambda item: item.severity.numeric, reverse=True)
        ],
        "profile": _profile_context(session),
        "campaign": session.config.campaign.to_summary(),
        "policy": {
            "execution_mode": session.config.policy.execution_mode.value,
            "evidence_threshold": session.config.policy.evidence_threshold.value,
            "raw_evidence_mode": session.config.policy.raw_evidence_mode.value,
            "retain_days": session.config.policy.retain_days,
        },
    }
    path.write_text(template.render(**context), encoding="utf-8")


def _severity_data(summary: dict[str, Any]) -> list[tuple[str, int, str]]:
    return [
        ("CRITICAL", summary["severity_counts"].get("critical", 0), "#dc2626"),
        ("HIGH", summary["severity_counts"].get("high", 0), "#ea580c"),
        ("MEDIUM", summary["severity_counts"].get("medium", 0), "#ca8a04"),
        ("LOW", summary["severity_counts"].get("low", 0), "#2563eb"),
        ("INFO", summary["severity_counts"].get("info", 0), "#6b7280"),
    ]


def _profile_context(session: ScanSession) -> dict[str, Any]:
    profile = session.profile
    provider = getattr(profile.provider, "value", profile.provider)
    guardrail_level = getattr(getattr(profile, "guardrails", None), "level", "")
    if hasattr(guardrail_level, "value"):
        guardrail_level = guardrail_level.value
    return {
        "mode": session.config.mode.value.upper(),
        "provider": provider or "unknown",
        "model": profile.detected_model or "unknown",
        "attack_surface_score": round(profile.attack_surface_score, 1),
        "context_window": profile.context_window,
        "guardrails": guardrail_level or "unknown",
        "rag_detected": bool(profile.rag_detected),
        "supports_code_execution": bool(profile.supports_code_execution),
        "detected_tools": [
            {
                "name": tool.name,
                "description": tool.description,
                "risk_level": tool.risk_level,
            }
            for tool in getattr(profile, "detected_tools", []) or []
        ],
    }


def _finding_context(
    finding: Finding,
    *,
    include_raw_content: bool,
    include_conversations: bool,
) -> dict[str, Any]:
    finding_data = finding.to_dict()
    evidence = finding.evidence
    evidence_view = None
    if evidence:
        evidence_view = {
            "verdict": evidence.verdict.value.upper(),
            "confidence": f"{evidence.confidence_score:.0%}",
            "confidence_basis": evidence.confidence_basis,
            "signals": [signal.to_dict() for signal in evidence.signals],
            "replay_steps": list(evidence.replay_steps),
            "notes": list(evidence.notes),
        }

    return {
        "id": finding.id,
        "severity": finding.severity.value.upper(),
        "color": _severity_color(finding.severity.value),
        "owasp": finding.category.owasp_id,
        "title": finding.title,
        "description": finding.description,
        "module": finding.attack_module,
        "confidence": f"{finding.confidence:.0%}",
        "module_trust_tier": finding_data["module_trust_tier"],
        "module_success_criteria": finding_data["module_success_criteria"],
        "module_evidence_requirements": finding_data["module_evidence_requirements"],
        "policy_downgraded": finding_data["policy_downgraded"],
        "original_severity": finding.metadata.get("original_severity", ""),
        "missing_evidence_requirements": finding.metadata.get("missing_evidence_requirements", []),
        "payload": finding.payload if include_raw_content else "[redacted in report output]",
        "response": finding.response[:1000] if include_raw_content else "[redacted in report output]",
        "remediation": finding.remediation,
        "evolution_generation": finding.evolution_generation,
        "conversation": [
            {"role": msg.role, "content": msg.content[:500]}
            for msg in finding.conversation
        ] if include_conversations and finding.conversation else [],
        "evidence": evidence_view,
    }


def _severity_color(severity: str) -> str:
    return {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#ca8a04",
        "low": "#2563eb",
        "info": "#6b7280",
    }.get(severity, "#6b7280")
