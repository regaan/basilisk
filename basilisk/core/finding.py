"""
Basilisk Finding — represents a discovered vulnerability in an AI system.

Each finding has a unique ID (BSLK-YYYY-XXXX), severity classification,
full attack conversation replay, and remediation guidance mapped to
OWASP LLM Top 10.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from functools import lru_cache
from typing import Any

from basilisk.core.evidence import EvidenceBundle


class Severity(str, Enum):
    """Vulnerability severity classification aligned with CVSS."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def color(self) -> str:
        return {
            Severity.CRITICAL: "red",
            Severity.HIGH: "orange1",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }[self]

    @property
    def icon(self) -> str:
        return {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "⚪",
        }[self]

    @property
    def numeric(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]


class AttackCategory(str, Enum):
    """Attack classification mapped to OWASP LLM Top 10."""
    PROMPT_INJECTION = "prompt_injection"          # LLM01
    INSECURE_OUTPUT = "insecure_output"            # LLM02
    DATA_POISONING = "data_poisoning"              # LLM03
    DENIAL_OF_SERVICE = "denial_of_service"        # LLM04
    SUPPLY_CHAIN = "supply_chain"                  # LLM05
    SENSITIVE_DISCLOSURE = "sensitive_disclosure"   # LLM06
    INSECURE_PLUGIN = "insecure_plugin"            # LLM07
    EXCESSIVE_AGENCY = "excessive_agency"           # LLM08
    OVERRELIANCE = "overreliance"                   # LLM09
    MODEL_THEFT = "model_theft"                     # LLM10

    @property
    def owasp_id(self) -> str:
        mapping = {
            AttackCategory.PROMPT_INJECTION: "LLM01",
            AttackCategory.INSECURE_OUTPUT: "LLM02",
            AttackCategory.DATA_POISONING: "LLM03",
            AttackCategory.DENIAL_OF_SERVICE: "LLM04",
            AttackCategory.SUPPLY_CHAIN: "LLM05",
            AttackCategory.SENSITIVE_DISCLOSURE: "LLM06",
            AttackCategory.INSECURE_PLUGIN: "LLM07",
            AttackCategory.EXCESSIVE_AGENCY: "LLM08",
            AttackCategory.OVERRELIANCE: "LLM09",
            AttackCategory.MODEL_THEFT: "LLM10",
        }
        return mapping[self]


@dataclass
class Message:
    """Single message in a conversation."""
    role: str           # "user", "assistant", "system", "tool"
    content: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }

    def sanitized_dict(self, max_chars: int = 160) -> dict[str, Any]:
        content = self.content[:max_chars]
        if len(self.content) > max_chars:
            content += "..."
        return {
            "role": self.role,
            "content": content,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Message:
        return cls(
            role=data["role"],
            content=data["content"],
            timestamp=datetime.fromisoformat(data.get("timestamp", datetime.now(timezone.utc).isoformat())),
            metadata=data.get("metadata", {}),
        )


@dataclass
class Finding:
    """
    Represents a confirmed vulnerability discovered during a Basilisk scan.

    Each finding carries the complete evidence chain: the payload that triggered
    the vulnerability, the model's response, and the full conversation history
    for replay and verification.
    """
    id: str = field(default_factory=lambda: f"BSLK-{datetime.now(timezone.utc).strftime('%Y')}-{uuid.uuid4().hex[:6].upper()}")
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    category: AttackCategory = AttackCategory.PROMPT_INJECTION
    attack_module: str = ""
    payload: str = ""
    response: str = ""
    conversation: list[Message] = field(default_factory=list)
    evolution_generation: int | None = None
    confidence: float = 0.0
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)
    evidence: EvidenceBundle | None = None

    def to_dict(self) -> dict[str, Any]:
        module_meta = _module_metadata(self.attack_module, self.metadata)
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "owasp_id": self.category.owasp_id,
            "attack_module": self.attack_module,
            "payload": self.payload,
            "response": self.response,
            "conversation": [m.to_dict() for m in self.conversation],
            "evolution_generation": self.evolution_generation,
            "confidence": self.confidence,
            "remediation": self.remediation,
            "references": self.references,
            "tags": self.tags,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "module_trust_tier": module_meta["trust_tier"],
            "module_success_criteria": module_meta["success_criteria"],
            "module_evidence_requirements": module_meta["evidence_requirements"],
            "policy_downgraded": bool(self.metadata.get("policy_downgraded", False)),
        }

    def sanitized_dict(
        self,
        *,
        include_payload: bool = False,
        include_response: bool = False,
        include_conversation: bool = False,
        payload_preview: int = 160,
        response_preview: int = 240,
    ) -> dict[str, Any]:
        data = self.to_dict()
        data["payload"] = _sanitize_artifact(self.payload, include_payload, payload_preview)
        data["response"] = _sanitize_artifact(self.response, include_response, response_preview)
        data["metadata"] = _sanitize_nested_value(
            self.metadata,
            include_raw=include_payload or include_response or include_conversation,
            preview_chars=max(payload_preview, response_preview),
        )
        data["conversation"] = (
            [m.to_dict() for m in self.conversation]
            if include_conversation
            else []
        )
        data["evidence"] = (
            self.evidence.sanitized_dict(
                include_raw=include_payload or include_response or include_conversation,
            )
            if self.evidence
            else None
        )
        if not include_conversation and self.conversation:
            data["metadata"] = {
                **self.metadata,
                "conversation_redacted": True,
                "conversation_message_count": len(self.conversation),
            }
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            id=data["id"],
            title=data["title"],
            description=data.get("description", ""),
            severity=Severity(data["severity"]),
            category=AttackCategory(data["category"]),
            attack_module=data["attack_module"],
            payload=data["payload"],
            response=data["response"],
            conversation=[Message.from_dict(m) for m in data.get("conversation", [])],
            evolution_generation=data.get("evolution_generation"),
            confidence=data.get("confidence", 0.0),
            remediation=data.get("remediation", ""),
            references=data.get("references", []),
            tags=data.get("tags", []),
            timestamp=datetime.fromisoformat(data.get("timestamp", datetime.now(timezone.utc).isoformat())),
            metadata=data.get("metadata", {}),
            evidence=EvidenceBundle.from_dict(data["evidence"]) if data.get("evidence") else None,
        )

    @property
    def severity_icon(self) -> str:
        return self.severity.icon

    def __str__(self) -> str:
        return f"[{self.severity.value.upper()}] {self.id}: {self.title}"


def _sanitize_artifact(value: str, include_raw: bool, preview_chars: int) -> str:
    if not value:
        return ""
    if include_raw:
        return value
    preview = value[:preview_chars]
    if len(value) > preview_chars:
        preview += "..."
    return f"[redacted] {preview}"


def _sanitize_nested_value(value: Any, *, include_raw: bool, preview_chars: int) -> Any:
    if isinstance(value, str):
        return _sanitize_artifact(value, include_raw, preview_chars)
    if isinstance(value, dict):
        return {
            key: _sanitize_nested_value(val, include_raw=include_raw, preview_chars=preview_chars)
            for key, val in value.items()
        }
    if isinstance(value, list):
        return [
            _sanitize_nested_value(item, include_raw=include_raw, preview_chars=preview_chars)
            for item in value
        ]
    return value


@lru_cache(maxsize=256)
def _descriptor_lookup(attack_module: str) -> tuple[str, list[str], list[str]]:
    if not attack_module:
        return ("beta", [], [])
    try:
        from basilisk.attacks.base import describe_attack_module, get_all_attack_modules

        candidates = (
            attack_module.removeprefix("basilisk.attacks."),
            attack_module,
        )
        for module in get_all_attack_modules():
            if module.name in candidates or f"basilisk.attacks.{module.name}" in candidates:
                descriptor = describe_attack_module(module)
                return (
                    descriptor.trust_tier,
                    descriptor.success_criteria,
                    descriptor.evidence_requirements,
                )
    except Exception:
        pass
    return ("beta", [], [])


def _module_metadata(attack_module: str, metadata: dict[str, Any]) -> dict[str, Any]:
    trust_tier, success_criteria, evidence_requirements = _descriptor_lookup(attack_module)
    return {
        "trust_tier": metadata.get("module_trust_tier", trust_tier),
        "success_criteria": metadata.get("module_success_criteria", success_criteria),
        "evidence_requirements": metadata.get("module_evidence_requirements", evidence_requirements),
    }
