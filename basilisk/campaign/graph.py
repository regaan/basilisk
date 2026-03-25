"""Exploit-chain planning for operator-driven AI red-team campaigns."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from basilisk.attacks.base import BasiliskAttack
from basilisk.core.session import ScanSession
from basilisk.policy.models import ExecutionMode


@dataclass
class AttackGraphStage:
    name: str
    objective: str
    module_names: list[str] = field(default_factory=list)
    gating_notes: list[str] = field(default_factory=list)
    confidence_goal: str = "probable"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "objective": self.objective,
            "module_names": self.module_names,
            "gating_notes": self.gating_notes,
            "confidence_goal": self.confidence_goal,
        }


@dataclass
class AttackGraphPlan:
    execution_mode: str
    objective: str
    stages: list[AttackGraphStage] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_mode": self.execution_mode,
            "objective": self.objective,
            "stages": [stage.to_dict() for stage in self.stages],
        }


def build_attack_graph(session: ScanSession, modules: list[BasiliskAttack]) -> AttackGraphPlan:
    """Build a phased exploit graph from campaign intent, profile, and available modules."""

    objective = session.config.campaign.objective.name or "authorized_assessment"
    stages: list[AttackGraphStage] = []
    module_names = [module.name for module in modules]
    focus = set(session.config.campaign.objective.exploit_chain_focus or [])

    def pick(prefixes: list[str]) -> list[str]:
        return [
            name for name in module_names
            if any(name.startswith(prefix) for prefix in prefixes)
            and (not focus or any(name.startswith(prefix) or name in focus for prefix in prefixes))
        ]

    stages.append(
        AttackGraphStage(
            name="recon",
            objective="Profile attack surface, tools, and guardrails before chaining exploitation.",
            module_names=[],
            gating_notes=[
                "Requires approved target scope.",
                "Collect tool/RAG/guardrail evidence before escalation.",
            ],
            confidence_goal="probable",
        )
    )

    injection_like = pick(["injection.", "guardrails.", "multiturn."])
    if injection_like:
        stages.append(
            AttackGraphStage(
                name="initial_access",
                objective="Establish prompt/guardrail influence and prove behavioral drift.",
                module_names=injection_like,
                gating_notes=[
                    "High/critical findings require explicit markers or baseline differential.",
                    "Escalation stages should be skipped if no influence foothold is observed.",
                ],
                confidence_goal="strong",
            )
        )

    discovery = pick(["extraction.", "exfil.tool_schema", "rag.knowledge_enum"])
    if discovery:
        stages.append(
            AttackGraphStage(
                name="discovery",
                objective="Enumerate instructions, tools, schemas, and knowledge-base boundaries.",
                module_names=discovery,
                gating_notes=[
                    "Tool-related chains require discovery proof before tool abuse.",
                    "Knowledge-base chains should only run when RAG is detected.",
                ],
                confidence_goal="strong",
            )
        )

    exploitation = pick(["toolabuse.", "exfil.", "rag.", "dos.", "multimodal"])
    if exploitation:
        stages.append(
            AttackGraphStage(
                name="exploitation",
                objective="Execute the scoped exploit chain against discovered trust boundaries.",
                module_names=exploitation,
                gating_notes=[
                    "Tool abuse requires tool-call proof for high/critical severity.",
                    "RAG poisoning and document injection should be treated as research unless evidence is strong.",
                ],
                confidence_goal="confirmed",
            )
        )

    return AttackGraphPlan(
        execution_mode=session.config.policy.execution_mode.value,
        objective=objective,
        stages=[stage for stage in stages if stage.name == "recon" or stage.module_names],
    )


def stage_modules(plan: AttackGraphPlan, modules: list[BasiliskAttack]) -> list[tuple[AttackGraphStage, list[BasiliskAttack]]]:
    """Resolve graph stage names into actual module instances."""

    mapping = {module.name: module for module in modules}
    staged: list[tuple[AttackGraphStage, list[BasiliskAttack]]] = []
    for stage in plan.stages:
        stage_instances = [mapping[name] for name in stage.module_names if name in mapping]
        staged.append((stage, stage_instances))
    return staged


def should_use_attack_graph(session: ScanSession) -> bool:
    """Whether this campaign should execute in phased exploit-chain mode."""
    return session.config.policy.execution_mode in {
        ExecutionMode.EXPLOIT_CHAIN,
        ExecutionMode.RESEARCH,
    }
