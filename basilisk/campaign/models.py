"""Campaign metadata for scoped, operator-driven engagements."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CampaignObjective:
    """Operator-stated goal for the engagement."""

    name: str = "authorized_assessment"
    hypothesis: str = ""
    success_definition: str = ""
    exploit_chain_focus: list[str] = field(default_factory=list)


@dataclass
class CampaignAuthorization:
    """Who approved the work, for what scope, and under which ticket."""

    operator: str = ""
    approver: str = ""
    ticket_id: str = ""
    target_owner: str = ""
    justification: str = ""
    scope_targets: list[str] = field(default_factory=list)
    approved: bool = False
    authorized_from: str = ""
    authorized_until: str = ""
    signed_scope_hash: str = ""


@dataclass
class CampaignConfig:
    """Top-level campaign envelope."""

    name: str = ""
    campaign_id: str = ""
    tags: list[str] = field(default_factory=list)
    objective: CampaignObjective = field(default_factory=CampaignObjective)
    authorization: CampaignAuthorization = field(default_factory=CampaignAuthorization)

    def to_summary(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "campaign_id": self.campaign_id,
            "tags": self.tags,
            "objective": {
                "name": self.objective.name,
                "hypothesis": self.objective.hypothesis,
                "success_definition": self.objective.success_definition,
                "exploit_chain_focus": self.objective.exploit_chain_focus,
            },
            "authorization": {
                "operator": self.authorization.operator,
                "approver": self.authorization.approver,
                "ticket_id": self.authorization.ticket_id,
                "target_owner": self.authorization.target_owner,
                "scope_targets": self.authorization.scope_targets,
                "approved": self.authorization.approved,
                "authorized_from": self.authorization.authorized_from,
                "authorized_until": self.authorization.authorized_until,
                "signed_scope_hash": self.authorization.signed_scope_hash,
            },
        }
