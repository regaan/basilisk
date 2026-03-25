"""
Tests for the shared runtime/orchestration foundation.
"""

from __future__ import annotations

from basilisk.campaign import build_attack_graph, should_use_attack_graph
from basilisk.attacks.base import describe_attack_module, resolve_attack_modules
from basilisk.attacks.injection.direct import DirectInjection
from basilisk.core.config import BasiliskConfig
from basilisk.core.session import ScanSession


class TestAttackCatalog:
    def test_resolve_attack_modules_excludes_research_by_default(self):
        modules = resolve_attack_modules()
        assert modules
        assert all(module.trust_tier != "research" for module in modules)

    def test_resolve_attack_modules_allows_explicit_research_selection(self):
        modules = resolve_attack_modules(selected=["multimodal"])
        assert any(module.name.startswith("multimodal") for module in modules)

    def test_descriptor_exposes_success_criteria(self):
        descriptor = describe_attack_module(DirectInjection())
        assert descriptor.trust_tier in {"production", "beta", "research"}
        assert descriptor.success_criteria
        assert descriptor.evidence_requirements


class TestAttackGraph:
    def test_build_attack_graph_for_exploit_chain(self):
        cfg = BasiliskConfig.from_dict({
            "target": {"url": "https://example.test", "provider": "custom"},
            "policy": {"execution_mode": "exploit_chain"},
            "campaign": {"objective": {"name": "tool_chain_validation"}},
        })
        session = ScanSession(cfg)
        modules = resolve_attack_modules(
            selected=["injection.direct", "toolabuse.ssrf", "exfil.tool_schema"],
            include_research=False,
        )
        graph = build_attack_graph(session, modules)
        assert graph.execution_mode == "exploit_chain"
        assert graph.stages
        assert any(stage.name == "initial_access" for stage in graph.stages)
        assert any(stage.name == "exploitation" for stage in graph.stages)

    def test_should_use_attack_graph_for_research(self):
        cfg = BasiliskConfig.from_dict({
            "target": {"url": "https://example.test", "provider": "custom"},
            "policy": {"execution_mode": "research"},
        })
        session = ScanSession(cfg)
        assert should_use_attack_graph(session) is True
