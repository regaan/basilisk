"""
Basilisk Runtime Orchestrator — shared execution engine for scans.

This module exists to keep CLI and desktop on the same scan pipeline
instead of maintaining drift-prone duplicate implementations.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from typing import Any, Awaitable, Callable

from basilisk.attacks.base import BasiliskAttack, resolve_attack_modules
from basilisk.campaign import build_attack_graph, should_use_attack_graph, stage_modules
from basilisk.core.audit import AuditLogger
from basilisk.core.config import BasiliskConfig
from basilisk.core.finding import AttackCategory, Finding, Severity
from basilisk.core.session import ScanSession
from basilisk.policy import ExecutionMode
from basilisk.providers.base import ProviderAdapter
from basilisk.providers.custom_http import CustomHTTPAdapter
from basilisk.providers.litellm_adapter import LiteLLMAdapter
from basilisk.providers.websocket import WebSocketAdapter


PhaseHook = Callable[[str, str], Any | Awaitable[Any]]
ProfileHook = Callable[[str, dict[str, Any]], Any | Awaitable[Any]]
ProgressHook = Callable[[str, str, float], Any | Awaitable[Any]]
FindingHook = Callable[[str, Finding], Any | Awaitable[Any]]
ErrorHook = Callable[[str, str, str], Any | Awaitable[Any]]
EvolutionHook = Callable[[str, dict[str, Any]], Any | Awaitable[Any]]
StopCheck = Callable[[], Any]


@dataclass
class ScanHooks:
    """Optional hooks for UI/CLI/event integration."""

    on_phase: PhaseHook | None = None
    on_profile: ProfileHook | None = None
    on_progress: ProgressHook | None = None
    on_finding: FindingHook | None = None
    on_error: ErrorHook | None = None
    on_evolution_stats: EvolutionHook | None = None


def create_provider(cfg: BasiliskConfig) -> ProviderAdapter:
    """Create the appropriate provider adapter from config."""

    if cfg.target.provider == "custom":
        return CustomHTTPAdapter(
            base_url=cfg.target.url,
            auth_header=cfg.target.auth_header,
            custom_headers=cfg.target.custom_headers,
            timeout=cfg.target.timeout,
        )
    if cfg.target.url.startswith("ws://") or cfg.target.url.startswith("wss://"):
        return WebSocketAdapter(
            ws_url=cfg.target.url,
            auth_header=cfg.target.auth_header,
            custom_headers=cfg.target.custom_headers,
            timeout=cfg.target.timeout,
        )

    api_base = cfg.target.url if cfg.target.provider == "custom" else None
    return LiteLLMAdapter(
        api_key=cfg.target.resolve_api_key(),
        api_base=api_base,
        provider=cfg.target.provider,
        default_model=cfg.target.model,
        timeout=cfg.target.timeout,
        max_retries=cfg.target.max_retries,
        custom_headers=cfg.target.custom_headers or None,
    )


async def execute_scan(
    cfg: BasiliskConfig,
    *,
    session: ScanSession | None = None,
    hooks: ScanHooks | None = None,
    audit: AuditLogger | None = None,
    modules: list[BasiliskAttack] | None = None,
    stop_check: StopCheck | None = None,
) -> ScanSession:
    """Run the shared scan pipeline for CLI and desktop callers."""

    own_session = False
    hooks = hooks or ScanHooks()
    final_status = "completed"
    if session is None:
        session = ScanSession(cfg)
        await session.initialize()
        own_session = True

    prov = create_provider(cfg)
    attacker_prov = None
    try:
        session.record_phase(
            "initializing",
            execution_mode=cfg.policy.execution_mode.value,
            aggression=cfg.policy.aggression,
        )
        if audit:
            audit.log_campaign_context(
                cfg.campaign.to_summary(),
                {
                    "execution_mode": cfg.policy.execution_mode.value,
                    "aggression": cfg.policy.aggression,
                    "evidence_threshold": cfg.policy.evidence_threshold.value,
                    "dry_run": cfg.policy.dry_run,
                    "allow_modules": cfg.policy.allow_modules,
                    "deny_modules": cfg.policy.deny_modules,
                    "request_budget": cfg.policy.request_budget,
                },
            )

        _check_continue(stop_check)
        healthy, error_msg = await prov.health_check()
        if not healthy:
            raise RuntimeError(f"Provider health check failed: {error_msg}")

        if cfg.skip_recon or cfg.mode.value == "quick":
            session.record_phase("recon_skipped")
            await _emit_phase(hooks, session.id, "recon_skipped")
        else:
            session.record_phase("recon_started")
            await _emit_phase(hooks, session.id, "recon")
            await run_recon_phase(prov, session, hooks=hooks, stop_check=stop_check, audit=audit)

        if cfg.policy.execution_mode == ExecutionMode.RECON or cfg.policy.dry_run:
            session.record_phase(
                "planning_complete",
                dry_run=cfg.policy.dry_run,
                selected_modules=_module_names(resolve_attack_modules(
                    selected=cfg.modules,
                    include_research=cfg.include_research_modules,
                )),
            )
            if audit:
                audit.log_policy_event("scan_planned_only", {
                    "dry_run": cfg.policy.dry_run,
                    "execution_mode": cfg.policy.execution_mode.value,
                })
            return session

        _check_continue(stop_check)
        session.record_phase("attacks_started")
        await _emit_phase(hooks, session.id, "attacking")
        selected_modules = modules if modules is not None else resolve_attack_modules(
            selected=cfg.modules,
            include_research=cfg.include_research_modules,
        )
        selected_modules = [
            module for module in selected_modules
            if cfg.policy.allows_module(module.name)
        ]
        selected_modules = _prioritize_modules(selected_modules, session)
        if should_use_attack_graph(session):
            graph = build_attack_graph(session, selected_modules)
            session.remember("attack_graph", graph.to_dict())
            session.record_phase("attack_graph_planned", graph=graph.to_dict())
            if audit:
                audit.log_policy_event("attack_graph_planned", graph.to_dict())
            await _run_attack_graph(
                prov,
                session,
                graph=graph,
                modules=selected_modules,
                hooks=hooks,
                audit=audit,
                stop_check=stop_check,
            )
        else:
            session.record_phase("module_plan", modules=_module_names(selected_modules))
            if audit:
                audit.log_policy_event("module_selection", {
                    "selected_modules": _module_names(selected_modules),
                    "execution_mode": cfg.policy.execution_mode.value,
                })
            await _run_attack_phase(
                prov,
                session,
                selected_modules,
                hooks=hooks,
                audit=audit,
                stop_check=stop_check,
            )

        _check_continue(stop_check)
        if cfg.evolution.enabled and cfg.mode.value in ("standard", "deep", "chaos") and cfg.policy.should_run_evolution():
            session.record_phase("evolution_started")
            await _emit_phase(hooks, session.id, "evolving")
            attacker_prov = await _run_evolution_phase(
                prov,
                session,
                cfg,
                hooks=hooks,
                stop_check=stop_check,
            )

        return session
    except asyncio.CancelledError:
        final_status = "stopped"
        raise
    except Exception:
        final_status = "error"
        raise
    finally:
        if attacker_prov:
            await attacker_prov.close()
        await prov.close()
        if own_session and session.finished_at is None:
            await session.close(final_status)


async def run_recon_phase(
    prov: ProviderAdapter,
    session: ScanSession,
    *,
    hooks: ScanHooks | None = None,
    stop_check: StopCheck | None = None,
    audit: AuditLogger | None = None,
) -> None:
    """Execute filtered recon modules in parallel where possible."""

    from basilisk.recon.context import measure_context_window
    from basilisk.recon.fingerprint import fingerprint_model
    from basilisk.recon.guardrails import profile_guardrails
    from basilisk.recon.rag import detect_rag
    from basilisk.recon.tools import discover_tools

    hooks = hooks or ScanHooks()
    requested = session.config.recon_modules
    available_steps = {
        "fingerprint": ("Model Fingerprinting", fingerprint_model),
        "context": ("Context Window Detection", measure_context_window),
        "tools": ("Tool Discovery", discover_tools),
        "guardrails": ("Guardrail Profiling", profile_guardrails),
        "rag": ("RAG Detection", detect_rag),
    }

    if not requested:
        active_steps = dict(available_steps)
    else:
        active_steps = {key: value for key, value in available_steps.items() if key in requested}

    if "fingerprint" in active_steps:
        _check_continue(stop_check)
        name, func = active_steps.pop("fingerprint")
        await func(prov, session.profile)
        session.sync_profile_memory()
        if audit:
            audit.log_recon_result("fingerprint", session.profile.to_dict())
        await _emit_progress(hooks, session.id, name, 1.0 if not active_steps else 0.2)

    if active_steps:
        sem = asyncio.Semaphore(3)
        total = len(active_steps)
        completed = 0

        async def run_step(key: str, name: str, func) -> None:
            nonlocal completed
            async with sem:
                _check_continue(stop_check)
                await func(prov, session.profile)
                completed += 1
                session.sync_profile_memory()
                if audit:
                    audit.log_recon_result(key, session.profile.to_dict())
                await _emit_progress(hooks, session.id, name, completed / total)

        await asyncio.gather(
            *(run_step(key, name, func) for key, (name, func) in active_steps.items())
        )

    await _emit_profile(hooks, session.id, session.profile.to_dict())


async def _run_attack_phase(
    prov: ProviderAdapter,
    session: ScanSession,
    modules: list[BasiliskAttack],
    *,
    hooks: ScanHooks,
    audit: AuditLogger | None = None,
    stop_check: StopCheck | None = None,
) -> None:
    if not modules:
        return

    sem = asyncio.Semaphore(max(1, session.config.policy.max_concurrency))
    completed = 0
    request_budget = session.config.policy.request_budget

    async def run_module(mod: BasiliskAttack) -> None:
        nonlocal completed, request_budget
        async with sem:
            _check_continue(stop_check)
            if request_budget == 0 and session.config.policy.request_budget > 0:
                await _emit_error(hooks, session.id, mod.name, "Request budget exhausted before module execution")
                return
            if request_budget > 0:
                request_budget -= 1
            await _emit_progress(hooks, session.id, f"Running {mod.name}...", completed / len(modules))
            try:
                session.record_phase("module_started", module=mod.name)
                session.remember("completed_modules", mod.name)
                if session.config.policy.rate_limit_delay > 0:
                    await asyncio.sleep(session.config.policy.rate_limit_delay)
                module_findings = await mod.execute(prov, session, session.profile)
                for finding in module_findings:
                    if audit:
                        audit.log_finding(finding.to_dict())
                    await _emit_finding(hooks, session.id, finding)
                session.record_phase("module_completed", module=mod.name, findings=len(module_findings))
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                await session.add_error(mod.name, str(exc))
                if audit:
                    audit.log_error(mod.name, str(exc))
                await _emit_error(hooks, session.id, mod.name, str(exc))
            finally:
                completed += 1
                await _emit_progress(hooks, session.id, mod.name, completed / len(modules))

    await asyncio.gather(*(run_module(mod) for mod in modules))


async def _run_attack_graph(
    prov: ProviderAdapter,
    session: ScanSession,
    *,
    graph,
    modules: list[BasiliskAttack],
    hooks: ScanHooks,
    audit: AuditLogger | None = None,
    stop_check: StopCheck | None = None,
) -> None:
    """Execute exploit-chain stages in sequence while preserving module concurrency within a stage."""

    staged = stage_modules(graph, modules)
    for stage, stage_instances in staged:
        _check_continue(stop_check)
        session.record_phase("chain_stage_started", stage=stage.to_dict())
        if audit:
            audit.log_policy_event("chain_stage_started", stage.to_dict())
        if stage.name != "recon":
            await _emit_phase(hooks, session.id, f"chain:{stage.name}")
        if stage_instances:
            await _run_attack_phase(
                prov,
                session,
                stage_instances,
                hooks=hooks,
                audit=audit,
                stop_check=stop_check,
            )
        session.record_phase(
            "chain_stage_completed",
            stage=stage.name,
            executed_modules=[module.name for module in stage_instances],
        )
        if audit:
            audit.log_policy_event(
                "chain_stage_completed",
                {
                    "stage": stage.name,
                    "executed_modules": [module.name for module in stage_instances],
                },
            )


async def _run_evolution_phase(
    prov: ProviderAdapter,
    session: ScanSession,
    cfg: BasiliskConfig,
    *,
    hooks: ScanHooks,
    stop_check: StopCheck | None = None,
) -> ProviderAdapter | None:
    from basilisk.evolution.engine import EvolutionEngine
    from basilisk.evolution.fitness import attack_goal_from_payloads
    from basilisk.core.refusal import classify_refusal_style

    seed_payloads = [finding.payload for finding in session.findings if finding.payload][:50]
    if not seed_payloads:
        from basilisk.attacks.injection.direct import PAYLOADS

        seed_payloads = PAYLOADS

    goal = attack_goal_from_payloads(
        seed_payloads,
        description="Bypass AI safety guardrails with probe-aligned proof",
        fallback_category="injection",
    )
    refusal_patterns = session.attack_memory.get("refusal_patterns", [])
    dominant_refusal_style = (
        max(set(refusal_patterns), key=refusal_patterns.count)
        if refusal_patterns else "unknown"
    )
    target_context = {
        "provider": cfg.target.provider,
        "model": cfg.target.model,
        "guardrail_level": session.attack_memory.get("guardrail_level", ""),
        "tool_surface": bool(session.attack_memory.get("discovered_tools")),
        "rag_detected": bool(session.attack_memory.get("rag_detected", False)),
        "dominant_refusal_style": dominant_refusal_style,
        "successful_framings": list(session.attack_memory.get("successful_framing_styles", [])),
        "best_probe_families": list(session.attack_memory.get("best_probe_families", [])),
    }

    async def on_generation(stats: dict[str, Any]) -> None:
        _check_continue(stop_check)
        await _emit_evolution_stats(hooks, session.id, stats)

    async def on_breakthrough(individual, generation: int) -> None:
        _check_continue(stop_check)
        finding = Finding(
            title=f"Evolution Breakthrough — Gen {generation}",
            severity=Severity.HIGH,
            category=AttackCategory.PROMPT_INJECTION,
            attack_module="basilisk.evolution",
            payload=individual.payload,
            response=individual.response[:500] if individual.response else "",
            evolution_generation=generation,
            confidence=individual.fitness,
        )
        await session.add_finding(finding)
        await _emit_finding(hooks, session.id, finding)

    attacker_prov: ProviderAdapter | None = None
    if cfg.evolution.attacker_provider:
        attacker_target = replace(
            cfg.target,
            provider=cfg.evolution.attacker_provider,
            model=cfg.evolution.attacker_model,
            api_key=cfg.evolution.attacker_api_key or cfg.target.api_key,
        )
        attacker_cfg = replace(cfg, target=attacker_target)
        attacker_prov = create_provider(attacker_cfg)

    engine = EvolutionEngine(
        prov,
        cfg.evolution,
        on_generation=on_generation,
        on_breakthrough=on_breakthrough,
        attacker_provider=attacker_prov,
        target_context=target_context,
    )
    result = await engine.evolve(seed_payloads, goal)

    session.remember("operator_learning", result.operator_learning)
    if result.best_individual and result.best_individual.behavioral_profile:
        refusal_style = result.best_individual.behavioral_profile.get("refusal_style")
        if refusal_style:
            session.remember("refusal_patterns", refusal_style)
    if result.best_individual and result.best_individual.operator_used:
        session.remember("successful_framing_styles", result.best_individual.operator_used.split(":", 1)[0])
    if result.best_individual and result.best_individual.selection_context:
        session.remember("behavioral_notes", {
            "type": "evolution_context",
            "context": result.best_individual.selection_context,
            "fitness": result.best_individual.fitness,
        })
    if goal.subcategories:
        session.remember("best_probe_families", goal.subcategories[:3])

    weakest_operator_families: list[str] = []
    context_data = result.operator_learning.get("contexts", {})
    current_context = result.operator_learning.get("current_context")
    if current_context and current_context in context_data:
        weakest_operator_families = [
            entry["operator"]
            for entry in sorted(context_data[current_context], key=lambda item: item["mean_reward"])[:2]
        ]
    for family in weakest_operator_families:
        session.remember("failed_operator_families", family)

    for finding in session.findings[-5:]:
        if finding.response:
            session.remember("refusal_patterns", classify_refusal_style(finding.response))
    return attacker_prov


async def _emit_phase(hooks: ScanHooks, session_id: str, phase: str) -> None:
    await _maybe_call(hooks.on_phase, session_id, phase)


async def _emit_profile(hooks: ScanHooks, session_id: str, profile: dict[str, Any]) -> None:
    await _maybe_call(hooks.on_profile, session_id, profile)


async def _emit_progress(hooks: ScanHooks, session_id: str, module: str, progress: float) -> None:
    await _maybe_call(hooks.on_progress, session_id, module, progress)


async def _emit_finding(hooks: ScanHooks, session_id: str, finding: Finding) -> None:
    await _maybe_call(hooks.on_finding, session_id, finding)


async def _emit_error(hooks: ScanHooks, session_id: str, module: str, error: str) -> None:
    await _maybe_call(hooks.on_error, session_id, module, error)


async def _emit_evolution_stats(hooks: ScanHooks, session_id: str, stats: dict[str, Any]) -> None:
    await _maybe_call(hooks.on_evolution_stats, session_id, stats)


async def _maybe_call(callback: Callable[..., Any] | None, *args: Any) -> None:
    if callback is None:
        return
    result = callback(*args)
    if hasattr(result, "__await__"):
        await result


def _check_continue(stop_check: StopCheck | None) -> None:
    if stop_check is None:
        return
    stop_check()


def _module_names(modules: list[BasiliskAttack]) -> list[str]:
    return [module.name for module in modules]


def _prioritize_modules(modules: list[BasiliskAttack], session: ScanSession) -> list[BasiliskAttack]:
    mode = session.config.policy.execution_mode
    profile = session.profile

    def score(module: BasiliskAttack) -> tuple[int, str]:
        value = 0
        name = module.name

        if mode == ExecutionMode.EXPLOIT_CHAIN:
            if "toolabuse" in name:
                value += 40
            if "multiturn" in name:
                value += 30
            if "rag" in name or "exfil" in name:
                value += 25
            if "injection" in name:
                value += 15
        elif mode == ExecutionMode.VALIDATE:
            if "dos" in name:
                value -= 20
            if "guardrails" in name or "injection" in name:
                value += 10
        elif mode == ExecutionMode.RESEARCH:
            if module.trust_tier == "research":
                value += 15

        if getattr(profile, "detected_tools", None):
            if "toolabuse" in name:
                value += 20
            if "exfil.tool_schema" in name:
                value += 10
        else:
            if "toolabuse" in name:
                value -= 10

        if getattr(profile, "rag_detected", False):
            if "rag." in name or "exfil.rag" in name:
                value += 20

        if getattr(profile, "supports_code_execution", False) and "command_injection" in name:
            value += 10

        return (-value, name)

    return sorted(modules, key=score)
