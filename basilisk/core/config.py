"""
Basilisk Configuration — YAML-based configuration loading and validation.

Supports target definitions, provider credentials, scan mode settings,
evolution parameters, and output preferences.
"""

from __future__ import annotations

import os
import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import logging
import yaml

from basilisk.campaign import CampaignConfig
from basilisk.policy.models import RawEvidenceMode, ScanPolicy

logger = logging.getLogger("basilisk.config")


class ScanMode(str, Enum):
    """Scan aggressiveness modes."""
    QUICK = "quick"         # Top 50 payloads, no evolution
    STANDARD = "standard"   # Full payloads, 3 generations
    DEEP = "deep"           # Full payloads, 10+ generations, multi-turn
    STEALTH = "stealth"     # Rate-limited, human-like timing
    CHAOS = "chaos"         # Everything parallel, max evolution


@dataclass
class TargetConfig:
    """Configuration for a single scan target."""
    url: str = ""
    provider: str = "openai"
    model: str = ""
    api_key: str = ""
    auth_header: str = ""
    custom_headers: dict[str, str] = field(default_factory=dict)
    system_prompt: str = ""
    timeout: float = 30.0
    max_retries: int = 3

    def resolve_api_key(self) -> str:
        """Resolve API key from config, environment variables, or files."""
        key = self.api_key
        
        # 1. Handle @filename syntax
        if key.startswith("@"):
            raw_path = key[1:]
            path = Path(raw_path).expanduser().resolve()
            
            
            safe_roots = [
                Path("~/.basilisk").expanduser().resolve(),
                Path.cwd().resolve()
            ]
            
            is_safe = any(path.is_relative_to(root) for root in safe_roots)
            allow_unsafe = os.environ.get("BASILISK_ALLOW_UNSAFE_CONFIG_READ", "").lower() == "true"
            
            if not is_safe and not allow_unsafe:
                logger.error(
                    "SECURITY ALERT: @filename path '%s' is outside permitted directories. "
                    "Only files in ~/.basilisk/ or CWD are allowed for enterprise security. "
                    "Use BASILISK_ALLOW_UNSAFE_CONFIG_READ=true to override (NOT RECOMMENDED).",
                    raw_path
                )
                return ""
                
            if path.exists():
                return path.read_text("utf-8").strip()
            # If specified as file but not found, return empty (validation will catch it)
            return ""

        # 2. Use explicit key if provided
        if key:
            return key

        # 3. Fallback to environment variables
        env_mapping = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "google": "GOOGLE_API_KEY",
            "azure": "AZURE_API_KEY",
            "xai": "XAI_API_KEY",
            'groq': 'GROQ_API_KEY',
        }
        env_var = env_mapping.get(self.provider, "BASILISK_API_KEY")
        return os.environ.get(env_var, "")


@dataclass
class EvolutionConfig:
    """Configuration for the genetic mutation engine."""
    enabled: bool = True
    population_size: int = 100
    generations: int = 5
    mutation_rate: float = 0.3
    crossover_rate: float = 0.5
    elite_count: int = 10
    fitness_threshold: float = 0.9
    tournament_size: int = 5
    stagnation_limit: int = 3       # Stop if no improvement for N generations
    attacker_provider: str = ""     # Optional: use a different provider for mutations
    attacker_model: str = ""        # Optional: model for mutations (e.g., gpt-4o)
    attacker_api_key: str = ""
    max_concurrent: int = 5
    temperature: float = 0.7
    exit_on_first: bool = False        # Stop after first breakthrough
    enable_cache: bool = True          # Cache payload evaluations
    cache_persist_path: str = ""       # Path to persist cache (empty = no persist)
    diversity_mode: str = "novelty"    # "off", "novelty", "niche"
    intent_weight: float = 0.15        # 0 = disabled, 0.15 = default
    operator_bandit: bool = True
    operator_reward_decay: float = 0.92
    operator_exploration_bias: float = 0.08
    multi_objective_mode: str = "pareto"


@dataclass
class OutputConfig:
    """Report output configuration."""
    format: str = "html"            # html, json, sarif, markdown, pdf
    output_dir: str = "./basilisk-reports"
    include_conversations: bool = False
    include_raw_content: bool = False
    include_evolution_log: bool = True
    sarif_file: str = ""
    jira_url: str = ""
    jira_project: str = ""
    jira_token: str = ""
    defectdojo_url: str = ""
    defectdojo_token: str = ""
    webhook_url: str = ""


@dataclass
class DashboardConfig:
    """Web dashboard configuration."""
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 5000
    auto_open: bool = True


@dataclass
class StealthConfig:
    """Stealth mode settings for production target scanning."""
    min_delay: float = 1.0          # Minimum seconds between requests
    max_delay: float = 5.0          # Maximum seconds between requests
    jitter: bool = True             # Add random timing jitter
    human_like_typing: bool = True  # Simulate human typing speed
    rotate_user_agents: bool = True
    proxy_url: str = ""


@dataclass
class BasiliskConfig:
    """
    Root configuration object for a Basilisk scan session.

    Can be loaded from YAML config file, CLI arguments, or environment variables.
    CLI arguments override config file values. Environment variables override both.
    """
    target: TargetConfig = field(default_factory=TargetConfig)
    mode: ScanMode = ScanMode.STANDARD
    evolution: EvolutionConfig = field(default_factory=EvolutionConfig)
    campaign: CampaignConfig = field(default_factory=CampaignConfig)
    policy: ScanPolicy = field(default_factory=ScanPolicy)
    output: OutputConfig = field(default_factory=OutputConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    stealth: StealthConfig = field(default_factory=StealthConfig)
    modules: list[str] = field(default_factory=list)   # Empty = all attack modules
    recon_modules: list[str] = field(default_factory=list) # Empty = all recon steps
    exclude_modules: list[str] = field(default_factory=list)
    max_findings: int = 0           # 0 = unlimited
    fail_on: str = "high"           # CI/CD exit code threshold
    verbose: bool = False
    debug: bool = False
    skip_recon: bool = False
    session_db: str = "./basilisk-sessions.db"
    include_research_modules: bool = False
    persist_payloads: bool = False
    persist_responses: bool = False
    persist_conversations: bool = False

    @classmethod
    def from_yaml(cls, path: str | Path) -> BasiliskConfig:
        """Load configuration from a YAML file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        with open(path) as f:
            raw = yaml.safe_load(f) or {}

        config = cls()
        _apply_dict(config, raw)
        return config

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BasiliskConfig:
        """Load configuration from a nested dictionary."""
        config = cls()
        _apply_dict(config, data or {})
        return config

    @classmethod
    def from_cli_args(cls, **kwargs: Any) -> BasiliskConfig:
        """Build configuration from CLI arguments."""
        config = cls()

        if kwargs.get("config"):
            config = cls.from_yaml(kwargs["config"])

        # CLI overrides
        if kwargs.get("target"):
            config.target.url = kwargs["target"]
        if kwargs.get("provider"):
            config.target.provider = kwargs["provider"]
        if kwargs.get("model"):
            config.target.model = kwargs["model"]
        if kwargs.get("api_key"):
            config.target.api_key = kwargs["api_key"]
        if kwargs.get("auth"):
            config.target.auth_header = kwargs["auth"]
        if kwargs.get("mode"):
            config.mode = ScanMode(kwargs["mode"])
        if kwargs.get("evolve") is not None:
            config.evolution.enabled = kwargs["evolve"]
        if kwargs.get("generations"):
            config.evolution.generations = kwargs["generations"]
        if kwargs.get("attacker_provider"):
            config.evolution.attacker_provider = kwargs["attacker_provider"]
        if kwargs.get("attacker_model"):
            config.evolution.attacker_model = kwargs["attacker_model"]
        if kwargs.get("attacker_api_key"):
            config.evolution.attacker_api_key = kwargs["attacker_api_key"]
        if kwargs.get("campaign"):
            _apply_dict(config.campaign, kwargs["campaign"])
        if kwargs.get("policy"):
            _apply_dict(config.policy, kwargs["policy"])
        if kwargs.get("population_size"):
            config.evolution.population_size = int(kwargs["population_size"])
        if kwargs.get("fitness_threshold"):
            config.evolution.fitness_threshold = float(kwargs["fitness_threshold"])
        if kwargs.get("stagnation_limit"):
            config.evolution.stagnation_limit = int(kwargs["stagnation_limit"])
        if kwargs.get("exit_on_first") is not None:
            config.evolution.exit_on_first = kwargs["exit_on_first"]
        if kwargs.get("enable_cache") is not None:
            config.evolution.enable_cache = kwargs["enable_cache"]
        if kwargs.get("diversity_mode"):
            config.evolution.diversity_mode = kwargs["diversity_mode"]
        if kwargs.get("intent_weight") is not None:
            config.evolution.intent_weight = float(kwargs["intent_weight"])
        if kwargs.get("output"):
            config.output.format = kwargs["output"]
        if kwargs.get("output_dir"):
            config.output.output_dir = kwargs["output_dir"]
        if kwargs.get("module"):
            config.modules = list(kwargs["module"])
        if kwargs.get("verbose"):
            config.verbose = kwargs["verbose"]
        if kwargs.get("debug"):
            config.debug = kwargs["debug"]
        if kwargs.get("no_dashboard"):
            config.dashboard.enabled = False
        if kwargs.get("fail_on"):
            config.fail_on = kwargs["fail_on"]
        if kwargs.get("skip_recon"):
            config.skip_recon = True
        if kwargs.get("recon_module"):
            config.recon_modules = list(kwargs["recon_module"])
        if kwargs.get("include_research_modules") is not None:
            config.include_research_modules = bool(kwargs["include_research_modules"])
        if kwargs.get("persist_payloads") is not None:
            config.persist_payloads = bool(kwargs["persist_payloads"])
        if kwargs.get("persist_responses") is not None:
            config.persist_responses = bool(kwargs["persist_responses"])
        if kwargs.get("persist_conversations") is not None:
            config.persist_conversations = bool(kwargs["persist_conversations"])
        if kwargs.get("include_conversations") is not None:
            config.output.include_conversations = bool(kwargs["include_conversations"])
        if kwargs.get("include_raw_content") is not None:
            config.output.include_raw_content = bool(kwargs["include_raw_content"])

        if config.policy.retain_raw_findings:
            config.persist_payloads = True
            config.persist_responses = True
        if config.policy.retain_conversations:
            config.persist_conversations = True
        if config.policy.raw_evidence_mode == RawEvidenceMode.FULL:
            config.output.include_raw_content = True
            config.output.include_conversations = config.persist_conversations

        return config

    def validate(self) -> list[str]:
        """Validate the configuration and return list of errors."""
        errors: list[str] = []
        if not self.target.url:
            errors.append("Target URL is required")
        if not self.target.resolve_api_key() and self.target.provider != "custom":
            errors.append(f"API key not found for provider '{self.target.provider}'")
        if self.evolution.population_size < 10:
            errors.append("Evolution population size must be >= 10")
        if self.evolution.generations < 1:
            errors.append("Evolution generations must be >= 1")
        errors.extend(self.policy.validate())
        if self.policy.execution_mode in ("exploit_chain", "research") and not self.campaign.authorization.operator:
            errors.append("Campaign operator is required for exploit_chain or research mode")
        if self.policy.approval_required and not self.campaign.authorization.approved:
            errors.append("Campaign approval is required by policy but not confirmed")
        return errors

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary (for saving/logging)."""
        return dataclasses.asdict(self)

    def to_safe_dict(self) -> dict[str, Any]:
        """Serialize configuration without persisting secrets."""
        data = dataclasses.asdict(self)

        target = data.get("target", {})
        if target:
            target["api_key"] = ""
            target["auth_header"] = ""
            if target.get("system_prompt"):
                target["system_prompt"] = "[redacted]"
            target["custom_headers"] = _redact_mapping(target.get("custom_headers", {}))

        evolution = data.get("evolution", {})
        if evolution:
            evolution["attacker_api_key"] = ""

        campaign = data.get("campaign", {})
        if campaign:
            auth = campaign.get("authorization", {})
            if auth:
                if auth.get("justification"):
                    auth["justification"] = "[redacted]"
                auth["signed_scope_hash"] = auth.get("signed_scope_hash", "")

        output = data.get("output", {})
        if output:
            output["jira_token"] = ""
            output["defectdojo_token"] = ""

        return data


def _redact_mapping(values: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in values.items():
        if _looks_sensitive_key(key):
            redacted[key] = "[redacted]"
        else:
            redacted[key] = value
    return redacted


def _looks_sensitive_key(key: str) -> bool:
    lower = key.lower()
    return any(token in lower for token in ("key", "token", "secret", "auth", "password", "cookie"))


def _apply_dict(obj: Any, data: dict[str, Any]) -> None:
    """Recursively apply dictionary values to a dataclass instance."""
    for key, value in data.items():
        if hasattr(obj, key):
            attr = getattr(obj, key)
            if isinstance(value, dict) and hasattr(attr, "__dataclass_fields__"):
                _apply_dict(attr, value)
            elif isinstance(attr, Enum):
                setattr(obj, key, type(attr)(value))
            else:
                setattr(obj, key, value)
