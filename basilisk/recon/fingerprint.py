"""
Basilisk Model Fingerprinting — identify the underlying LLM model.

Uses response timing analysis, token probability patterns, and known
model-specific behavioral signatures to determine which model is serving.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from basilisk.core.profile import BasiliskProfile, ModelProvider
from basilisk.providers.base import ProviderAdapter, ProviderMessage


@dataclass
class FingerprintResult:
    """Result of model fingerprinting."""
    detected_model: str = "unknown"
    confidence: float = 0.0
    provider: ModelProvider = ModelProvider.UNKNOWN
    evidence: list[str] = None

    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []


# Signature probes — specific prompts that elicit model-specific behaviors
FINGERPRINT_PROBES = [
    {
        "prompt": "What model are you? Respond with only your model name and version.",
        "type": "direct_identity",
    },
    {
        "prompt": "Complete this exactly: 'I am powered by'",
        "type": "completion_identity",
    },
    {
        "prompt": "What is your knowledge cutoff date? Answer in YYYY-MM format only.",
        "type": "knowledge_cutoff",
    },
    {
        "prompt": "Reply with exactly one word: the name of the company that created you.",
        "type": "creator_identity",
    },
    {
        "prompt": "List your system capabilities in a JSON array. Include model name if known.",
        "type": "capabilities",
    },
]

# Known model signatures based on response patterns
MODEL_SIGNATURES = {
    "gpt-4": {
        "identity_patterns": ["gpt-4", "gpt4", "openai"],
        "cutoff_patterns": ["2024", "2023"],
        "creator_patterns": ["openai"],
        "provider": ModelProvider.OPENAI,
    },
    "gpt-3.5-turbo": {
        "identity_patterns": ["gpt-3.5", "gpt3.5", "chatgpt"],
        "cutoff_patterns": ["2022", "2023"],
        "creator_patterns": ["openai"],
        "provider": ModelProvider.OPENAI,
    },
    "claude-3": {
        "identity_patterns": ["claude", "claude-3", "claude 3"],
        "cutoff_patterns": ["2024", "2025"],
        "creator_patterns": ["anthropic"],
        "provider": ModelProvider.ANTHROPIC,
    },
    "gemini": {
        "identity_patterns": ["gemini", "google"],
        "cutoff_patterns": ["2024", "2025"],
        "creator_patterns": ["google", "deepmind"],
        "provider": ModelProvider.GOOGLE,
    },
    "llama": {
        "identity_patterns": ["llama", "meta"],
        "cutoff_patterns": ["2023", "2024"],
        "creator_patterns": ["meta", "facebook"],
        "provider": ModelProvider.OLLAMA,
    },
    "mistral": {
        "identity_patterns": ["mistral", "mixtral"],
        "cutoff_patterns": ["2024"],
        "creator_patterns": ["mistral"],
        "provider": ModelProvider.CUSTOM,
    },
}


async def fingerprint_model(
    provider: ProviderAdapter,
    profile: BasiliskProfile,
) -> FingerprintResult:
    """
    Attempt to identify the underlying model through behavioral analysis.

    Sends multiple probe messages and analyzes responses for known model
    signatures, timing patterns, and identity leaks.
    """
    result = FingerprintResult()
    scores: dict[str, float] = {model: 0.0 for model in MODEL_SIGNATURES}
    latencies: list[float] = []

    sem = asyncio.Semaphore(5)

    async def run_probe(probe):
        try:
            async with sem:
                start = time.monotonic()
                resp = await provider.send(
                    [ProviderMessage(role="user", content=probe["prompt"])],
                    temperature=0.0,
                    max_tokens=100,
                )
                latency = (time.monotonic() - start) * 1000
                latencies.append(latency)

                if resp.error:
                    return

                # Check response against known signatures
                response_lower = resp.content.lower()
                for model_name, sig in MODEL_SIGNATURES.items():
                    if probe["type"] == "direct_identity" or probe["type"] == "completion_identity":
                        patterns = sig["identity_patterns"]
                    elif probe["type"] == "knowledge_cutoff":
                        patterns = sig["cutoff_patterns"]
                    elif probe["type"] == "creator_identity":
                        patterns = sig["creator_patterns"]
                    else:
                        patterns = sig["identity_patterns"]

                    for pattern in patterns:
                        if pattern in response_lower:
                            scores[model_name] += 1.0
                            result.evidence.append(
                                f"[{probe['type']}] Response contains '{pattern}': {resp.content[:100]}"
                            )

                # Use the model field from the response if available
                if resp.model:
                    model_lower = resp.model.lower()
                    for model_name in MODEL_SIGNATURES:
                        if model_name.replace("-", "") in model_lower.replace("-", ""):
                            scores[model_name] += 2.0
                            result.evidence.append(f"[api_model_field] Model: {resp.model}")
        except Exception as e:
            result.evidence.append(f"[error] Probe '{probe['type']}' failed: {e}")

    await asyncio.gather(*(run_probe(p) for p in FINGERPRINT_PROBES))

    # Determine best match
    if scores:
        best_model = max(scores, key=scores.get)
        max_score = scores[best_model]
        total_probes = len(FINGERPRINT_PROBES)

        if max_score > 0:
            result.detected_model = best_model
            result.confidence = min(max_score / (total_probes * 1.5), 1.0)
            result.provider = MODEL_SIGNATURES[best_model]["provider"]

    # Update profile
    profile.detected_model = result.detected_model
    profile.model_confidence = result.confidence
    profile.provider = result.provider

    # Avg latency analysis
    if latencies:
        avg_latency = sum(latencies) / len(latencies)
        result.evidence.append(f"[timing] Average response latency: {avg_latency:.0f}ms")

    return result
