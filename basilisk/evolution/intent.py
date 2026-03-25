"""
Basilisk Intent — semantic intent preservation scoring.

Measures how well a mutated payload preserves the original attack intent.
Uses TF-IDF cosine similarity by default (zero dependencies).
Optionally uses sentence-transformers for higher quality if available.
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from typing import Any

logger = logging.getLogger("basilisk.evolution.intent")

# Try to import sentence-transformers for high-quality embeddings
_SENTENCE_TRANSFORMER = None
_ST_MODEL = None

def _init_sentence_transformer() -> bool:
    """Lazy-load sentence-transformers model. Returns True if available."""
    global _SENTENCE_TRANSFORMER, _ST_MODEL
    if _ST_MODEL is not None:
        return True
    try:
        from sentence_transformers import SentenceTransformer
        _ST_MODEL = SentenceTransformer("all-MiniLM-L6-v2")
        _SENTENCE_TRANSFORMER = True
        logger.info("Intent scoring: using sentence-transformers (high quality)")
        return True
    except ImportError:
        _SENTENCE_TRANSFORMER = False
        logger.debug("Intent scoring: using TF-IDF fallback (install sentence-transformers for better quality)")
        return False


def _tokenize(text: str) -> list[str]:
    """Simple whitespace + punctuation tokenizer."""
    return re.findall(r'\b\w+\b', text.lower())


def _tfidf_cosine(text_a: str, text_b: str) -> float:
    """Compute cosine similarity using TF-IDF vectors (zero-dependency)."""
    tokens_a = _tokenize(text_a)
    tokens_b = _tokenize(text_b)

    if not tokens_a or not tokens_b:
        return 0.0

    # Build term frequency vectors
    tf_a = Counter(tokens_a)
    tf_b = Counter(tokens_b)

    # All terms
    all_terms = set(tf_a.keys()) | set(tf_b.keys())

    # Compute dot product and magnitudes
    dot = 0.0
    mag_a = 0.0
    mag_b = 0.0
    for term in all_terms:
        a = tf_a.get(term, 0)
        b = tf_b.get(term, 0)
        dot += a * b
        mag_a += a * a
        mag_b += b * b

    if mag_a == 0 or mag_b == 0:
        return 0.0

    return dot / (math.sqrt(mag_a) * math.sqrt(mag_b))


def _st_cosine(text_a: str, text_b: str) -> float:
    """Compute cosine similarity using sentence-transformers."""
    if _ST_MODEL is None:
        return _tfidf_cosine(text_a, text_b)

    embeddings = _ST_MODEL.encode([text_a, text_b], convert_to_numpy=True)
    # Cosine similarity
    dot = sum(a * b for a, b in zip(embeddings[0], embeddings[1]))
    mag_a = math.sqrt(sum(a * a for a in embeddings[0]))
    mag_b = math.sqrt(sum(b * b for b in embeddings[1]))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


def compute_intent_similarity(original: str, mutated: str) -> float:
    """Compute semantic similarity between original and mutated payload.

    Returns a score in [0.0, 1.0] where:
    - 1.0 = identical intent
    - 0.0 = completely different intent

    Uses sentence-transformers if available, falls back to TF-IDF.
    """
    if not original or not mutated:
        return 0.0

    # Identical payloads
    if original == mutated:
        return 1.0

    # Try sentence-transformers first
    if _SENTENCE_TRANSFORMER is None:
        _init_sentence_transformer()

    if _SENTENCE_TRANSFORMER:
        return float(_st_cosine(original, mutated))
    else:
        return float(_tfidf_cosine(original, mutated))


class IntentTracker:
    """Tracks intent drift across generations.

    Stores the original seed payloads and computes how much
    the current population has drifted from the original intent.
    """

    def __init__(self, seed_payloads: list[str]) -> None:
        self.seeds = seed_payloads[:20]  # Keep top 20 seeds for comparison
        self._generation_drift: list[float] = []

    def score_payload(self, payload: str) -> float:
        """Score how well a payload preserves seed intent.

        Returns max similarity across all seed payloads.
        """
        if not self.seeds:
            return 1.0  # No seeds = no penalty

        max_sim = max(
            compute_intent_similarity(seed, payload)
            for seed in self.seeds
        )
        return max_sim

    def record_generation(self, payloads: list[str]) -> float:
        """Record average intent preservation for a generation.

        Returns the average intent score for the generation.
        """
        if not payloads or not self.seeds:
            return 1.0

        scores = [self.score_payload(p) for p in payloads]
        avg = sum(scores) / len(scores)
        self._generation_drift.append(avg)
        return avg

    @property
    def drift_history(self) -> list[float]:
        """Per-generation average intent scores (1.0 = no drift)."""
        return self._generation_drift

    @property
    def total_drift(self) -> float:
        """Overall drift from first to last generation."""
        if len(self._generation_drift) < 2:
            return 0.0
        return self._generation_drift[0] - self._generation_drift[-1]

    def stats(self) -> dict[str, Any]:
        return {
            "seed_count": len(self.seeds),
            "generations_tracked": len(self._generation_drift),
            "current_intent_score": self._generation_drift[-1] if self._generation_drift else 1.0,
            "total_drift": round(self.total_drift, 3),
        }
