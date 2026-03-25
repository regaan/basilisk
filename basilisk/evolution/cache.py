"""
Basilisk Payload Cache — avoids redundant API calls during evolution.

Caches (payload + context_hash) → (response, fitness) so identical payloads
across generations don't consume API tokens. Optionally persists to disk.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger("basilisk.evolution.cache")


@dataclass
class CacheEntry:
    """A cached evaluation result."""
    response: str
    fitness: float


class PayloadCache:
    """
    LRU cache for payload evaluation results.

    Keys are SHA-256 hashes of (payload + context_hash).
    Saves API costs by returning cached responses for identical payloads.
    """

    def __init__(self, max_size: int = 5000, persist_path: str | None = None) -> None:
        self.max_size = max_size
        self.persist_path = Path(persist_path) if persist_path else None
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._hits = 0
        self._misses = 0

        if self.persist_path and self.persist_path.exists():
            self._load()

    @staticmethod
    def _make_key(payload: str, context_hash: str = "") -> str:
        """Create a cache key from payload and context hash."""
        raw = f"{context_hash}::{payload}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @staticmethod
    def hash_context(context_messages: list[dict[str, str]]) -> str:
        """Create a stable hash from context messages."""
        serialized = json.dumps(
            [{"role": m.get("role", ""), "content": m.get("content", "")[:200]} for m in context_messages],
            sort_keys=True,
        )
        return hashlib.sha256(serialized.encode()).hexdigest()[:12]

    def get(self, payload: str, context_hash: str = "") -> CacheEntry | None:
        """Look up a cached result. Returns None on miss."""
        key = self._make_key(payload, context_hash)
        if key in self._cache:
            self._hits += 1
            self._cache.move_to_end(key)
            return self._cache[key]
        self._misses += 1
        return None

    def put(self, payload: str, response: str, fitness: float, context_hash: str = "") -> None:
        """Store an evaluation result in the cache."""
        key = self._make_key(payload, context_hash)
        self._cache[key] = CacheEntry(response=response, fitness=fitness)
        self._cache.move_to_end(key)

        # Evict oldest if over capacity
        while len(self._cache) > self.max_size:
            self._cache.popitem(last=False)

    @property
    def hits(self) -> int:
        return self._hits

    @property
    def misses(self) -> int:
        return self._misses

    @property
    def api_calls_saved(self) -> int:
        return self._hits

    @property
    def size(self) -> int:
        return len(self._cache)

    @property
    def hit_rate(self) -> float:
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0

    def stats(self) -> dict[str, Any]:
        return {
            "cache_size": self.size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self.hit_rate, 3),
            "api_calls_saved": self.api_calls_saved,
        }

    def save(self) -> None:
        """Persist cache to disk."""
        if not self.persist_path:
            return
        self.persist_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            k: {"response": v.response[:500], "fitness": v.fitness}
            for k, v in self._cache.items()
        }
        self.persist_path.write_text(json.dumps(data, indent=2))
        logger.debug(f"Cache saved: {self.size} entries → {self.persist_path}")

    def _load(self) -> None:
        """Load cache from disk."""
        try:
            data = json.loads(self.persist_path.read_text())  # type: ignore[union-attr]
            for k, v in data.items():
                self._cache[k] = CacheEntry(response=v["response"], fitness=v["fitness"])
            logger.debug(f"Cache loaded: {self.size} entries ← {self.persist_path}")
        except (json.JSONDecodeError, KeyError, OSError) as e:
            logger.warning(f"Cache load failed: {e}")

    def clear(self) -> None:
        """Clear the cache."""
        self._cache.clear()
        self._hits = 0
        self._misses = 0
