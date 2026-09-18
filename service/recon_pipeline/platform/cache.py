"""S8 — the Redis hot cache: run-scoped state that must survive a dead Redis.

Two jobs from the plan:

* **hot scores** — the latest score per asset so workers ask Redis, not Neo4j;
* **membership** — a bloom-style set of "asset already known" so pipelines can
  cheaply skip re-processing across stages.

The graceful-degrade contract matters more than the feature: **Redis being
down is a state, not an error.**  Every method returns a usable answer (cache
miss) and the ``available`` flag says whether anything actually reached Redis.
A caller that ignores the flag degrades to "no cache" — never to a crash — and
the run report records the degradation.

No ``redis`` import happens until a connection is actually attempted, so the
platform imports cleanly on machines without the client library installed.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any

from .common.redis_url import connection_kwargs

log = logging.getLogger("platform.cache")

DEGRADED_REASON = "redis unavailable"

SCORE_PREFIX = "asm:score:"
KNOWN_PREFIX = "asm:known:"
CACHE_TTL_SECONDS = 7 * 24 * 3600


def _redis_url() -> str:
    return os.getenv("REDIS_URL", "redis://localhost:6379/0")


@dataclass
class CacheHealth:
    """What the report reads: did the cache work, and if not, why not."""

    available: bool
    reason: str = ""

    def to_dict(self) -> dict[str, str | bool]:
        return {"available": self.available, "reason": self.reason}


class HotCache:
    """Redis-backed hot state; every operation degrades to a miss."""

    def __init__(self, url: str | None = None, *, client: Any | None = None) -> None:
        self._url = url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self._client: Any | None = client
        self._health = CacheHealth(available=False)
        if client is not None:
            self._health = CacheHealth(available=True)
        else:
            self._connect()

    # ------------------------------------------------------------------ #
    # connection
    # ------------------------------------------------------------------ #

    def _connect(self) -> None:
        try:
            import redis  # imported lazily: optional dependency
        except ImportError:
            self._health = CacheHealth(available=False, reason="redis client not installed")
            return
        try:
            self._client = redis.Redis(**connection_kwargs(str(self._url)))
            self._client.ping()
            self._health = CacheHealth(available=True)
        except Exception as exc:  # any redis failure is a degradation
            self._client = None
            self._health = CacheHealth(available=False, reason=f"{type(exc).__name__}: {exc}")

    @property
    def health(self) -> CacheHealth:
        return self._health

    @property
    def available(self) -> bool:
        return self._health.available

    # ------------------------------------------------------------------ #
    # hot scores
    # ------------------------------------------------------------------ #

    def put_score(self, asset_type: str, canonical_value: str, score: int) -> bool:
        """Store the latest score for an asset.  Returns success (False = degraded)."""
        if not self.available:
            return False
        client = self._client
        assert client is not None  # narrowing: available implies connected
        try:
            key = f"{SCORE_PREFIX}{asset_type}:{canonical_value}"
            client.set(key, json.dumps({"score": score}), ex=CACHE_TTL_SECONDS)
            return True
        except Exception as exc:
            log.debug("put_score degraded: %s", exc)
            return False

    def get_score(self, asset_type: str, canonical_value: str) -> int | None:
        """The latest score, or ``None`` on miss/degradation."""
        if not self.available:
            return None
        client = self._client
        assert client is not None  # narrowing: available implies connected
        try:
            key = f"{SCORE_PREFIX}{asset_type}:{canonical_value}"
            raw = client.get(key)
            if raw is None:
                return None
            return int(json.loads(raw)["score"])
        except Exception as exc:
            log.debug("get_score degraded: %s", exc)
            return None

    # ------------------------------------------------------------------ #
    # membership
    # ------------------------------------------------------------------ #

    def mark_known(self, asset_type: str, canonical_value: str) -> bool:
        if not self.available:
            return False
        client = self._client
        assert client is not None  # narrowing: available implies connected
        try:
            client.sadd(f"{KNOWN_PREFIX}{asset_type}", canonical_value)
            return True
        except Exception as exc:
            log.debug("mark_known degraded: %s", exc)
            return False

    def is_known(self, asset_type: str, canonical_value: str) -> bool | None:
        """``True``/``False`` when Redis answered; ``None`` when degraded."""
        if not self.available:
            return None
        client = self._client
        assert client is not None  # narrowing: available implies connected
        try:
            return bool(client.sismember(f"{KNOWN_PREFIX}{asset_type}", canonical_value))
        except Exception as exc:
            log.debug("is_known degraded: %s", exc)
            return None

    def to_dict(self) -> dict[str, object]:
        return {"cache": self._health.to_dict()}
