"""S9 — the queue topology: pipeline outputs become messages.

Redis Streams topology from the plan:

* one **stream per pipeline stage** (``asm:stream:<pipeline>:<stage>``);
* a **consumer group** per worker pool (``asm:group:default``);
* messages are small JSON envelopes: ``{"asset_type", "canonical_value",
  "source", "payload"}`` — enough to route, not enough to be a database;
* failed deliveries go to the **DLQ** (``asm:dlq``) with the error attached,
  because the difference between "not yet" and "never" is the observability
  layer's first question.

Graceful degrade, same contract as :mod:`.cache`: with Redis down the queue
becomes a **no-op bus** — ``publish`` counts the message as dropped-with-reason,
``consume`` yields nothing, and ``available`` is False.  A pipeline that
publishes its findings therefore still works end-to-end without Redis; it just
loses the async hop.

A practical extra: when Redis is unavailable, published envelopes are *also*
appended to an on-disk spool file, so a degraded run's messages are recoverable
instead of vanishing.  The spool is best-effort (never raises).
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .common.redis_url import connection_kwargs

log = logging.getLogger("platform.queueing")

STREAM_PREFIX = "asm:stream:"
GROUP_DEFAULT = "asm:group:default"
DLQ_STREAM = "asm:dlq"
#: Re-delivery ceiling: after this many attempts a message goes to the DLQ.
MAX_DELIVERIES = 5


@dataclass
class Envelope:
    """One unit of work on a stream."""

    stream: str
    asset_type: str
    canonical_value: str
    source: str
    payload: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "stream": self.stream,
            "asset_type": self.asset_type,
            "canonical_value": self.canonical_value,
            "source": self.source,
            "payload": self.payload,
            "published_at": time.time(),
        }

    @classmethod
    def from_fields(cls, raw: dict) -> "Envelope":
        return cls(
            stream=str(raw.get("stream", "")),
            asset_type=str(raw.get("asset_type", "")),
            canonical_value=str(raw.get("canonical_value", "")),
            source=str(raw.get("source", "")),
            payload=dict(raw.get("payload") or {}),
        )


@dataclass
class QueueHealth:
    available: bool
    reason: str = ""
    published: int = 0
    dropped: int = 0
    spooled: int = 0
    dead: int = 0

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "reason": self.reason,
            "published": self.published,
            "dropped": self.dropped,
            "spooled": self.spooled,
            "dead_lettered": self.dead,
        }


class Queue:
    """Redis Streams producer/consumer with a no-op degradation mode."""

    def __init__(
        self,
        url: str | None = None,
        *,
        client: Any | None = None,
        spool_path: Path | str | None = None,
    ) -> None:
        self._url = url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self._client: Any | None = client
        self._health = QueueHealth(available=False)
        self._spool_path = Path(spool_path) if spool_path else None
        if client is not None:
            self._health.available = True
        else:
            self._connect()

    def _connect(self) -> None:
        try:
            import redis  # optional dependency, imported lazily
        except ImportError:
            self._health.reason = "redis client not installed"
            return
        try:
            self._client = redis.Redis(**connection_kwargs(str(self._url)))
            self._client.ping()
            self._health.available = True
        except Exception as exc:
            self._client = None
            self._health.reason = f"{type(exc).__name__}: {exc}"

    @property
    def health(self) -> QueueHealth:
        return self._health

    @property
    def available(self) -> bool:
        return self._health.available

    # ------------------------------------------------------------------ #
    # producing
    # ------------------------------------------------------------------ #

    def publish(self, envelope: Envelope) -> bool:
        """Publish one envelope; returns True when Redis actually took it."""
        body = json.dumps(envelope.to_dict())
        if self.available:
            client = self._client
            assert client is not None  # narrowing: available implies connected
            try:
                client.xadd(envelope.stream, {"envelope": body})
                self._health.published += 1
                return True
            except Exception as exc:
                log.warning("publish degraded: %s", exc)
        self._spool(envelope)
        self._health.dropped += 1
        return False

    def _spool(self, envelope: Envelope) -> None:
        """Best-effort local spool so degraded messages are recoverable."""
        if self._spool_path is None:
            return
        try:
            self._spool_path.parent.mkdir(parents=True, exist_ok=True)
            with self._spool_path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(envelope.to_dict()) + "\n")
            self._health.spooled += 1
        except OSError as exc:
            log.debug("spool failed: %s", exc)

    def ensure_group(self, stream: str) -> bool:
        """Create the consumer group if needed; idempotent."""
        if not self.available:
            return False
        client = self._client
        assert client is not None  # narrowing: available implies connected
        try:
            try:
                client.xgroup_create(stream, GROUP_DEFAULT, id="0", mkstream=True)
            except Exception as exc:
                if "BUSYGROUP" in str(exc):
                    return True
                raise
            return True
        except Exception as exc:
            log.warning("ensure_group degraded: %s", exc)
            return False

    # ------------------------------------------------------------------ #
    # consuming
    # ------------------------------------------------------------------ #

    def consume(self, stream: str, count: int = 10, block_ms: int = 0) -> list[Envelope]:
        """Read pending/default-group messages; empty list when degraded."""
        if not self.available:
            return []
        client = self._client
        assert client is not None  # narrowing: available implies connected
        try:
            entries = client.xreadgroup(
                GROUP_DEFAULT, stream, {stream: ">"}, count=count, block=block_ms
            )
            envelopes: list[Envelope] = []
            for _stream_name, messages in entries or []:
                for message_id, fields in messages:
                    raw = json.loads((fields or {}).get("envelope", "{}"))
                    envelope = Envelope.from_fields(raw)
                    client.xack(stream, GROUP_DEFAULT, message_id)
                    envelopes.append(envelope)
            return envelopes
        except Exception as exc:
            log.warning("consume degraded: %s", exc)
            return []

    def dead_letter(self, envelope: Envelope, error: str) -> bool:
        """Move a failed envelope to the DLQ with its error attached."""
        self._health.dead += 1
        if not self.available:
            return False
        client = self._client
        assert client is not None  # narrowing: available implies connected
        try:
            body = json.dumps({**envelope.to_dict(), "error": error})
            client.xadd(DLQ_STREAM, {"envelope": body})
            return True
        except Exception as exc:
            log.warning("dead_letter degraded: %s", exc)
            return False

    def to_dict(self) -> dict:
        return {"queue": self._health.to_dict()}
