"""The OOB effect: our own collaborator, and the records it saw.

Blind classes (SSRF, blind SQLi, XXE) have no evidence class strong enough for a
finding except this one. A timing heuristic can be wrong; something *we control*
recording that the target's server reached out to it cannot be. That is why the
design self-hosts the correlator instead of using a third party: private
telemetry, per-probe identifiers, and no other firm in the loop.

Two URLs, and the difference between them is the whole trick:

``public_base``
    The URL embedded in a probe — the one *the target* must be able to reach.
    Inside a container network that is usually ``host.docker.internal`` (or the
    collaborator's compose service name), never ``127.0.0.1``: a container's
    loopback is the container.

``local_base``
    Where *we* read the records from.  ``127.0.0.1`` on the host.

Getting these the wrong way round produces the most confusing possible failure —
a probe that works, an interaction that was recorded, and a poller reading an
empty file — so they are two named parameters rather than one clever one.

The interaction record is the evidence; this module's job is only to fetch it and
hand it to ``world/observe.py`` as :class:`RawOobFetch`. Nothing here decides
whether an interaction means anything.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from ..kernel.exchange import RawOobFetch, RawOobInteraction

NAME = "oob"

DEFAULT_PUBLIC_BASE = "http://host.docker.internal:9009"
DEFAULT_LOCAL_BASE = "http://127.0.0.1:9009"

#: Poll cadence and patience.  A blind fetch is a *server-side* round trip that
#: the target may do after responding to us, so the first poll is usually too
#: early; the wait is real but bounded, and a miss is inconclusive rather than a
#: refutation.
DEFAULT_POLL_INTERVAL = 0.5
DEFAULT_POLL_TIMEOUT = 15.0


@dataclass(frozen=True)
class OobCapabilities:
    """What the collaborator can be asked for, reported rather than assumed."""

    name: str = NAME
    available: bool = False
    #: HTTP-only in Phase 1.  DNS-based collaboration is more robust and is
    #: deferred: the limitation is recorded here instead of being forgotten.
    dns: bool = False
    public_base: str = ""
    local_base: str = ""
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "available": self.available,
            "dns": self.dns,
            "public_base": self.public_base,
            "local_base": self.local_base,
            "reason": self.reason,
        }


@dataclass
class OobEffect:
    """Client for the self-hosted collaborator (``service/oob_collaborator``)."""

    public_base: str = DEFAULT_PUBLIC_BASE
    local_base: str = DEFAULT_LOCAL_BASE
    timeout: float = 5.0
    poll_interval: float = DEFAULT_POLL_INTERVAL
    poll_timeout: float = DEFAULT_POLL_TIMEOUT
    client: Any = None
    _owned_client: bool = False
    _health: OobCapabilities | None = None

    def __post_init__(self) -> None:
        if self.client is None:
            import httpx

            self.client = httpx.Client(timeout=httpx.Timeout(self.timeout))
            self._owned_client = True

    # ------------------------------------------------------------------ #
    # what the technique embeds
    # ------------------------------------------------------------------ #

    def url_for(self, probe: str) -> str:
        """The collaborator URL a probe should embed, for probe id *probe*.

        Deterministic: the same probe id always produces the same URL, so a probe
        spec is reproducible and a recorded interaction can be attributed without
        a lookup table.
        """
        return f"{self.public_base.rstrip('/')}/oob/{probe}"

    # ------------------------------------------------------------------ #
    # what the verifier reads
    # ------------------------------------------------------------------ #

    def health(self) -> OobCapabilities:
        """Is the collaborator there?  Cached: a run asks once."""
        if self._health is not None:
            return self._health
        self._health = self._probe_health()
        return self._health

    def _probe_health(self) -> OobCapabilities:
        try:
            response = self.client.get(f"{self.local_base.rstrip('/')}/healthz")
            body = response.json() if response.status_code == 200 else {}
            return OobCapabilities(
                available=response.status_code == 200,
                public_base=self.public_base,
                local_base=self.local_base,
                reason="" if response.status_code == 200 else f"status {response.status_code}",
                dns=bool(body.get("dns", False)),
            )
        except Exception as exc:  # noqa: BLE001 - unavailable is a state, not an error
            return OobCapabilities(
                available=False,
                public_base=self.public_base,
                local_base=self.local_base,
                reason=f"{type(exc).__name__}: {exc}",
            )

    @property
    def capabilities(self) -> OobCapabilities:
        return self.health()

    def read(self, probe: str) -> RawOobFetch:
        """Every interaction recorded for *probe*; empty when none arrived."""
        url = f"{self.local_base.rstrip('/')}/interactions"
        try:
            response = self.client.get(url, params={"probe": probe})
        except Exception as exc:  # noqa: BLE001
            return RawOobFetch(probe=probe, error=f"{type(exc).__name__}: {exc}")
        if response.status_code != 200:
            return RawOobFetch(probe=probe, error=f"collaborator answered {response.status_code}")
        try:
            payload = response.json()
        except (json.JSONDecodeError, ValueError) as exc:
            return RawOobFetch(probe=probe, error=f"unreadable collaborator response: {exc}")
        rows = payload.get("interactions") if isinstance(payload, dict) else payload
        if not isinstance(rows, list):
            return RawOobFetch(probe=probe, error="collaborator returned no interaction list")
        interactions: list[RawOobInteraction] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            interactions.append(
                RawOobInteraction(
                    probe=str(row.get("probe") or probe),
                    path=str(row.get("path") or ""),
                    method=str(row.get("method") or "GET"),
                    source_ip=str(row.get("source_ip") or ""),
                    user_agent=str(row.get("user_agent") or ""),
                    at=float(row.get("at") or 0.0),
                )
            )
        return RawOobFetch(probe=probe, interactions=tuple(interactions))

    def wait(
        self,
        probe: str,
        *,
        timeout: float | None = None,
        interval: float | None = None,
        sleep: Any = None,
    ) -> RawOobFetch:
        """Poll until an interaction arrives, or the patience runs out.

        A timeout returns an *empty* fetch, not an error: "nothing arrived in
        fifteen seconds" is an inconclusive result, and the receipt written for it
        must say so (``failed`` is not ``none`` — see ``platform/receipt.py``).
        *sleep* is injectable so tests do not wait in real time.
        """
        import time

        waiter = sleep or time.sleep
        deadline = time.time() + (self.poll_timeout if timeout is None else timeout)
        gap = self.poll_interval if interval is None else interval
        latest = self.read(probe)
        while not latest.seen and not latest.error:
            if time.time() >= deadline:
                break
            waiter(gap)
            latest = self.read(probe)
        return latest

    def close(self) -> None:
        if self._owned_client and self.client is not None:
            self.client.close()
            self._owned_client = False


@dataclass
class RecordedCollaborator:
    """An in-memory collaborator, for tests and offline replay.

    Implements the same three calls :class:`OobEffect` makes, so a test can drive
    the whole OOB path — probe URL, "the target fetched it", poll, observation —
    without Docker and without a socket.
    """

    interactions: list[dict] = field(default_factory=list)
    available: bool = True
    dns: bool = False

    def record(self, probe: str, *, path: str = "", method: str = "GET", source_ip: str = "10.0.0.1") -> None:
        """Simulate the target reaching the collaborator."""
        self.interactions.append(
            {
                "probe": probe,
                "path": path or f"/oob/{probe}",
                "method": method,
                "source_ip": source_ip,
                "user_agent": "",
                "at": float(len(self.interactions)),
            }
        )

    # --- the OobEffect surface ---

    def url_for(self, probe: str) -> str:
        return f"http://collaborator.test/oob/{probe}"

    def read(self, probe: str) -> RawOobFetch:
        rows = [row for row in self.interactions if row["probe"] == probe]
        return RawOobFetch(
            probe=probe,
            interactions=tuple(RawOobInteraction(**row) for row in rows),
        )

    def wait(self, probe: str, **_: Any) -> RawOobFetch:
        return self.read(probe)

    @property
    def capabilities(self) -> OobCapabilities:
        return OobCapabilities(
            available=self.available,
            dns=self.dns,
            public_base="http://collaborator.test",
            local_base="memory",
            reason="" if self.available else "recorded collaborator disabled",
        )

    def close(self) -> None:
        return None


__all__ = [
    "DEFAULT_LOCAL_BASE",
    "DEFAULT_POLL_INTERVAL",
    "DEFAULT_POLL_TIMEOUT",
    "DEFAULT_PUBLIC_BASE",
    "NAME",
    "OobCapabilities",
    "OobEffect",
    "RecordedCollaborator",
]
