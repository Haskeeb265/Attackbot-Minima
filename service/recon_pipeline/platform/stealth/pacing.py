"""Pacing: per-host token buckets, centred jitter, backoff and cooldowns.

Why pacing is the main event
----------------------------
Fingerprint spoofing gets a *connection* past inspection.  It does not make a
sequence of requests look human, and the sequence is where the detection lives:

* Cloudflare's published JA4 Signals are **inter-request** aggregates over the
  last hour of global traffic — how browser-like a fingerprint is, how much of
  its traffic is HTTP/2 or HTTP/3, how cacheable its responses are.  A client
  that behaves like a machine stays an outlier no matter what ClientHello it
  sends;
* published DNS analytics flag subdomain brute force at *volume* — more than
  ~75 unique names of one base domain per client per hour combined with a high
  NXDOMAIN share (see :mod:`..dns_budget`, which enforces the volume lever);
* perfectly regular timing is itself a signature.  Constant intervals mean
  "scheduler", so every delay here is jittered around its target rather than
  fixed.

What this module provides
-------------------------
* :class:`TokenBucket` — a sustained rate with a small burst allowance, so a
  host that is idle for a while may be fetched a few times quickly (like a page
  load) without the average climbing;
* :class:`Pacer` — per-host buckets, jittered delays, exponential backoff on
  failures, and cooldowns driven by ``Retry-After`` when a host says so;
* :class:`Clock` / :class:`FakeClock` — injectable time.  Every delay decision
  is deterministic under a fake clock, which is the only way to test pacing
  without real sleeping (and matches how the rest of this repo tests timing).
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Protocol

from . import detect


def jittered(delay: float, fraction: float, random_value: float) -> float:
    """Spread *delay* by ±*fraction* using an injected random value.

    Exposed as a function so every layer jitters the same way: the pacer, the
    DNS batch spacing, and any future caller.  Centred rather than full jitter,
    because full jitter can collapse a backoff to ~0 and waste the wait it was
    there to enforce.
    """
    if delay <= 0 or fraction <= 0:
        return max(0.0, delay)
    spread = delay * fraction
    return max(0.0, delay + (random_value * 2.0 - 1.0) * spread)


class Clock(Protocol):
    """Minimal time source, so pacing is testable without sleeping."""

    def now(self) -> float: ...

    def sleep(self, seconds: float) -> None: ...

    def random(self) -> float:
        """A value in ``[0, 1)``."""
        ...


class RealClock:
    """Monotonic wall clock plus the real sleep/random."""

    def now(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)

    def random(self) -> float:
        return random.random()


@dataclass
class FakeClock:
    """Deterministic clock: ``sleep`` advances time instead of waiting."""

    started: float = 0.0
    _random: random.Random = field(default_factory=lambda: random.Random(0), repr=False)
    slept: list[float] = field(default_factory=list)

    def now(self) -> float:
        return self.started

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.started += max(0.0, seconds)

    def random(self) -> float:
        return self._random.random()

    def advance(self, seconds: float) -> None:
        """Move time forward without recording a sleep."""
        self.started += seconds


@dataclass
class TokenBucket:
    """Sustained rate with a burst allowance (the classic two-parameter limit)."""

    rate: float
    burst: float
    clock: Clock
    tokens: float = field(default=0.0)
    updated: float = field(default=0.0)

    def __post_init__(self) -> None:
        if self.rate <= 0:
            raise ValueError("rate must be positive")
        if self.burst <= 0:
            raise ValueError("burst must be positive")
        self.tokens = self.burst
        self.updated = self.clock.now()

    def _refill(self) -> None:
        now = self.clock.now()
        elapsed = max(0.0, now - self.updated)
        if elapsed:
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.updated = now

    def time_until(self, tokens: float = 1.0) -> float:
        """Seconds until *tokens* are available (0 when they already are)."""
        self._refill()
        if self.tokens >= tokens:
            return 0.0
        return (tokens - self.tokens) / self.rate

    def take(self, tokens: float = 1.0) -> bool:
        """Consume *tokens* if available; otherwise leave the bucket alone."""
        self._refill()
        if self.tokens < tokens:
            return False
        self.tokens -= tokens
        return True


@dataclass
class PacerConfig:
    """Tuning for :class:`Pacer`, in plain values so tests can set them directly."""

    #: Sustained requests per second against one host.
    qps: float = 2.0
    #: Burst allowance per host.
    burst: float = 4.0
    #: Timing jitter as a fraction of the target delay (0 disables it).
    jitter: float = 0.35
    backoff_base: float = 1.0
    backoff_factor: float = 2.0
    backoff_max: float = 60.0
    #: Cooldown applied to a host that answered with a challenge and gave no
    #: ``Retry-After``; long on purpose, because a challenge means "stop".
    challenge_cooldown: float = 900.0
    #: Hard ceiling on requests this run may make to any single host.
    max_requests_per_host: int = 500

    def __post_init__(self) -> None:
        if not 0.0 <= self.jitter < 1.0:
            raise ValueError("jitter must be in [0, 1)")
        if self.backoff_factor < 1.0:
            raise ValueError("backoff_factor must be >= 1")


@dataclass
class HostState:
    """Per-host pacing state."""

    bucket: TokenBucket
    requests: int = 0
    failures: int = 0
    cooldown_until: float = 0.0
    blocks: int = 0

    @property
    def exhausted(self) -> bool:
        return False  # set by the Pacer via max_requests_per_host


class Pacer:
    """Per-host pacing with jitter, backoff and ``Retry-After`` cooldowns."""

    def __init__(self, config: PacerConfig | None = None, *, clock: Clock | None = None) -> None:
        self.config = config or PacerConfig()
        self.clock = clock or RealClock()
        self._hosts: dict[str, HostState] = {}
        self.requests = 0
        self.sleeps = 0
        self.slept_seconds = 0.0

    # -- internals ---------------------------------------------------------- #

    def state(self, host: str) -> HostState:
        key = host.strip().lower().rstrip(".")
        state = self._hosts.get(key)
        if state is None:
            state = HostState(
                bucket=TokenBucket(self.config.qps, self.config.burst, self.clock),
            )
            self._hosts[key] = state
        return state

    def _jittered(self, delay: float) -> float:
        return jittered(delay, self.config.jitter, self.clock.random())

    # -- public API --------------------------------------------------------- #

    def cooldown_remaining(self, host: str) -> float:
        return max(0.0, self.state(host).cooldown_until - self.clock.now())

    def budget_exhausted(self, host: str) -> bool:
        return self.state(host).requests >= self.config.max_requests_per_host

    def delay_for(self, host: str) -> float:
        """Seconds we must wait before the next request to *host* (may be 0)."""
        if self.budget_exhausted(host):
            return float("inf")
        delay = max(self.state(host).bucket.time_until(), self.cooldown_remaining(host))
        return self._jittered(delay)

    def acquire(self, host: str, *, tokens: float = 1.0) -> float:
        """Wait as needed, then consume a token.  Returns the delay applied.

        Raises :class:`PacingBudgetExceeded` when the host has already received
        its ceiling of requests for this run: stopping is the correct behaviour,
        and the caller reports it instead of silently probing more.
        """
        if self.budget_exhausted(host):
            raise PacingBudgetExceeded(host, self.config.max_requests_per_host)
        delay = self.delay_for(host)
        if delay > 0:
            self.clock.sleep(delay)
            self.sleeps += 1
            self.slept_seconds += delay
        state = self.state(host)
        state.bucket.take(tokens)
        state.requests += 1
        self.requests += 1
        return delay

    def record(self, host: str, verdict: detect.Verdict) -> float:
        """Feed a response back in; returns the cooldown applied (seconds).

        A rate limit or challenge pushes the host's next request out — by
        ``Retry-After`` when the host supplies one, otherwise by exponential
        backoff.  Repeated blocks escalate; a normal answer resets the streak so
        a single transient 503 does not leave a permanent shadow on a host.
        """
        state = self.state(host)
        if verdict.kind == detect.OK:
            state.failures = 0
            return 0.0

        state.failures += 1
        if verdict.kind in detect.QUARANTINE_KINDS:
            state.blocks += 1

        if verdict.retry_after is not None:
            cooldown = verdict.retry_after
        elif verdict.kind == detect.CHALLENGE:
            cooldown = min(
                self.config.challenge_cooldown * state.failures,
                self.config.backoff_max * 4,
            )
        else:
            cooldown = min(
                self.config.backoff_base * (self.config.backoff_factor ** (state.failures - 1)),
                self.config.backoff_max,
            )
        cooldown = self._jittered(cooldown)
        state.cooldown_until = max(state.cooldown_until, self.clock.now() + cooldown)
        return cooldown

    def stats(self) -> dict[str, object]:
        """Pacing summary for the run report."""
        hosts = {
            host: {
                "requests": state.requests,
                "failures": state.failures,
                "blocks": state.blocks,
                "cooldown_remaining": round(self.cooldown_remaining(host), 2),
            }
            for host, state in sorted(self._hosts.items())
        }
        return {
            "qps": self.config.qps,
            "burst": self.config.burst,
            "jitter": self.config.jitter,
            "requests": self.requests,
            "waits": self.sleeps,
            "waited_seconds": round(self.slept_seconds, 2),
            "hosts": hosts,
        }

    def to_dict(self) -> dict[str, object]:
        return self.stats()


class PacingBudgetExceeded(RuntimeError):
    """Raised instead of making more requests than a host's ceiling allows."""

    def __init__(self, host: str, limit: int) -> None:
        super().__init__(f"{host}: per-host request budget of {limit} exhausted")
        self.host = host
        self.limit = limit
