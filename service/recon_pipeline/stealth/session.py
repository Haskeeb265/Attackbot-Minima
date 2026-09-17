"""The stealth chokepoint: identity + pacing + detection + quarantine, together.

Everything above this module — the DNS stages, the HTTP probe, any future
light-active source — goes through one place, so there is exactly one answer to
"how fast are we going, as whom, and what do we do when a target objects?".

The lifecycle of one request:

1. **Is the host even allowed?**  A quarantined host is refused before a packet
   is sent (``QuarantineBlocked``), and when the whole run has degraded to
   passive-only, every active request is refused (``PassiveOnly``).
2. **Wait.**  The per-host token bucket plus any cooldown decides the delay, and
   the delay is jittered so the timing is not a metronome.
3. **Send** through the selected transport, presenting this host's one stable
   identity.
4. **Classify** the response (WAF fingerprint, challenge markers, status) and
   feed it back: pacing backs off, and a trusted block quarantines the host —
   escalating to the WAF scope, and from there to passive-only, when many hosts
   behind the same WAF are being challenged.
5. **Save** quarantine state so the *next* run respects a cooldown it triggered.

The same session also owns the DNS plan (:meth:`plan_dns`), because the DNS
volume budget and the HTTP pacing are the same problem: how much traffic this
engagement may produce without becoming the story.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from . import detect, dns_budget as dns_budget_mod, settings as stealth_settings
from .identity import BrowserIdentity, IdentityPool
from .pacing import Clock, Pacer, PacerConfig, PacingBudgetExceeded, RealClock, jittered
from .quarantine import GLOBAL_SCOPE, Quarantine, host_scope
from .transport import Request, Response, Selection, Transport, select_transport

log = logging.getLogger("stealth.session")


class QuarantineBlocked(RuntimeError):
    """Raised instead of sending a request to a quarantined scope."""

    def __init__(self, host: str, scope: str) -> None:
        super().__init__(f"{host}: quarantined by {scope}")
        self.host = host
        self.scope = scope


class PassiveOnly(RuntimeError):
    """Raised when active technique is disabled for the whole run."""

    def __init__(self, reason: str = "passive-only mode") -> None:
        super().__init__(f"active request refused: {reason}")
        self.reason = reason


@dataclass
class StealthConfig:
    """All stealth knobs in one place, built from settings or passed explicitly."""

    qps: float = 2.0
    burst: float = 4.0
    jitter: float = 0.35
    backoff_base: float = 1.0
    backoff_factor: float = 2.0
    backoff_max: float = 60.0
    challenge_cooldown: float = 900.0
    max_requests_per_host: int = 500
    timeout: float = 10.0
    #: ``auto`` | ``curl_cffi`` | ``requests``
    transport: str = "auto"
    identity: str = ""
    identity_salt: str = ""
    passive_only: bool = False
    quarantine_path: Path | None = None
    quarantine_ttl: float = 3600.0
    quarantine_failures: int = 3
    dns_budget: dns_budget_mod.DnsBudget = field(default_factory=dns_budget_mod.DnsBudget)

    @classmethod
    def from_settings(cls, **overrides: object) -> "StealthConfig":
        """Read module defaults from the environment, then apply *overrides*."""
        base = cls(
            qps=stealth_settings.HOST_QPS,
            burst=stealth_settings.HOST_BURST,
            jitter=stealth_settings.JITTER,
            backoff_base=stealth_settings.BACKOFF_BASE,
            backoff_factor=2.0,
            backoff_max=stealth_settings.BACKOFF_MAX,
            identity=stealth_settings.IDENTITY,
            identity_salt=stealth_settings.IDENTITY_SALT,
            passive_only=stealth_settings.PASSIVE_ONLY,
            quarantine_path=stealth_settings.QUARANTINE_FILE,
            quarantine_ttl=float(stealth_settings.QUARANTINE_TTL),
            quarantine_failures=stealth_settings.QUARANTINE_FAILURES,
            dns_budget=dns_budget_mod.DnsBudget(
                names_per_resolver_hour=stealth_settings.DNS_NAMES_PER_RESOLVER_HOUR,
                qps=stealth_settings.DNS_QPS,
                batch_size=stealth_settings.DNS_BATCH_SIZE,
                batch_spacing=stealth_settings.DNS_BATCH_SPACING,
                shuffle=stealth_settings.DNS_SHUFFLE,
                seed=stealth_settings.DNS_SEED,
                jitter=stealth_settings.JITTER,
            ),
        )
        for key, value in overrides.items():
            if value is not None and hasattr(base, key):
                setattr(base, key, value)
        return base

    def pacer_config(self) -> PacerConfig:
        return PacerConfig(
            qps=self.qps,
            burst=self.burst,
            jitter=self.jitter,
            backoff_base=self.backoff_base,
            backoff_factor=self.backoff_factor,
            backoff_max=self.backoff_max,
            challenge_cooldown=self.challenge_cooldown,
            max_requests_per_host=self.max_requests_per_host,
        )


@dataclass
class Attempt:
    """One attempted request: what came back, and what we did about it."""

    response: Response
    verdict: detect.Verdict
    delay: float = 0.0
    quarantined: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "url": self.response.url,
            "status": self.response.status,
            "seconds": round(self.response.seconds, 2),
            "delay": round(self.delay, 2),
            "verdict": self.verdict.to_dict(),
        }


class StealthSession:
    """One paced, identity-coherent, block-aware session for a whole run."""

    def __init__(
        self,
        config: StealthConfig | None = None,
        *,
        clock: Clock | None = None,
        transport: Transport | None = None,
        selection: Selection | None = None,
        identity_pool: IdentityPool | None = None,
        quarantine: Quarantine | None = None,
    ) -> None:
        self.config = config or StealthConfig.from_settings()
        self.clock = clock or RealClock()
        self.pacer = Pacer(self.config.pacer_config(), clock=self.clock)
        self.identities = identity_pool or IdentityPool(
            salt=self.config.identity_salt,
            pinned=self.config.identity,
        )
        if transport is not None:
            self.transport: Transport = transport
            self.selection = selection or Selection(transport, "injected")
        else:
            self.selection = selection or select_transport(
                timeout=self.config.timeout,
                prefer=self.config.transport,
            )
            self.transport = self.selection.transport
        self.quarantine = quarantine or Quarantine(
            path=self.config.quarantine_path,
            ttl=self.config.quarantine_ttl,
            failures=self.config.quarantine_failures,
            passive_only=self.config.passive_only,
            clock=self.clock,
        )
        self.attempts: list[Attempt] = []
        self.dns_plans: list[dict[str, object]] = []
        self._dns_plan: dns_budget_mod.DnsPlan | None = None
        self.verdict_counts: dict[str, int] = {}
        if self.quarantine.passive_only:
            log.warning("stealth: running in PASSIVE-ONLY mode; active technique is disabled")

    # -- identity ----------------------------------------------------------- #

    def identity_for(self, host: str) -> BrowserIdentity:
        return self.identities.for_host(host)

    # -- gates -------------------------------------------------------------- #

    @property
    def passive_only(self) -> bool:
        return self.quarantine.passive_only

    def is_allowed(self, host: str) -> bool:
        """False when this host must not be contacted."""
        if self.passive_only:
            return False
        return not self.quarantine.is_host_quarantined(host)

    def blocked_hosts(self) -> list[str]:
        return sorted({host for host, state in self.pacer.stats()["hosts"].items() if state["blocks"]})

    # -- DNS planning ------------------------------------------------------- #

    def plan_dns(self, labels: list[str], resolvers: list[str], *, seed: str = "") -> dns_budget_mod.DnsPlan:
        """Shuffle + budget the candidate list before any query is sent."""
        plan = dns_budget_mod.plan(labels, resolvers, budget=self.config.dns_budget, seed=seed)
        self._dns_plan = plan
        self.dns_plans.append(plan.to_dict())
        if plan.notes:
            for note in plan.notes:
                log.warning("dns budget: %s", note)
        log.info(
            "dns plan: %d name(s) over %d resolver(s), max %d name(s)/resolver in %d batch(es)%s",
            len(plan.labels),
            plan.resolver_count,
            plan.max_per_resolver,
            len(plan.batches),
            "" if plan.within_budget else " [OVER BUDGET]",
        )
        return plan

    def dns_rate_limit(self, *, resolver_count: int = 0) -> int:
        """``--rate-limit`` for the resolver tools, derived from the same budget."""
        return dns_budget_mod.rate_limit_arg(budget=self.config.dns_budget, resolver_count=resolver_count)

    def pause_between_batches(self, index: int) -> float:
        """Jittered pause before a DNS batch, so a big list is not one burst."""
        delay = dns_budget_mod.batch_delay(
            index,
            budget=self.config.dns_budget,
            random_value=self.clock.random(),
        )
        if delay > 0:
            self.clock.sleep(delay)
            self.pacer.sleeps += 1
            self.pacer.slept_seconds += delay
        return delay

    def httpx_rate_limit(self) -> int:
        """Per-second rate to hand the httpx CLI (it has its own scheduler)."""
        return max(1, int(self.config.qps))

    def httpx_max_host_errors(self) -> int:
        """How many failures before the CLI skips a host rather than hammering it."""
        return max(1, int(self.config.max_requests_per_host / 100) or 1)

    # -- requests ----------------------------------------------------------- #

    def request(self, url: str, *, host: str = "", referer: str = "") -> Attempt:
        """Paced, identity-coherent, quarantine-aware single request."""
        request = Request(url=url, host=host, referer=referer)
        target = request.host

        if self.passive_only:
            raise PassiveOnly("quarantine escalated the run to passive-only")
        for scope in (host_scope(target), GLOBAL_SCOPE):
            if self.quarantine.is_quarantined(scope):
                raise QuarantineBlocked(target, scope)

        delay = self.pacer.acquire(target)
        response = self.transport.send(request, identity=self.identity_for(target))
        verdict = detect.classify(
            status=response.status,
            headers=response.headers,
            body=response.body,
            error=response.error,
        )
        attempt = Attempt(response=response, verdict=verdict, delay=delay)
        self._record(target, verdict, attempt)
        self.attempts.append(attempt)
        return attempt

    def record_probe(self, host: str, *, status: int | None, headers: dict[str, str] | None = None, body: str = "") -> detect.Verdict:
        """Classify a response observed elsewhere (e.g. the bulk httpx pass).

        The bulk pass is scheduled by the CLI, so it cannot be paced per request
        by this session — but its *outcomes* still have to feed detection and
        quarantine, or a blocked host would simply be probed again by the next
        step.
        """
        verdict = detect.classify(status=status, headers=headers or {}, body=body)
        self._record(host, verdict, None)
        return verdict

    def _record(self, host: str, verdict: detect.Verdict, attempt: Attempt | None) -> None:
        self.verdict_counts[verdict.kind] = self.verdict_counts.get(verdict.kind, 0) + 1
        self.pacer.record(host, verdict)

        if verdict.should_quarantine:
            entry = self.quarantine.record(host_scope(host), verdict, host=host)
            if entry is not None:
                log.warning(
                    "stealth: %s quarantined (%s from %s, %s incident(s), %.0fs)",
                    host,
                    verdict.kind,
                    verdict.waf or "unknown",
                    entry.incidents,
                    max(0.0, entry.expires_at - entry.first_seen),
                )
            waf_entry = self.quarantine.escalate_waf(verdict.waf or "", host=host)
            if waf_entry is not None and self.quarantine.passive_only:
                log.error(
                    "stealth: %s blocked %d host(s); degrading the run to passive-only",
                    waf_entry.waf,
                    len(waf_entry.hosts),
                )
                if attempt is not None:
                    attempt.quarantined = waf_entry.scope
            if attempt is not None and entry is not None:
                attempt.quarantined = entry.scope

    def save(self) -> Path | None:
        """Persist quarantine state (called at the end of a run)."""
        return self.quarantine.save()

    def close(self) -> None:
        try:
            self.transport.close()
        finally:
            self.save()

    # -- reporting ---------------------------------------------------------- #

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "transport": self.selection.transport.capabilities.to_dict(),
            "transport_reason": self.selection.reason,
            "installed": list(self.selection.installed),
            "identities": {
                "pool": [profile.name for profile in self.identities.profiles],
                "pinned": self.config.identity or None,
                "salt_set": bool(self.config.identity_salt),
            },
            "pacing": self.pacer.stats(),
            "verdicts": dict(sorted(self.verdict_counts.items())),
            "quarantine": self.quarantine.to_dict(),
            "passive_only": self.passive_only,
            "blocked_hosts": self.blocked_hosts(),
            "dns_budget": self.config.dns_budget.__dict__,
            "dns_plans": self.dns_plans[-4:],
        }
        if self._dns_plan is not None:
            payload["dns_plan"] = self._dns_plan.to_dict()
        return payload


def blocked_summary(session: StealthSession) -> str:
    """One-line summary of blocks, for logs."""
    counts = session.verdict_counts
    blocked = counts.get(detect.CHALLENGE, 0) + counts.get(detect.BLOCKED, 0)
    if not blocked:
        return "no blocks observed"
    parts = [f"{counts.get(detect.CHALLENGE, 0)} challenge(s)", f"{counts.get(detect.BLOCKED, 0)} block(s)"]
    if counts.get(detect.RATE_LIMITED):
        parts.append(f"{counts[detect.RATE_LIMITED]} rate limit(s)")
    return ", ".join(parts)


__all__ = [
    "Attempt",
    "PassiveOnly",
    "QuarantineBlocked",
    "StealthConfig",
    "StealthSession",
    "PacingBudgetExceeded",
    "blocked_summary",
    "jittered",
]
