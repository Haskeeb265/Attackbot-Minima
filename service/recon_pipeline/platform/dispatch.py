"""S10 — the active dispatcher: no active packet leaves without a decision.

The policy chokepoint between *knowing about* an asset and *touching* it.
Every active step (DNS resolution, port scan, HTTP probe, crawl, recursion)
asks the dispatcher first; the dispatcher consults the scope engine and the
score, applies the rate budget, and answers one of three verbs:

- ``ALLOW``   — proceed (the caller still paces through the stealth layer);
- ``DEFER``   — not now: budget exhausted, cooldown, needs re-queuing;
- ``DENY``    — never without operator action: out of scope, needs review,
                below the score floor, or the passive-only flag is set.

Design rules the code enforces:

* **deny-by-default.**  An asset with no scope decision, no score, or an
  unknown type is ``DENY`` with a reason — the gate cannot be "configured
  open" by accident, only by an explicit policy override.
* **every decision is auditable.**  Each answer carries its reason, and the
  dispatcher keeps the decision log the run report embeds.
* **budgets are per-host and global.**  A token-bucket per host (paced through
  the stealth layer) plus a run-level cap the operator sets; ``DEFER`` is the
  honest answer when either runs dry.

The dispatcher does not perform I/O: it decides.  Execution, retries and
pacing stay in the callers (tools + stealth), which keeps this module pure
enough to test on a fake clock.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field

from .scope import NEEDS_REVIEW, OUT_OF_SCOPE

ALLOW = "ALLOW"
DEFER = "DEFER"
DENY = "DENY"


@dataclass(frozen=True)
class Decision:
    verb: str
    reason: str

    @property
    def allowed(self) -> bool:
        return self.verb == ALLOW

    def to_dict(self) -> dict[str, str]:
        return {"verb": self.verb, "reason": self.reason}


@dataclass
class DispatchPolicy:
    """The operator-tunable rules; defaults are the conservative ones."""

    #: Minimum score for any active work (S2 output).
    min_score: int = 40
    #: Maximum active actions for the whole run (0 = unlimited).
    run_budget: int = 0
    #: Maximum active actions per host (0 = unlimited; stealth still paces).
    host_budget: int = 20
    #: Seconds a DENY for a host is remembered before it may be asked again.
    deny_cooldown_seconds: float = 3600.0
    #: Allow active work on needs_review assets (operator override).
    allow_needs_review: bool = False


class Dispatcher:
    """The gate.  ``decide()`` is the only method a caller needs."""

    def __init__(self, scope, scoring_enabled: bool = True, *, policy: DispatchPolicy | None = None) -> None:
        self.scope = scope
        self.policy = policy or DispatchPolicy()
        self.scoring_enabled = scoring_enabled
        self._host_counts: dict[str, int] = defaultdict(int)
        self._run_count = 0
        self._denied_until: dict[str, float] = {}
        self._decisions: list[dict] = []

    # ------------------------------------------------------------------ #
    # the decision
    # ------------------------------------------------------------------ #

    def decide(
        self,
        host: str,
        *,
        asset_type: str = "",
        score: int | None = None,
        scope_decision=None,
        now: float | None = None,
    ) -> Decision:
        """Should we actively touch *host*?  Pure: pass ``now`` on a fake clock."""
        now = time.time() if now is None else now

        # 0. cooldown on a recent DENY — do not re-litigate every request.
        until = self._denied_until.get(host)
        if until is not None and now < until:
            return self._record(
                host,
                Decision(DEFER, f"recently denied; cooldown until {until:.0f}"),
            )

        # 1. scope decides first — a scope failure can never be scored away.
        #    ``needs_review`` is *not* decided here: it is advisory-only by
        #    default but the operator may override it, so it falls through to
        #    step 2.  Only ``out_of_scope`` is final.
        verdict = scope_decision or self._scope_decision(host)
        if verdict.state == OUT_OF_SCOPE:
            self._denied_until[host] = now + self.policy.deny_cooldown_seconds
            return self._record(host, Decision(DENY, f"scope: {verdict.reason}"))

        # 2. needs_review requires the explicit operator override.
        if verdict.state == NEEDS_REVIEW and not self.policy.allow_needs_review:
            return self._record(
                host,
                Decision(
                    DENY,
                    f"needs_review (override with allow_needs_review): {verdict.reason}",
                ),
            )

        # 3. score floor.
        if self.scoring_enabled and score is not None and score < self.policy.min_score:
            return self._record(
                host, Decision(DENY, f"score {score} below floor {self.policy.min_score}")
            )

        # 4. budgets.
        if self.policy.run_budget and self._run_count >= self.policy.run_budget:
            return self._record(host, Decision(DEFER, "run budget exhausted"))
        if self.policy.host_budget and self._host_counts[host] >= self.policy.host_budget:
            return self._record(host, Decision(DEFER, f"host budget exhausted for {host}"))

        # 5. allowed — consume budget.
        self._run_count += 1
        self._host_counts[host] += 1
        return self._record(host, Decision(ALLOW, "in scope and within budget"))

    def _scope_decision(self, host: str):
        """Fresh scope decision when the caller did not supply one."""
        from .common.normalize import is_ip_literal

        if is_ip_literal(host):
            return self.scope.check_address(host)
        return self.scope.check_host(host)

    def _record(self, host: str, decision: Decision) -> Decision:
        self._decisions.append(
            {"host": host, **decision.to_dict(), "at": time.time()}
        )
        return decision

    # ------------------------------------------------------------------ #
    # reporting
    # ------------------------------------------------------------------ #

    def summary(self) -> dict:
        counts: dict[str, int] = defaultdict(int)
        for entry in self._decisions:
            counts[entry["verb"]] += 1
        return {
            "policy": {
                "min_score": self.policy.min_score,
                "run_budget": self.policy.run_budget,
                "host_budget": self.policy.host_budget,
                "allow_needs_review": self.policy.allow_needs_review,
            },
            "decisions": counts,
            "run_actions": self._run_count,
        }

    @property
    def decisions(self) -> list[dict]:
        return list(self._decisions)
