"""The authorization verifier: fresh identities, flipped order, no re-reading.

A differential claim is self-confirming the moment the verifier reads the
proposer's numbers: "session B got a 200" re-examined by whoever asked for it
is an opinion with a receipt. This verifier never sees those numbers. Its
input from the candidate is the confirmation spec — which URL, and nothing
else — and it re-asks the target itself, through the policy gate, under both
declared identities, **in the flipped order**: session B first, session A
second. Flipping the order is what makes the confirmation a different
measurement in kind — a cache, a flaky proxy, or an ordering artifact that
produced the proposer's pair will not reproduce it in reverse.

The oracle (``DIFFERENTIAL_SESSIONS`` — "two sessions, one object") needs
both directions to agree:

* **B allowed, A allowed** — both fresh measurements succeeded for the same
  object: the access boundary the operator declared is genuinely absent.
* **B denied on the flip** — the proposer's pair does not reproduce, and the
  claim is refused with the fresh statuses named. A one-off pair is not a
  finding.

Anything else (a measurement error, a gate refusal) is *inconclusive*, not
a refutation — the same honesty rule the timing verifier applies.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from urllib.parse import urlsplit

from ..kernel.evidence import (
    DIFFERENTIAL_SESSIONS,
    EVIDENCE_DIFFERENTIAL,
    Evidence,
)
from ..kernel.exchange import RawHttpExchange
from ..kernel.observation import OBS_HTTP_RESPONSE
from ..kernel.verdict import Candidate, Verdict, refuse
from ..policy.gate import EffectRequest, PolicyGate

#: Confirmation-spec kind this verifier answers.  Must equal the technique's
#: ``confirm["kind"]``; pinned by a test so the two cannot drift.
CONFIRM_KIND = "authorization.differential"

#: Status buckets, shared spelling with the technique's interpret module.
_ALLOWED = range(200, 300)
_DENIED = {301, 302, 303, 307, 308, 401, 403, 404}


@dataclass
class AuthorizationVerifier:
    """Confirms an authorization claim by re-asking both identities, flipped."""

    gate: PolicyGate

    def verify(self, candidate: Candidate) -> Verdict:
        """Confirm or refuse *candidate*.  Never raises for an ordinary failure."""
        confirm = dict(candidate.confirm or {})
        if confirm.get("kind") != CONFIRM_KIND:
            return refuse(
                candidate,
                "the proposer offered no authorization-differential confirmation "
                "for this candidate, and a session claim cannot be established "
                "any other way",
            )
        url = str(confirm.get("url") or "")
        oracle = str(confirm.get("oracle") or "")
        if not url:
            return refuse(candidate, "the confirmation spec names no URL to re-measure")
        if oracle != DIFFERENTIAL_SESSIONS:
            return refuse(
                candidate,
                f"the confirmation spec's oracle is {oracle!r}, not "
                f"{DIFFERENTIAL_SESSIONS!r}: the two sides cannot drift silently",
            )

        # Flipped order, deliberately: the proposer measured A then B; the
        # verifier measures B then A. Fresh requests, fresh identities.
        status_b = self._measure(url, session="b", probe=candidate.id)
        status_a = self._measure(url, session=None, probe=candidate.id)
        if status_b is None or status_a is None:
            return refuse(
                candidate,
                "a flipped measurement failed before both identities answered, so "
                "the claim is inconclusive rather than refuted",
            )
        at = self.gate.now()
        evidence = Evidence(
            kind=OBS_HTTP_RESPONSE,
            grade=EVIDENCE_DIFFERENTIAL,
            probe=str(confirm.get("probe") or candidate.id),
            at=at,
            payload={
                "oracle": DIFFERENTIAL_SESSIONS,
                "flipped_session_a_status": status_a,
                "flipped_session_b_status": status_b,
                "url": url,
                "reason": "fresh two-session measurement through the policy gate, flipped order",
            },
        )
        b_allowed = status_b in _ALLOWED
        a_allowed = status_a in _ALLOWED
        if b_allowed and a_allowed:
            Verdict.check_independence(candidate.proposer_grade, evidence)
            return Verdict(
                candidate_id=candidate.id,
                proven=True,
                evidence=evidence,
                reason=(
                    f"fresh flipped measurement: session B answered {status_b} and "
                    f"session A answered {status_a} for the same object — the "
                    "declared access boundary is absent"
                ),
                proposer_grade=candidate.proposer_grade,
            )
        if status_b in _DENIED:
            return refuse(
                candidate,
                (
                    f"the flipped measurement denied session B (status {status_b}): "
                    "the proposer's pair did not reproduce, and a one-off pair is "
                    "not a finding"
                ),
            )
        return refuse(
            candidate,
            (
                f"the flipped measurement produced statuses A={status_a}, B={status_b}, "
                "which neither proves nor refutes the claim — inconclusive"
            ),
        )

    # ------------------------------------------------------------------ #
    # measurement
    # ------------------------------------------------------------------ #

    def _measure(self, url: str, *, session: str | None, probe: str) -> int | None:
        """One fresh request under one identity; the status, or ``None``."""
        detail: dict = {"url": url, "method": "GET"}
        if session:
            detail["_session"] = session
        outcome = self.gate.run(
            EffectRequest(
                kind="http.request",
                host=(urlsplit(url).hostname or "").lower(),
                detail=detail,
                technique="authorization_verifier",
                probe=probe,
            )
        )
        if not outcome.executed:
            return None
        exchange: RawHttpExchange = outcome.effect
        if not exchange.ok:
            return None
        return exchange.status


__all__ = ["CONFIRM_KIND", "AuthorizationVerifier"]
