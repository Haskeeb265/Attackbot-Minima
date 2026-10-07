"""The authorization verifier: fresh identities, flipped order, no re-reading.

A differential claim is self-confirming the moment the verifier reads the
proposer's numbers: "session B got a 200" re-examined by whoever asked for it
is an opinion with a receipt. This verifier never sees those numbers. Its input
is the shared confirmation spec (``kernel.confirm.ConfirmSpec``) — which URL,
and nothing else — and it re-asks the target itself, through the policy gate,
under both declared identities, **in the flipped order**: session B first,
session A second. Flipping the order is what makes the confirmation a different
measurement in kind — a cache, a flaky proxy, or an ordering artifact that
produced the proposer's pair will not reproduce it in reverse.

Both runtimes reach it through the same door: the classic path projects a
candidate's ``confirm`` dict onto the shared spec (``verify``), and the two-gate
runner projects its ``ConfirmationSpec`` onto the same shape and calls
``confirm`` directly — which is what closed the rigor gap between the two
flows' identically-labelled authorization findings.

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

import hashlib
import statistics
from dataclasses import dataclass
from urllib.parse import urlsplit

from ..kernel.claim import (
    CLAIM_SHAPES,
    CLAIM_STATE_CHANGE,
    STATE_CHANGE_MISROUTE_REASON,
    is_differential_provable,
)
from ..kernel.confirm import ConfirmSpec
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

#: Content comparison. A 200 that carries a *different representation* than the
#: owner's is not access to the object — generic success envelopes, redacted
#: bodies and empty shells are all "200". The verifier therefore compares B's
#: body against A's on the same object by exact hash first and length second:
#: identical content is the strongest corroboration (the same bytes crossed the
#: boundary), and a materially shorter body is the classic partial/redacted
#: answer, refused rather than promoted. Length changes below the fraction are
#: treated as representation noise (dynamic tokens, timestamps), not as
#: evidence either way.
_EMPTY_LENGTH = 0
_LENGTH_DELTA_FRACTION = 0.5


@dataclass
class AuthorizationVerifier:
    """Confirms an authorization claim by re-asking both identities, flipped."""

    gate: PolicyGate

    def verify(self, candidate: Candidate) -> Verdict:
        """Confirm or refuse *candidate*.  Never raises for an ordinary failure."""
        if str((candidate.confirm or {}).get("kind") or "") != CONFIRM_KIND:
            return refuse(
                candidate,
                "the proposer offered no authorization-differential confirmation "
                "for this candidate, and a session claim cannot be established "
                "any other way",
            )
        spec = ConfirmSpec.from_confirm(candidate.confirm)
        return self.confirm(
            spec, candidate_id=candidate.id, proposer_grade=candidate.proposer_grade
        )

    def confirm(
        self, spec: ConfirmSpec, *, candidate_id: str, proposer_grade: str = "hypothesis"
    ) -> Verdict:
        """Confirm the claim *spec* describes, for whichever runtime sent it.

        The one measurement policy, reached from both runtimes: the classic
        path projects ``Candidate.confirm`` onto the shared spec, the two-gate
        runner projects its ``ConfirmationSpec`` — and both then get the same
        flipped-order, content-comparing proof, so an authorization finding
        means the same thing no matter which flow proposed it.
        """
        url = spec.url
        oracle = spec.oracle
        if spec.kind != CONFIRM_KIND:
            return self._refuse(
                candidate_id,
                proposer_grade,
                "the proposer offered no authorization-differential confirmation "
                "for this candidate, and a session claim cannot be established "
                "any other way",
            )
        if not url:
            return self._refuse(
                candidate_id, proposer_grade, "the confirmation spec names no URL to re-measure"
            )
        if oracle != DIFFERENTIAL_SESSIONS:
            return self._refuse(
                candidate_id,
                proposer_grade,
                f"the confirmation spec's oracle is {oracle!r}, not "
                f"{DIFFERENTIAL_SESSIONS!r}: the two sides cannot drift silently",
            )

        # The claim-shape routing rule (NOVELTY.md §7.2, kernel/claim.py). This
        # verifier's flipped re-measure observes the read under two sessions;
        # it never re-executes a change. A state_change claim ("the change at
        # T reaches V") is provable today — by the setup-re-executing confirm
        # kind (``authorization.state_change``) — but *not by this verifier*:
        # a ``proven`` verdict here would score the weaker, often-legitimate
        # claim "B can read V" at the strongest grade. So the shape is refused
        # with the misroute reason, which names the verifier that does prove
        # it — loudly, never silently downgraded. Legacy specs with no shape
        # are grandfathered: every hand-written technique (IDOR) predates
        # shapes and proves exactly what this verifier measures.
        claim_shape = spec.claim_shape
        if claim_shape and claim_shape not in CLAIM_SHAPES:
            return self._refuse(
                candidate_id,
                proposer_grade,
                f"the confirmation spec's claim_shape {claim_shape!r} is not one "
                f"the engine speaks: {', '.join(CLAIM_SHAPES)}",
            )
        if claim_shape == CLAIM_STATE_CHANGE:
            return self._refuse(candidate_id, proposer_grade, STATE_CHANGE_MISROUTE_REASON)
        if claim_shape and not is_differential_provable(claim_shape):
            return self._refuse(
                candidate_id,
                proposer_grade,
                f"no verifier proves the {claim_shape!r} claim shape at "
                "differential today",
            )

        # Flipped order, deliberately: the proposer measured A then B; the
        # verifier measures B then A. Fresh requests, fresh identities — and,
        # since the status code alone cannot tell "the object" from "a generic
        # 200 envelope", each measurement keeps its body long enough to hash
        # and size it, then drops it. The bodies are never logged, never
        # carried on the evidence: only their hashes and lengths are.
        b_response = self._measure(url, session="b", probe=spec.probe or candidate_id)
        a_response = self._measure(url, session=None, probe=spec.probe or candidate_id)
        if b_response is None or a_response is None:
            return self._refuse(
                candidate_id,
                proposer_grade,
                "a flipped measurement failed before both identities answered, so "
                "the claim is inconclusive rather than refuted",
            )
        status_b = b_response.status
        status_a = a_response.status
        at = self.gate.now()
        length_a = len(a_response.body)
        length_b = len(b_response.body)
        hash_a = hashlib.sha256(a_response.body).hexdigest()
        hash_b = hashlib.sha256(b_response.body).hexdigest()
        same_content = hash_a == hash_b
        evidence = Evidence(
            kind=OBS_HTTP_RESPONSE,
            grade=EVIDENCE_DIFFERENTIAL,
            probe=spec.probe or candidate_id,
            at=at,
            payload={
                "oracle": DIFFERENTIAL_SESSIONS,
                "flipped_session_a_status": status_a,
                "flipped_session_b_status": status_b,
                "url": url,
                "session_a_body_length": length_a,
                "session_b_body_length": length_b,
                "session_a_body_hash": hash_a,
                "session_b_body_hash": hash_b,
                "same_content": same_content,
                "reason": (
                    "fresh two-session measurement through the policy gate, flipped "
                    "order, compared by status and by content hash/length"
                ),
            },
        )
        b_allowed = status_b in _ALLOWED
        a_allowed = status_a in _ALLOWED
        if b_allowed and a_allowed:
            # Both 200 — now the content question, the one a status-only
            # verifier could not ask. B's 200 must carry the *object*, not an
            # empty shell or a generic envelope.
            if length_b == _EMPTY_LENGTH:
                return self._refuse(
                    candidate_id,
                    proposer_grade,
                    (
                        f"session B answered {status_b} with an empty body: a 200 that "
                        "carries nothing is not access to the object — partial, "
                        "redacted or generic responses are not a boundary failure"
                    ),
                )
            if not same_content:
                fraction = abs(length_a - length_b) / max(length_a, length_b, 1)
                if fraction >= _LENGTH_DELTA_FRACTION:
                    return self._refuse(
                        candidate_id,
                        proposer_grade,
                        (
                            f"session B's body differs materially from session A's "
                            f"({length_b} vs {length_a} bytes, {fraction:.0%}): a 200 "
                            "that carries a different representation is not proven "
                            "access to the object"
                        ),
                    )
            Verdict.check_independence(proposer_grade, evidence)
            return Verdict(
                candidate_id=candidate_id,
                proven=True,
                evidence=evidence,
                reason=(
                    f"fresh flipped measurement: session B answered {status_b} and "
                    f"session A answered {status_a} for the same object with "
                    + (
                        "identical content"
                        if same_content
                        else f"equivalent content ({length_b} vs {length_a} bytes)"
                    )
                    + " — the declared access boundary is absent"
                ),
                proposer_grade=proposer_grade,
            )
        if status_b in _DENIED:
            return self._refuse(
                candidate_id,
                proposer_grade,
                (
                    f"the flipped measurement denied session B (status {status_b}): "
                    "the proposer's pair did not reproduce, and a one-off pair is "
                    "not a finding"
                ),
            )
        return self._refuse(
            candidate_id,
            proposer_grade,
            (
                f"the flipped measurement produced statuses A={status_a}, B={status_b}, "
                "which neither proves nor refutes the claim — inconclusive"
            ),
        )

    @staticmethod
    def _refuse(candidate_id: str, proposer_grade: str, reason: str) -> Verdict:
        """The shared-spec refusal shape: not proven, with the reason."""
        return Verdict(
            candidate_id=candidate_id,
            proven=False,
            reason=reason,
            proposer_grade=proposer_grade,
        )

    # ------------------------------------------------------------------ #
    # measurement
    # ------------------------------------------------------------------ #

    def _measure(
        self, url: str, *, session: str | None, probe: str
    ) -> RawHttpExchange | None:
        """One fresh request under one identity; the exchange, or ``None``.

        The exchange (not just the status) is what the content comparison
        needs; the bodies it carries live exactly as long as hashing takes and
        are then dropped — the evidence carries hashes and lengths only.
        """
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
        return exchange


__all__ = ["CONFIRM_KIND", "AuthorizationVerifier"]
