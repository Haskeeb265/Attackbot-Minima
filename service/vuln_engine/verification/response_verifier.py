"""The response-differential verifier: the classic answer to ``differential.response``.

Route-parity work (batch 2, Phase 3): the two-gate flow has answered this confirm
kind since its first routines (``method_confusion.response.v1`` and
``path_traversal.response.v1``), but the classic layer had no verifier for it, so
a classic technique proposing one would have been a dead arm — proposed, refused
by the dispatcher, never provable. This verifier closes that: the classic path
can now answer ``differential.response`` with the same confirm kind the two-gate
routine uses, measured by the same response-differential semantics. (No classic
folder proposes it yet — adding one is vuln-class breadth, out of batch-2 scope;
the route-parity test records the exclusion so the gap stays named.)

The proof it applies is the response-differential oracle's own semantics: the
injected population must differ from the baseline **and** from the control — a
plain baseline difference is what an ordinary reflecting parameter produces, so
the control is what makes "changed" mean more than "echoed". The comparison
reduces each fresh response to the same three fields the two-gate oracle reads
(status, length beyond the declared delta, body hash); the two implementations
are pinned against each other by the route-parity test, the same convention as
the timing verifier's pinned fallback payloads.

Fresh measurements through the gate, never the proposer's numbers; a failed
population is inconclusive, not a refutation; and the evidence carries statuses,
lengths and hashes — bytes are dropped once hashed, like every verifier's.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from urllib.parse import urlsplit

from ..kernel.confirm import ConfirmSpec
from ..kernel.evidence import EVIDENCE_DIFFERENTIAL, Evidence
from ..kernel.observation import OBS_HTTP_RESPONSE
from ..kernel.technique import Surface
from ..kernel.verdict import Candidate, Verdict, refuse
from ..policy.gate import EffectRequest, PolicyGate
from ..techniques.common import json_body_request, with_parameter

#: Confirmation-spec kind this verifier answers. Must equal the technique's
#: ``confirm["kind"]`` and the two-gate routine's; pinned by the route-parity test.
CONFIRM_KIND = "differential.response"

#: Fresh samples per population. Two per side survives one outlier; the control
#: population does the discriminating work.
SAMPLES = 2


@dataclass(frozen=True)
class _Population:
    """One population, reduced to the three fields the comparison reads.

    The exchange's bytes live exactly as long as hashing takes; only these
    reduced fields travel on, the same reduction ``twogate.spec`` applies.
    """

    status: int | None
    length: int
    body_hash: str


def _differs(
    left_status: int | None,
    left_length: int,
    left_hash: str,
    right_status: int | None,
    right_length: int,
    right_hash: str,
    length_delta: int,
) -> bool:
    """The response-differential comparison, on reduced fields.

    Mirrors ``twogate.spec._differs`` field for field (status, then length
    beyond the delta, then body hash) — the two implementations are pinned to
    each other by the route-parity test so neither can drift.
    """
    if left_status != right_status:
        return True
    if abs(left_length - right_length) > length_delta:
        return True
    return bool(left_hash) and left_hash != right_hash


@dataclass
class DifferentialResponseVerifier:
    """Confirms a response-differential claim by re-measuring all populations."""

    gate: PolicyGate

    def verify(self, candidate: Candidate) -> Verdict:
        """Confirm or refuse *candidate*. Never raises for an ordinary failure."""
        if str((candidate.confirm or {}).get("kind") or "") != CONFIRM_KIND:
            return refuse(
                candidate,
                "the proposer offered no response-differential confirmation for this "
                "candidate, and a response claim cannot be established any other way",
            )
        spec = ConfirmSpec.from_confirm(candidate.confirm)
        return self.confirm(
            spec, candidate_id=candidate.id, proposer_grade=candidate.proposer_grade
        )

    def confirm(
        self, spec: ConfirmSpec, *, candidate_id: str, proposer_grade: str = "hypothesis"
    ) -> Verdict:
        """Confirm the claim *spec* describes, for whichever runtime sent it."""
        if spec.kind != CONFIRM_KIND:
            return self._refuse(
                candidate_id,
                proposer_grade,
                "the proposer offered no response-differential confirmation for this "
                "candidate, and a response claim cannot be established any other way",
            )
        url = spec.url
        param = spec.param
        if not url or not param:
            return self._refuse(
                candidate_id,
                proposer_grade,
                "the confirmation spec names no surface or parameter",
            )
        baseline_payload = spec.baseline_payload
        injected_payload = spec.injected_payload
        control_payload = spec.control_payload
        if not baseline_payload or not injected_payload:
            return self._refuse(
                candidate_id,
                proposer_grade,
                "the confirmation spec names no baseline or injected population",
            )

        baseline = self._measure(url, param, baseline_payload, spec.probe or candidate_id, spec)
        if baseline is None:
            return self._refuse(
                candidate_id,
                proposer_grade,
                "the baseline population failed before it was complete, so the claim "
                "is inconclusive rather than refuted",
            )
        control = (
            self._measure(url, param, control_payload, spec.probe or candidate_id, spec)
            if control_payload
            else None
        )
        if control_payload and control is None:
            return self._refuse(
                candidate_id,
                proposer_grade,
                "the control population failed before it was complete, so the claim "
                "is inconclusive rather than refuted",
            )
        injected = self._measure(url, param, injected_payload, spec.probe or candidate_id, spec)
        if injected is None:
            return self._refuse(
                candidate_id,
                proposer_grade,
                "the injected population failed before it was complete, so the claim "
                "is inconclusive rather than refuted",
            )

        length_delta = 0
        if not _differs(
            injected.status,
            injected.length,
            injected.body_hash,
            baseline.status,
            baseline.length,
            baseline.body_hash,
            length_delta,
        ):
            return self._refuse(
                candidate_id,
                proposer_grade,
                (
                    "the injected value's response matched the baseline's "
                    f"(status {baseline.status}, {baseline.length} bytes): a value "
                    "that changes nothing is not a traversal or a response "
                    "differential"
                ),
            )
        if control is not None and not _differs(
            injected.status,
            injected.length,
            injected.body_hash,
            control.status,
            control.length,
            control.body_hash,
            length_delta,
        ):
            return self._refuse(
                candidate_id,
                proposer_grade,
                (
                    "the injected value's response differed from the baseline but "
                    "matched the control's: an ordinary malformed-but-benign value "
                    "produces the same answer, so this is not a response "
                    "differential"
                ),
            )

        at = self.gate.now()
        evidence = Evidence(
            kind=OBS_HTTP_RESPONSE,
            grade=EVIDENCE_DIFFERENTIAL,
            probe=spec.probe or candidate_id,
            at=at,
            payload={
                "baseline_status": baseline.status,
                "control_status": control.status if control is not None else None,
                "injected_status": injected.status,
                "baseline_length": baseline.length,
                "control_length": control.length if control is not None else None,
                "injected_length": injected.length,
                "baseline_body_hash": baseline.body_hash,
                "control_body_hash": control.body_hash if control is not None else "",
                "injected_body_hash": injected.body_hash,
                "baseline_payload": baseline_payload,
                "control_payload": control_payload,
                "injected_payload": injected_payload,
                "samples_per_population": SAMPLES,
                "reason": (
                    "fresh response-differential measurement through the policy gate: "
                    "the injected population differed from the baseline and from the "
                    "control"
                ),
            },
        )
        Verdict.check_independence(proposer_grade, evidence)
        return Verdict(
            candidate_id=candidate_id,
            proven=True,
            evidence=evidence,
            reason=(
                "fresh response differential: the injected value answered "
                f"{injected.status} ({injected.length} bytes) where the baseline "
                f"answered {baseline.status} ({baseline.length} bytes)"
                + (
                    f" and the control answered {control.status} ({control.length} bytes)"
                    if control is not None
                    else ""
                )
            ),
            proposer_grade=proposer_grade,
        )

    # ------------------------------------------------------------------ #
    # measurement
    # ------------------------------------------------------------------ #

    def _measure(
        self, url: str, param: str, payload: str, probe: str, spec: ConfirmSpec
    ) -> _Population | None:
        """One population's fresh response, reduced — or ``None`` when it failed."""
        if spec.where == "body":
            spec_surface = Surface(
                url=url,
                host=(urlsplit(url).hostname or "").lower(),
                param=param,
                companions=dict(spec.companions),
            )
            request_url, headers, content = json_body_request(spec_surface, param, payload)
            detail: dict = {
                "url": request_url,
                "method": "POST",
                "headers": headers,
                "content": content,
            }
        else:
            detail = {"url": with_parameter(url, param, payload), "method": "GET"}
        outcome = self.gate.run(
            EffectRequest(
                kind="http.request",
                host=(urlsplit(url).hostname or "").lower(),
                detail=detail,
                technique="response_verifier",
                probe=probe,
            )
        )
        if not outcome.executed:
            return None
        exchange = outcome.effect
        if not exchange.ok:
            return None
        body: bytes = exchange.body or b""
        digest = hashlib.sha256(body).hexdigest()[:16]
        return _Population(status=exchange.status, length=len(body), body_hash=digest)

    @staticmethod
    def _refuse(candidate_id: str, proposer_grade: str, reason: str) -> Verdict:
        return Verdict(
            candidate_id=candidate_id,
            proven=False,
            reason=reason,
            proposer_grade=proposer_grade,
        )


__all__ = ["CONFIRM_KIND", "DifferentialResponseVerifier", "SAMPLES"]
