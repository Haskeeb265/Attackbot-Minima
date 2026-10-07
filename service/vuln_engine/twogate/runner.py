"""The ConfirmationSpecRunner: execute a declarative spec, apply the oracle.

This is the only module in the two-gate flow that sends traffic, and it sends it
exclusively through :class:`~..policy.gate.PolicyGate` — the same chokepoint every
other probe uses. It never calls a model, never reads a clock into a pure
decision (the gate's clock stamps the effects), and never decides a verdict by
any means other than a deterministic oracle over measured features.

The independence property it implements: the runner reads the *spec* and nothing
else. The proposer's rationale, confidence, or numbers are unreachable from here,
which is what stops a proposal from being re-read as its own proof.

**One measurement policy, two runtimes (gap-closure batch 2, Phase 1).** The
timing and authorization routes no longer measure here: they project the spec
onto the kernel's shared :class:`~..kernel.confirm.ConfirmSpec` and delegate to
the classic :class:`~..verification.timing_verifier.TimingVerifier` /
:class:`~..verification.authorization_verifier.AuthorizationVerifier`. Before
this, a two-gate timing finding proved only "the populations separated" and a
two-gate authorization finding proved only "the sessions differed" — weaker than
the identically-labelled classic findings, which add a dose-response
discrimination and a content comparison. Delegation means both runtimes' findings
rest on the same evidence, and the runner keeps only the routes the classic
layer does not have (``differential.extraction``/``differential.response``, plus
the browser and OOB routes, which are the same transports but a declarative-spec
interface).
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ..kernel.evidence import EVIDENCE_HYPOTHESIS
from ..kernel.exchange import RawHttpExchange
from ..kernel.technique import Surface, oob_sentinel
from ..kernel.verdict import Verdict
from ..policy.gate import EffectRequest, PolicyGate
from ..techniques.common import json_body_request, with_parameter
from ..verification.authorization_verifier import AuthorizationVerifier
from ..verification.timing_verifier import TimingVerifier
from .spec import (
    ConfirmationResult,
    ConfirmationSpec,
    Features,
    OracleContext,
    apply_oracle,
    feature_from_browser,
    feature_from_exchange,
)

#: The confirm kinds this runner answers through the classic verifiers, and the
#: kinds only this runner answers. The verification registry's alignment check
#: takes this tuple, so a kind handled here but unlisted in the registry is a
#: test failure, the same way an unlisted classic kind is.
TWOGATE_CONFIRM_KINDS: tuple[str, ...] = (
    "browser.run",
    "oob.read",
    "authorization.differential",
    "timing.differential",
    "differential.extraction",
    "differential.response",
)


class ConfirmationSpecRunner:
    """Runs one spec and returns whether its pre-declared oracle held."""

    def __init__(self, gate: PolicyGate) -> None:
        self.gate = gate

    # ------------------------------------------------------------------ #
    # the entry point
    # ------------------------------------------------------------------ #

    def run(self, spec: ConfirmationSpec) -> ConfirmationResult:
        """Execute *spec* and answer with the oracle's boolean, or a refusal."""
        if spec.kind == "browser.run":
            return self._run_browser(spec)
        if spec.kind == "oob.read":
            return self._run_oob(spec)
        if spec.kind == "authorization.differential":
            return self._run_authorization(spec)
        if spec.kind == "timing.differential":
            return self._run_timing(spec)
        return self._run_response(spec)

    # ------------------------------------------------------------------ #
    # routes delegated to the classic verifiers (one measurement policy)
    # ------------------------------------------------------------------ #

    def _run_timing(self, spec: ConfirmationSpec) -> ConfirmationResult:
        """Delegate the timing route to the classic :class:`TimingVerifier`.

        The projection converts this spec's margin (milliseconds) to the shared
        spec's seconds and carries the routine's payloads, companions and dose
        payloads. The verdict — populations re-measured fresh, dose-response
        discrimination, refusals naming their numbers — is the classic one,
        which is the point.
        """
        verifier = TimingVerifier(self.gate)
        verdict = verifier.confirm(
            spec.as_confirm_spec(),
            candidate_id=f"confirm:{spec.routine_id}",
            proposer_grade=EVIDENCE_HYPOTHESIS,
        )
        return _from_verdict(spec, verdict)

    def _run_authorization(self, spec: ConfirmationSpec) -> ConfirmationResult:
        """Delegate the authorization route to the classic ``AuthorizationVerifier``.

        The projection maps this spec's runner-side oracle name to the
        verifier-side contract (``DIFFERENTIAL_SESSIONS``), so the proof is the
        classic one: flipped order, and session B must answer with the *object*
        (2xx with equivalent content), not merely with a different page.
        """
        verifier = AuthorizationVerifier(self.gate)
        verdict = verifier.confirm(
            spec.as_confirm_spec(),
            candidate_id=f"confirm:{spec.routine_id}",
            proposer_grade=EVIDENCE_HYPOTHESIS,
        )
        return _from_verdict(spec, verdict)

    # ------------------------------------------------------------------ #
    # HTTP-shaped routines
    # ------------------------------------------------------------------ #

    def _run_response(self, spec: ConfirmationSpec) -> ConfirmationResult:
        baseline = self._sample(spec, spec.baseline_payload)
        control = self._sample(spec, spec.control_payload)
        injected = self._sample(spec, spec.injected_payload)
        if not injected:
            return _refused(spec, "the injected population produced no measurement")
        ctx = OracleContext(
            baseline=(baseline[0] if baseline else Features()),
            injected=tuple(injected),
            control=(control[0] if control else None),
            length_delta=spec.length_delta,
        )
        return _decide(spec, ctx)

    # ------------------------------------------------------------------ #
    # browser routine
    # ------------------------------------------------------------------ #

    def _run_browser(self, spec: ConfirmationSpec) -> ConfirmationResult:
        url = spec.url
        outcome = self.gate.run(
            EffectRequest(
                kind="browser.run",
                host=spec.host,
                detail={"url": url, "markers": {spec.marker or "ve-marker": "1"}},
                technique="two_gate_verifier",
                probe=f"confirm:{spec.routine_id}",
            )
        )
        if not outcome.executed:
            return _refused(spec, f"browser run not executed: {outcome.reason}")
        features = feature_from_browser(outcome.effect)
        ctx = OracleContext(baseline=Features(), injected=(features,))
        return _decide(spec, ctx)

    # ------------------------------------------------------------------ #
    # out-of-band routine
    # ------------------------------------------------------------------ #

    def _run_oob(self, spec: ConfirmationSpec) -> ConfirmationResult:
        probe_id = f"confirm:{spec.routine_id}"
        sentinel = oob_sentinel(probe_id)
        collaborator = self.gate.allocate_oob(probe_id)
        payload = spec.injected_payload.replace(sentinel, collaborator)
        injected = self._sample(spec, payload)
        fetch = self.gate.read_oob(probe_id)
        ctx = OracleContext(
            baseline=Features(),
            injected=tuple(injected) if injected else (Features(),),
            oob_hit=bool(fetch.seen),
        )
        return _decide(spec, ctx)

    # ------------------------------------------------------------------ #
    # one population
    # ------------------------------------------------------------------ #

    def _sample(
        self, spec: ConfirmationSpec, payload: str, *, session: str = ""
    ) -> list[Features]:
        """Send ``spec.samples`` fresh requests carrying *payload*; features back.

        Returns ``[]`` the moment any request was refused or errored — an
        incomplete population is inconclusive, never a refutation.
        """
        features: list[Features] = []
        for index in range(max(1, spec.samples)):
            exchanged = self._send(spec, payload, session=session, index=index)
            if exchanged is None:
                return []
            features.append(exchanged)
        return features

    def _send(
        self, spec: ConfirmationSpec, payload: str, *, session: str, index: int
    ) -> Features | None:
        if spec.where == "body":
            surface = Surface(
                url=spec.url,
                host=spec.host,
                param=spec.param,
                companions=dict(spec.companions),
            )
            url, headers, content = json_body_request(surface, spec.param, payload)
            detail: dict = {
                "url": url,
                "method": "POST",
                "headers": headers,
                "content": content,
            }
        else:
            detail = {
                "url": with_parameter(spec.url, spec.param, payload),
                "method": "GET",
            }
        if session:
            detail["_session"] = session
        outcome = self.gate.run(
            EffectRequest(
                kind="http.request",
                host=spec.host,
                detail=detail,
                technique="two_gate_verifier",
                probe=f"confirm:{spec.routine_id}:{session or 'a'}:{index}",
            )
        )
        if not outcome.executed:
            return None
        exchange: RawHttpExchange = outcome.effect
        return feature_from_exchange(exchange, value=spec.canary)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _from_verdict(spec: ConfirmationSpec, verdict: Verdict) -> ConfirmationResult:
    """A delegated verdict, as the runner's own result shape.

    The oracle question is answered by the verifier's own policy (proven or
    not), so ``oracle_true`` mirrors ``proven`` here — a delegated route has no
    second oracle to apply. The features carried forward are the measurements
    the decision actually used: the shared verifiers summarize their fresh
    populations into their evidence payloads, and those numbers — not raw
    per-sample features — are what an operator reads.
    """
    evidence_payload: dict = {}
    if verdict.evidence is not None:
        evidence_payload = dict(verdict.evidence.payload or {})
    return ConfirmationResult(
        spec=spec,
        proven=verdict.proven,
        oracle_true=verdict.proven,
        reason=verdict.reason,
        context=_context_from_payload(spec, evidence_payload),
        evidence_grade=verdict.grade,
    )


def _context_from_payload(
    spec: ConfirmationSpec, payload: dict
) -> OracleContext | None:
    """The measured numbers of a delegated verdict, as an ``OracleContext``.

    Empty payload → ``None`` (the refusal paths carry no measurement). The
    field names are the shared verifiers' own evidence keys, so a drift between
    the evidence shape and this reduction is caught by the delegation test.
    """
    if not payload:
        return None
    if spec.kind == "timing.differential":
        baseline = Features(elapsed_ms=round(float(payload.get("baseline_median", 0.0)) * 1000.0, 3))
        injected = (
            Features(elapsed_ms=round(float(payload.get("injected_median", 0.0)) * 1000.0, 3)),
        )
        return OracleContext(
            baseline=baseline,
            injected=injected,
            margin=float(payload.get("margin", 0.0)),
        )
    if spec.kind == "authorization.differential":
        return OracleContext(
            baseline=Features(
                status=payload.get("flipped_session_a_status"),
                length=int(payload.get("session_a_body_length", 0) or 0),
                body_hash=str(payload.get("session_a_body_hash", ""))[:16],
            ),
            injected=(Features(),),
            session_a=Features(
                status=payload.get("flipped_session_a_status"),
                length=int(payload.get("session_a_body_length", 0) or 0),
                body_hash=str(payload.get("session_a_body_hash", ""))[:16],
            ),
            session_b=Features(
                status=payload.get("flipped_session_b_status"),
                length=int(payload.get("session_b_body_length", 0) or 0),
                body_hash=str(payload.get("session_b_body_hash", ""))[:16],
            ),
        )
    return None


def _decide(spec: ConfirmationSpec, ctx: OracleContext) -> ConfirmationResult:
    from .spec import ORACLE_EVIDENCE

    truth = apply_oracle(spec.oracle, ctx)
    grade = ORACLE_EVIDENCE.get(spec.oracle, "")
    if truth:
        return ConfirmationResult(
            spec=spec,
            proven=True,
            oracle_true=True,
            reason=f"oracle {spec.oracle!r} held over fresh measurements",
            context=ctx,
            evidence_grade=grade,
        )
    return ConfirmationResult(
        spec=spec,
        proven=False,
        oracle_true=False,
        reason=(
            f"oracle {spec.oracle!r} did not hold: the fresh measurements showed "
            "no separation"
        ),
        context=ctx,
        evidence_grade="",
    )


def _refused(spec: ConfirmationSpec, reason: str) -> ConfirmationResult:
    return ConfirmationResult(
        spec=spec,
        proven=False,
        oracle_true=False,
        reason=reason,
        context=None,
        evidence_grade="",
    )


__all__ = ["TWOGATE_CONFIRM_KINDS", "ConfirmationSpecRunner"]
