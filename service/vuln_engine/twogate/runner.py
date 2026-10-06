"""The ConfirmationSpecRunner: execute a declarative spec, apply the oracle.

This is the only module in the two-gate flow that sends traffic, and it sends it
exclusively through :class:`~..policy.gate.PolicyGate` — the same chokepoint every
other probe uses. It never calls a model, never reads a clock into a pure
decision (the gate's clock stamps the effects), and never decides a verdict by
any means other than :func:`~.spec.apply_oracle` over measured features.

The independence property it implements: the runner reads the *spec* and nothing
else. The proposer's rationale, confidence, or numbers are unreachable from here,
which is what stops a proposal from being re-read as its own proof.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ..kernel.exchange import RawHttpExchange
from ..kernel.technique import Surface, oob_sentinel
from ..policy.gate import EffectRequest, PolicyGate
from ..techniques.common import json_body_request, with_parameter
from .spec import (
    ConfirmationResult,
    ConfirmationSpec,
    Features,
    OracleContext,
    apply_oracle,
    feature_from_browser,
    feature_from_exchange,
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

    def _run_timing(self, spec: ConfirmationSpec) -> ConfirmationResult:
        baseline = self._sample(spec, spec.baseline_payload)
        injected = self._sample(spec, spec.injected_payload)
        if not baseline or not injected:
            return _refused(spec, "a population failed before both were complete (inconclusive)")
        ctx = OracleContext(
            baseline=baseline[0],
            injected=tuple(injected),
            control=None,
            margin=spec.margin,
        )
        return _decide(spec, ctx)

    # ------------------------------------------------------------------ #
    # session-differential routine
    # ------------------------------------------------------------------ #

    def _run_authorization(self, spec: ConfirmationSpec) -> ConfirmationResult:
        session_a = self._sample(spec, spec.injected_payload, session="")
        session_b = self._sample(spec, spec.injected_payload, session="b")
        if not session_a or not session_b:
            return _refused(
                spec,
                "one session produced no measurement (inconclusive, not refuted)",
            )
        ctx = OracleContext(
            baseline=session_a[0],
            injected=(session_b[0],),
            session_a=session_a[0],
            session_b=session_b[0],
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


__all__ = ["ConfirmationSpecRunner"]
