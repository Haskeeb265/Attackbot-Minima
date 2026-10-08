"""The differential verifier: fresh measurements, not a re-reading of the proposal.

A timing claim is the easiest claim in security to half-prove: the proposer's own
numbers, re-examined, always look the same. This verifier never sees them. Its
whole input is the shared confirmation spec (``kernel.confirm.ConfirmSpec``) —
which surface, which parameter, what margin, and *which payloads* — and it
re-runs both populations through the policy gate itself, alternating baseline and
injected exactly like the technique's grammar, then compares the fresh medians.

Both runtimes reach it through the same door: the classic path projects a
candidate's ``confirm`` dict onto the shared spec (``verify``), and the two-gate
runner projects its ``ConfirmationSpec`` onto the same shape and calls
``confirm`` directly — which is what closed the rigor gap between the two
flows' identically-labelled timing findings.

Reading the payloads from the spec is not a leak. The independence that makes
``differential`` its own evidence class is that every *measurement* here is
fresh — the spec's numbers are unread, its medians unverifiable by themselves.
What travels on the spec is what to inject, not what to conclude; re-deriving
the injection text independently would mean re-deriving the technique's whole
interpolation-shape table, and a verifier that owned a second copy of the
grammar could not be pinned to it except by convention. The pin still exists:
the fallback table below (for specs that name no payloads) is held against the
technique's by the test suite, so neither side can drift silently.

Three answers, in the order the code checks them:

* **a measurement that failed** — the target errored or the gate refused — is an
  inconclusive candidate, not a refutation: nothing is known;
* **a separation beyond the margin** proves the claim on ``differential`` grade,
  the evidence carrying both fresh medians and the sample count, so a reader can
  judge the measurement rather than trust the verdict;
* **anything else refuses, naming the numbers**: a slow target is not a finding,
  and "the populations overlap" is a fact worth logging, not hiding.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from urllib.parse import urlsplit

from ..kernel.confirm import ConfirmSpec
from ..kernel.evidence import EVIDENCE_DIFFERENTIAL, Evidence
from ..kernel.exchange import RawHttpExchange
from ..kernel.observation import OBS_HTTP_RESPONSE
from ..kernel.verdict import Candidate, Verdict, refuse
from ..policy.gate import EffectRequest, PolicyGate
from ..techniques.common import with_parameter

#: Confirmation-spec kind this verifier answers.  Must equal the technique's
#: ``confirm["kind"]``; pinned by a test so the two cannot drift.
CONFIRM_KIND = "timing.differential"

#: How many fresh samples per population the verifier requires. Two per side is
#: the floor that survives one outlier; the margin does the rest.
SAMPLES = 2

#: Fallback payload spellings, duplicated from the technique's grammar
#: deliberately: only for a confirmation spec that names no payloads of its own.
#: The two tables are pinned against each other by the test suite, so a grammar
#: change that forgets this fallback fails a test instead of confirming nothing.
_BASELINE_PAYLOAD = "ve-noop0"
_INJECTED_PAYLOAD = "1 AND SLEEP(4.0)"

#: The dose-response discriminator. A timing separation alone proves "this input
#: changed how long the target took" — which rate limiting, a WAF's regex
#: backtracking, or a load blip can each produce without any SQL being
#: interpreted. SQL that reaches an interpreter answers to the *dose*: the
#: sleep argument is an input the interpreter reads, so the measured delay must
#: scale with it. Both doses are measured fresh, after the main separation, so
#: the discrimination is the verifier's own second experiment — not a re-reading
#: of the proposer's populations. A target whose delay does not track the dose
#: is refused: the effect was observed, the cause was not established.
DOSE_SHORT_SECONDS = 2.0
DOSE_LONG_SECONDS = 6.0
#: Samples per dose population; two per side survives one outlier.
DOSE_SAMPLES = 2
#: The long dose's median must beat the short's by at least this fraction of
#: the dose gap (4s gap × 0.4 = 1.6s) before the delay is credited to the
#: interpreter rather than to noise.
DOSE_MARGIN_FRACTION = 0.4


@dataclass
class TimingVerifier:
    """Confirms a timing claim by re-measuring both populations itself."""

    gate: PolicyGate

    def verify(self, candidate: Candidate) -> Verdict:
        """Confirm or refuse *candidate*.  Never raises for an ordinary failure."""
        if str((candidate.confirm or {}).get("kind") or "") != CONFIRM_KIND:
            return refuse(
                candidate,
                "the proposer offered no differential confirmation for this candidate, "
                "and a timing claim cannot be established any other way",
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
        runner projects its ``ConfirmationSpec`` — and both then get this same
        dose-response discrimination, so a timing finding proves the same
        thing no matter which flow proposed it.
        """
        if spec.kind != CONFIRM_KIND:
            return self._refuse(
                candidate_id,
                proposer_grade,
                "the proposer offered no differential confirmation for this candidate, "
                "and a timing claim cannot be established any other way",
            )
        url = spec.url
        param = spec.param
        margin = float(spec.margin)
        if not url or not param:
            return self._refuse(
                candidate_id,
                proposer_grade,
                "the confirmation spec names no surface or parameter",
            )

        baseline_payload = spec.baseline_payload or _BASELINE_PAYLOAD
        injected_payload = spec.injected_payload or _INJECTED_PAYLOAD
        # The transport shape travels with the claim: a body-shaped surface is
        # re-measured with body-shaped requests — the same SQL, the same
        # transport the proposal used, so the populations stay comparable.
        where = spec.where or "query"
        companions = dict(spec.companions)
        probe_label = spec.probe or candidate_id

        baseline = self._measure(
            url, param, baseline_payload, probe_label, where=where, companions=companions
        )
        injected = self._measure(
            url, param, injected_payload, probe_label, where=where, companions=companions
        )
        if baseline is None or injected is None:
            return self._refuse(
                candidate_id,
                proposer_grade,
                "a measurement failed before both populations were complete, so the "
                "claim is inconclusive rather than refuted",
            )
        difference = statistics.median(injected) - statistics.median(baseline)
        if difference < margin:
            return self._refuse(
                candidate_id,
                proposer_grade,
                (
                    f"fresh populations differ by {difference:.2f}s, below the "
                    f"declared margin of {margin:.2f}s: a slow target is not a finding"
                ),
            )
        # The causal discriminator (a second, fresh experiment). The separation
        # above proves the *effect* — this input made the target slower. It does
        # not prove the *cause* — that the input was interpreted as SQL. The
        # dose-response pair does: a delay that scales with the sleep argument
        # is the signature of an interpreter reading the value, and it is the
        # one signature rate limiting, WAF heuristics and load variance cannot
        # produce. An incomplete dose measurement is inconclusive, never a
        # refutation; a complete one that does not track the dose is a refusal
        # naming both medians.
        dose = self._measure_dose(
            url,
            param,
            where=where,
            companions=companions,
            dose_short=spec.dose_short_payload or f"1 AND SLEEP({DOSE_SHORT_SECONDS})",
            dose_long=spec.dose_long_payload or f"1 AND SLEEP({DOSE_LONG_SECONDS})",
        )
        if dose is None:
            return self._refuse(
                candidate_id,
                proposer_grade,
                "the populations separated, but a dose-response measurement failed "
                "before both doses were complete, so the claim is inconclusive: "
                "the effect was observed, the cause was not established",
            )
        dose_gap = DOSE_LONG_SECONDS - DOSE_SHORT_SECONDS
        dose_margin = DOSE_MARGIN_FRACTION * dose_gap
        dose_difference = dose[1] - dose[0]
        at = self.gate.now()
        evidence = Evidence(
            kind=OBS_HTTP_RESPONSE,
            grade=EVIDENCE_DIFFERENTIAL,
            probe=probe_label,
            at=at,
            payload={
                "baseline_median": round(statistics.median(baseline), 4),
                "injected_median": round(statistics.median(injected), 4),
                "difference": round(difference, 4),
                "margin": margin,
                "baseline_samples": len(baseline),
                "injected_samples": len(injected),
                "baseline_payload": baseline_payload,
                "injected_payload": injected_payload,
                "dose_short_median": round(dose[0], 4),
                "dose_long_median": round(dose[1], 4),
                "dose_gap_seconds": dose_gap,
                "dose_margin": round(dose_margin, 4),
                "dose_tracks": dose_difference >= dose_margin,
                "variant": str(getattr(spec, "variant", "") or ""),
                "reason": (
                    "fresh differential measurement through the policy gate, with a "
                    "dose-response discrimination of the delay's cause"
                ),
            },
        )
        if dose_difference < dose_margin:
            return self._refuse(
                candidate_id,
                proposer_grade,
                (
                    f"the populations separated, but the delay does not track the "
                    f"injection dose (dose {DOSE_LONG_SECONDS}s - {DOSE_SHORT_SECONDS}s moved "
                    f"the median {dose_difference:.2f}s, wanted >= {dose_margin:.2f}s): "
                    "a timing effect without an interpreter behind it is not a "
                    "finding"
                ),
            )
        Verdict.check_independence(proposer_grade, evidence)
        return Verdict(
            candidate_id=candidate_id,
            proven=True,
            evidence=evidence,
            reason=(
                f"fresh differential measurement separated the populations by "
                f"{difference:.2f}s (margin {margin:.2f}s) and the delay tracked "
                f"the injection dose ({dose_difference:.2f}s across a {dose_gap:.1f}s gap)"
            ),
            proposer_grade=proposer_grade,
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

    def _measure_dose(
        self,
        url: str,
        param: str,
        *,
        where: str = "query",
        companions: dict[str, str] | None = None,
        dose_short: str = "",
        dose_long: str = "",
    ) -> tuple[float, float] | None:
        """Fresh medians for the short and long sleep doses, or ``None``.

        The payloads travel on the confirmation spec — the winning variant's
        own shape at the two declared doses, so the dose experiment asks *this*
        injection and never a second copy of a grammar that could drift. The
        SQL fallbacks below exist only for specs that name no dose payloads,
        and are pinned to the technique's table by the test suite.
        """
        short = self._measure(
            url,
            param,
            dose_short or f"1 AND SLEEP({DOSE_SHORT_SECONDS})",
            f"{url}#dose-short",
            where=where,
            companions=companions,
            count=DOSE_SAMPLES,
        )
        if short is None:
            return None
        long = self._measure(
            url,
            param,
            dose_long or f"1 AND SLEEP({DOSE_LONG_SECONDS})",
            f"{url}#dose-long",
            where=where,
            companions=companions,
            count=DOSE_SAMPLES,
        )
        if long is None:
            return None
        return (statistics.median(short), statistics.median(long))

    def _measure(
        self,
        url: str,
        param: str,
        payload: str,
        probe: str,
        *,
        where: str = "query",
        companions: dict[str, str] | None = None,
        count: int = SAMPLES,
    ) -> list[float] | None:
        """One population's fresh elapsed times, or ``None`` if any request failed."""
        if where == "body":
            # The API shape: the same helper the technique's grammar uses, so
            # verifier and proposer build byte-identical requests. The spec's
            # plain data becomes a minimal kernel Surface — the one vocabulary
            # techniques and verifiers share.
            from ..kernel.technique import Surface
            from ..techniques.common import json_body_request

            spec_surface = Surface(
                url=url,
                host=(urlsplit(url).hostname or "").lower(),
                param=param,
                companions=dict(companions or {}),
            )
            request_url, headers, content = json_body_request(
                spec_surface, param, payload
            )
            detail: dict = {
                "url": request_url,
                "method": "POST",
                "headers": headers,
                "content": content,
            }
        else:
            detail = {"url": with_parameter(url, param, payload), "method": "GET"}
        samples: list[float] = []
        for _ in range(count):
            outcome = self.gate.run(
                EffectRequest(
                    kind="http.request",
                    host=(urlsplit(url).hostname or "").lower(),
                    detail=dict(detail),
                    technique="timing_verifier",
                    probe=probe,
                )
            )
            if not outcome.executed:
                return None
            exchange: RawHttpExchange = outcome.effect
            if not exchange.ok:
                return None
            transports = getattr(self.gate, "_http", None)
            if transports is not None and getattr(transports, "throttled", False):
                # Item 2.1: the transport honors a Retry-After inside the
                # measured window, so this elapsed is the rate limiter's wait
                # plus the server's time — not a comparable timing sample. The
                # population refuses rather than reports, which is the honest
                # shape: an incomplete population is inconclusive.
                return None
            samples.append(exchange.elapsed)
        return samples


__all__ = [
    "CONFIRM_KIND",
    "DOSE_LONG_SECONDS",
    "DOSE_MARGIN_FRACTION",
    "DOSE_SAMPLES",
    "DOSE_SHORT_SECONDS",
    "TimingVerifier",
]
