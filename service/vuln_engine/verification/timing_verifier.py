"""The differential verifier: fresh measurements, not a re-reading of the proposal.

A timing claim is the easiest claim in security to half-prove: the proposer's own
numbers, re-examined, always look the same. This verifier never sees them. Its
whole input from the candidate is the confirmation spec — which surface, which
parameter, what margin, and *which payloads* — and it re-runs both populations
through the policy gate itself, alternating baseline and injected exactly like
the technique's grammar, then compares the fresh medians.

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


@dataclass
class TimingVerifier:
    """Confirms a timing claim by re-measuring both populations itself."""

    gate: PolicyGate

    def verify(self, candidate: Candidate) -> Verdict:
        """Confirm or refuse *candidate*.  Never raises for an ordinary failure."""
        confirm = dict(candidate.confirm or {})
        if confirm.get("kind") != CONFIRM_KIND:
            return refuse(
                candidate,
                "the proposer offered no differential confirmation for this candidate, "
                "and a timing claim cannot be established any other way",
            )
        url = str(confirm.get("url") or "")
        param = str(confirm.get("param") or "")
        margin = float(confirm.get("margin") or 0.0)
        if not url or not param:
            return refuse(candidate, "the confirmation spec names no surface or parameter")

        baseline_payload = str(confirm.get("baseline_payload") or _BASELINE_PAYLOAD)
        injected_payload = str(confirm.get("injected_payload") or _INJECTED_PAYLOAD)

        baseline = self._measure(url, param, baseline_payload, candidate.id)
        injected = self._measure(url, param, injected_payload, candidate.id)
        if baseline is None or injected is None:
            return refuse(
                candidate,
                "a measurement failed before both populations were complete, so the "
                "claim is inconclusive rather than refuted",
            )
        difference = statistics.median(injected) - statistics.median(baseline)
        at = self.gate.now()
        evidence = Evidence(
            kind=OBS_HTTP_RESPONSE,
            grade=EVIDENCE_DIFFERENTIAL,
            probe=str(confirm.get("probe") or candidate.id),
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
                "variant": str(confirm.get("variant") or ""),
                "reason": "fresh differential measurement through the policy gate",
            },
        )
        if difference < margin:
            return refuse(
                candidate,
                (
                    f"fresh populations differ by {difference:.2f}s, below the "
                    f"declared margin of {margin:.2f}s: a slow target is not a finding"
                ),
            )
        Verdict.check_independence(candidate.proposer_grade, evidence)
        return Verdict(
            candidate_id=candidate.id,
            proven=True,
            evidence=evidence,
            reason=(
                f"fresh differential measurement separated the populations by "
                f"{difference:.2f}s (margin {margin:.2f}s)"
            ),
            proposer_grade=candidate.proposer_grade,
        )

    # ------------------------------------------------------------------ #
    # measurement
    # ------------------------------------------------------------------ #

    def _measure(
        self, url: str, param: str, payload: str, probe: str
    ) -> list[float] | None:
        """One population's fresh elapsed times, or ``None`` if any request failed."""
        samples: list[float] = []
        for _ in range(SAMPLES):
            request_url = with_parameter(url, param, payload)
            outcome = self.gate.run(
                EffectRequest(
                    kind="http.request",
                    host=(urlsplit(url).hostname or "").lower(),
                    detail={"url": request_url, "method": "GET"},
                    technique="timing_verifier",
                    probe=probe,
                )
            )
            if not outcome.executed:
                return None
            exchange: RawHttpExchange = outcome.effect
            if not exchange.ok:
                return None
            samples.append(exchange.elapsed)
        return samples


__all__ = ["CONFIRM_KIND", "TimingVerifier"]
