"""Interpretation: two populations of measured elapsed times, one structured claim.

The proposer's job here is deliberately modest: group the recorded response
observations by their ``timing_class`` label, reduce each population to a median,
and compare against the declared margin. What it produces is a candidate whose
own summary says exactly how weak a timing claim is — "consistent with a
server-side delay, and equally consistent with a slow target".

Two honesty rules in the arithmetic:

* **the margin is declared, not discovered** — :data:`MARGIN_SECONDS` is the
  smallest difference this technique will even propose from. A 50ms gap against a
  payload that asked for 2000ms is weather, not injection, and a technique that
  proposed from it would be filling the report with noise;
* **an incomplete population proposes nothing** — if any request errored or a
  sample is missing, the run did not measure the difference; it measured a
  partial experiment. ``None`` populations mean no candidate, not a candidate
  with caveats.

The confirmation spec asks for ``timing.differential``: fresh measurements by the
verifier, both populations, with the same margin. The proposer's numbers are
never shown to the verifier — it re-derives everything, which is the whole
independence argument for this class.
"""

from __future__ import annotations

import statistics
from collections.abc import Iterable

from ...kernel.evidence import EVIDENCE_SEMANTIC, Evidence
from ...kernel.observation import OBS_HTTP_RESPONSE, Observation
from ...kernel.technique import Hypothesis
from ...kernel.verdict import Candidate
from . import probes as probe_grammar

NAME = "sqli_blind_time"

#: The smallest baseline↔injected median difference worth proposing from.
#: Declared here so the test suite can hold the technique to it.
MARGIN_SECONDS = 0.5

#: How many elapsed samples per population the proposer requires before it will
#: say anything at all.
MIN_SAMPLES = 2

TIMING_BASELINE = probe_grammar.TIMING_BASELINE
TIMING_INJECTED = probe_grammar.TIMING_INJECTED


def _elapsed_samples(
    observations: list[Observation], timing_class: str, probe_prefix: str
) -> list[float]:
    """Successful elapsed times for one population of *this technique's* probes.

    The prefix filter keeps another technique's (or a previous arm's) response
    observations out of the population: the id space is the join key, and a
    population that mixed probes would be a number with no meaning.
    """
    samples: list[float] = []
    for item in observations:
        if item.kind != OBS_HTTP_RESPONSE:
            continue
        if not item.probe.startswith(probe_prefix):
            continue
        if str(item.payload.get("timing_class", "")) != timing_class:
            continue
        if not item.payload.get("ok"):
            continue
        elapsed = item.payload.get("elapsed")
        if isinstance(elapsed, (int, float)):
            samples.append(float(elapsed))
    return samples


def _median(samples: Iterable[float]) -> float | None:
    """The population's median, or ``None`` when it is too small to mean anything."""
    values = list(samples)
    if len(values) < MIN_SAMPLES:
        return None
    return statistics.median(values)


def candidates(hypothesis: Hypothesis, observations: list[Observation]) -> list[Candidate]:
    """The timing-difference candidate, when both populations were measured."""
    surface = hypothesis.surface
    probe = probe_grammar.probe_id(hypothesis)
    baseline = _median(_elapsed_samples(observations, TIMING_BASELINE, probe))
    injected = _median(_elapsed_samples(observations, TIMING_INJECTED, probe))
    if baseline is None or injected is None:
        return []
    difference = injected - baseline
    if difference < MARGIN_SECONDS:
        return []
    return [
        Candidate(
            id=f"{NAME}:{surface.host}:{surface.url.split('//')[-1]}:{surface.param}",
            technique=NAME,
            vuln_class="sqli",
            surface={
                "url": surface.url,
                "param": surface.param,
                "where": surface.where,
                "host": surface.host,
            },
            summary=(
                f"responses to a payload-carrying {surface.param!r} took "
                f"{difference:.2f}s longer than the baseline (medians "
                f"{injected:.2f}s vs {baseline:.2f}s), consistent with a "
                "server-side delay and equally consistent with a slow target"
            ),
            evidence=Evidence(
                kind=OBS_HTTP_RESPONSE,
                grade=EVIDENCE_SEMANTIC,
                payload={
                    "baseline_median": round(baseline, 4),
                    "injected_median": round(injected, 4),
                    "difference": round(difference, 4),
                    "margin": MARGIN_SECONDS,
                    "baseline_samples": len(
                        _elapsed_samples(observations, TIMING_BASELINE, probe)
                    ),
                    "injected_samples": len(
                        _elapsed_samples(observations, TIMING_INJECTED, probe)
                    ),
                    "reason": "two measured populations differ beyond the declared margin",
                },
                probe=probe,
            ),
            confirm={
                # The verifier's own question: measure both populations fresh,
                # with the same margin. Kind names the differential verifier.
                "kind": "timing.differential",
                "probe": probe,
                "margin": MARGIN_SECONDS,
                "url": surface.url,
                "param": surface.param,
            },
            # The payload that makes the candidate reproducible by hand.
            payload=probe_grammar.SLEEP_PAYLOAD,
            repro_url=probe_grammar._detail(hypothesis, probe_grammar.SLEEP_PAYLOAD, "injected")[
                "url"
            ],
        )
    ]


interpret = candidates

__all__ = ["MARGIN_SECONDS", "MIN_SAMPLES", "candidates", "interpret"]
