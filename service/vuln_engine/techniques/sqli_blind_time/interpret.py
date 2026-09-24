"""Interpretation: measured populations per variant, one structured claim.

The proposer's job here is deliberately modest: group the recorded response
observations by their ``timing_class`` label — and, for injected populations, by
*variant* — reduce each population to a median, and compare against the declared
margin. What it produces is a candidate whose own summary says exactly how weak
a timing claim is — "consistent with a server-side delay, and equally consistent
with a slow target".

Three honesty rules in the arithmetic:

* **the margin is declared, not discovered** — :data:`MARGIN_SECONDS` is the
  smallest difference this technique will even propose from. A 50ms gap against a
  payload that asked for seconds is weather, not injection, and a technique that
  proposed from it would be filling the report with noise;
* **an incomplete population proposes nothing** — if any request errored or a
  sample is missing, the run did not measure the difference; it measured a
  partial experiment. ``None`` populations mean no candidate, not a candidate
  with caveats;
* **the winner is the variant, not the family** — the candidate rests on the one
  interpolation shape whose population separated, and carries *that* variant's
  payloads in its confirmation spec. A family whose three other shapes returned
  fast is not a footnote; it is the control that makes the separation mean
  "this shape was parsed" rather than "the target was slow during this variant".

The confirmation spec asks for ``timing.differential`` with the winning
payloads inline: fresh measurements by the verifier, both populations, same
margin, *same SQL*. The proposer's numbers are never shown to the verifier — it
re-derives every measurement, which is the whole independence argument for this
class. What it reads from the spec is what to inject, not what to conclude.
"""

from __future__ import annotations

import statistics
from collections.abc import Iterable

from ...kernel.evidence import EVIDENCE_SEMANTIC, Evidence
from ...kernel.observation import OBS_HTTP_RESPONSE, Observation
from ...kernel.technique import Hypothesis
from ...kernel.verdict import Candidate
from ..common import with_parameter
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
    observations: list[Observation],
    timing_class: str,
    probe_prefix: str,
    *,
    variant: str = "",
) -> list[float]:
    """Successful elapsed times for one population of *this technique's* probes.

    The prefix filter keeps another technique's (or a previous arm's) response
    observations out of the population: the id space is the join key, and a
    population that mixed probes would be a number with no meaning. Injected
    populations are further keyed by *variant* — the id of an injected probe
    carries it — so two variants' samples never merge into one median.
    """
    samples: list[float] = []
    for item in observations:
        if item.kind != OBS_HTTP_RESPONSE:
            continue
        if not item.probe.startswith(probe_prefix):
            continue
        if str(item.payload.get("timing_class", "")) != timing_class:
            continue
        if variant:
            if f":{variant}:" not in item.probe:
                continue
        elif ":verify:" in item.probe or any(
            f":{name}:" in item.probe for name, _ in probe_grammar.PAYLOAD_VARIANTS
        ):
            # A probe id naming a variant (or the verifier's spelling) belongs to
            # an injected population, never to the baseline's.
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
    """The timing-difference candidate, when a variant's population separated."""
    surface = hypothesis.surface
    probe = probe_grammar.probe_id(hypothesis)
    baseline = _median(_elapsed_samples(observations, TIMING_BASELINE, probe))
    if baseline is None:
        return []

    # The winner: the first variant whose median separates beyond the margin,
    # in declared (shape) order — ties go to the cheaper, earlier shape. Every
    # variant measured is reported in the evidence, so the losing shapes stay
    # visible as the control they are.
    winner: str = ""
    winner_median = 0.0
    measured: dict[str, float] = {}
    for variant, _ in probe_grammar.PAYLOAD_VARIANTS:
        samples = _elapsed_samples(observations, TIMING_INJECTED, probe, variant=variant)
        median = _median(samples)
        if median is None:
            continue
        measured[variant] = round(median, 4)
        if not winner and median - baseline >= MARGIN_SECONDS:
            winner, winner_median = variant, median
    if not winner:
        return []

    winner_payload = probe_grammar.variant_payload(winner)
    difference = winner_median - baseline
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
                f"responses to a {winner}-shaped payload in {surface.param!r} took "
                f"{difference:.2f}s longer than the baseline (medians "
                f"{winner_median:.2f}s vs {baseline:.2f}s), consistent with a "
                "server-side delay and equally consistent with a slow target"
            ),
            evidence=Evidence(
                kind=OBS_HTTP_RESPONSE,
                grade=EVIDENCE_SEMANTIC,
                payload={
                    "variant": winner,
                    "baseline_median": round(baseline, 4),
                    "injected_median": round(winner_median, 4),
                    "difference": round(difference, 4),
                    "margin": MARGIN_SECONDS,
                    "baseline_samples": len(
                        _elapsed_samples(observations, TIMING_BASELINE, probe)
                    ),
                    "injected_samples": len(
                        _elapsed_samples(observations, TIMING_INJECTED, probe, variant=winner)
                    ),
                    "variants_measured": measured,
                    "reason": (
                        "one interpolation shape's population separated beyond the "
                        "declared margin; the others are the control"
                    ),
                },
                probe=probe,
            ),
            confirm={
                # The verifier's own question: measure both populations fresh,
                # with the same margin and the *same SQL*. The payloads travel
                # on the spec — what to inject is data, never a conclusion.
                "kind": "timing.differential",
                "probe": probe,
                "margin": MARGIN_SECONDS,
                "url": surface.url,
                "param": surface.param,
                "baseline_payload": probe_grammar.QUIET_PAYLOAD,
                "injected_payload": winner_payload,
                "variant": winner,
            },
            # The payload that makes the candidate reproducible by hand.
            payload=winner_payload,
            repro_url=with_parameter(surface.url, surface.param, winner_payload),
        )
    ]


#: The name the driver and the tests use for this function. Same alias as the
#: sibling techniques', for the same reason.
interpret = candidates


__all__ = ["MARGIN_SECONDS", "MIN_SAMPLES", "candidates", "interpret"]
