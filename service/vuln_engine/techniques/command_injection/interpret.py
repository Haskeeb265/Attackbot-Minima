"""Interpretation: measured populations per variant, one structured claim.

The proposer groups the recorded response observations by their
``timing_class`` label — and, for injected populations, by *variant* — reduces
each population to a median, and compares against the declared margin. What it
produces is a candidate whose own summary says exactly how weak a timing claim
is — "consistent with a server-side delay, and equally consistent with a slow
target".

Three honesty rules, the same as the SQLi timing technique's:

* **the margin is declared, not discovered** — a 50ms gap against a payload that
  asked for seconds is weather, not injection;
* **an incomplete population proposes nothing** — a partial experiment is not a
  measurement;
* **the winner is the variant, not the family** — the candidate rests on the one
  interpolation shape whose population separated, and carries *that* variant's
  payloads in its confirmation spec. The shapes that returned fast are the
  control that makes the separation mean "this metacharacter was processed"
  rather than "the target was slow during this variant".

The confirmation spec asks for ``timing.differential`` with the winning
payloads inline: fresh measurements by the verifier, both populations, same
margin, *same shell text*. The proposer's numbers are never shown to the
verifier — it re-derives every measurement.
"""

from __future__ import annotations

import statistics
from collections.abc import Iterable

from ...kernel.evidence import EVIDENCE_SEMANTIC, Evidence
from ...kernel.observation import OBS_HTTP_RESPONSE, Observation
from ...kernel.technique import Hypothesis
from ...kernel.verdict import Candidate
from ..common import surface_id_prefix, with_parameter
from . import probes as probe_grammar

NAME = "command_injection"
VULN_CLASS = "command-injection"

#: The smallest baseline↔injected median difference worth proposing from.
MARGIN_SECONDS = 0.5

#: How many elapsed samples per population the proposer requires.
MIN_SAMPLES = 2

TIMING_BASELINE = probe_grammar.TIMING_BASELINE
TIMING_INJECTED = probe_grammar.TIMING_INJECTED


def _all_variants() -> tuple[tuple[str, str], ...]:
    return probe_grammar.PAYLOAD_VARIANTS + probe_grammar.BODY_VARIANTS


def _elapsed_samples(
    observations: list[Observation],
    timing_class: str,
    probe_prefix: str,
    *,
    variant: str = "",
) -> list[float]:
    """Successful elapsed times for one population of *this technique's* probes."""
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
            f":{name}:" in item.probe for name, _ in _all_variants()
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

    winner: str = ""
    winner_median = 0.0
    measured: dict[str, float] = {}
    variants = (
        probe_grammar.BODY_VARIANTS
        if surface.where == "body"
        else probe_grammar.PAYLOAD_VARIANTS
    )
    for variant, _ in variants:
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
    # The causal discriminator travels with the claim (see sqli_blind_time's
    # interpreter): the winning shape at the two declared doses.
    dose_short, dose_long = probe_grammar.dose_payloads(winner)
    difference = winner_median - baseline
    return [
        Candidate(
            id=f"{surface_id_prefix(NAME, surface)}",
            technique=NAME,
            vuln_class=VULN_CLASS,
            surface={
                "url": surface.url,
                "param": surface.param,
                "where": surface.where,
                "host": surface.host,
            },
            summary=(
                f"responses to a {winner}-shaped value in {surface.param!r} took "
                f"{difference:.2f}s longer than the baseline (medians "
                f"{winner_median:.2f}s vs {baseline:.2f}s), consistent with a "
                "server-side command delay and equally consistent with a slow target"
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
                "kind": "timing.differential",
                "probe": probe,
                "margin": MARGIN_SECONDS,
                "url": surface.url,
                "param": surface.param,
                "where": surface.where,
                "companions": dict(surface.companions or {}),
                "baseline_payload": probe_grammar.QUIET_PAYLOAD,
                "injected_payload": winner_payload,
                "dose_short_payload": dose_short,
                "dose_long_payload": dose_long,
                "variant": winner,
            },
            payload=winner_payload,
            repro_url=(
                surface.url
                if surface.where == "body"
                else with_parameter(surface.url, surface.param, winner_payload)
            ),
        )
    ]


interpret = candidates

__all__ = ["MARGIN_SECONDS", "MIN_SAMPLES", "candidates", "interpret"]
