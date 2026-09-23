"""The probe grammar for a timing-differential technique, as data.

Two populations, deliberately symmetric:

``baseline``
    The parameter set to a value that carries *no* delay payload — just the same
    length and shape, so the two requests differ in one property (the payload's
    semantics) rather than in size, shape or spelling.
``injected``
    The same request with the delay payload. On the fixture the payload is the
    sleep marker; against a real target the grammar would hold the SQLSleep
    shapes, but the *structure* — N of each, alternating, labelled — is the
    technique, which is what makes it testable offline.

Every spec carries ``timing_class`` in its detail, and the driver forwards it to
the observation layer so each response is labelled with its population. That
label is the join key the interpreter and the verifier both group by — a plain
lookup, never a parse of the URL.

The alternation (baseline, injected, baseline, injected…) is the grammar's one
defence against drifting server load: a slow-down that arrives mid-run hits both
populations instead of being mistaken for an injection. A technique that sent
all baselines first would measure the weather, not the target.
"""

from __future__ import annotations

from ...kernel.technique import (
    KIND_HTTP,
    ORACLE_TIMING_DIFFERENTIAL,
    PURPOSE_PROPOSE,
    Hypothesis,
    ProbeSpec,
)
from ..common import with_parameter

NAME = "sqli_blind_time"

#: The substring the fixture's ``/delay`` endpoint sleeps on. Against a real
#: target the payload row below is what changes; the grammar does not.
SLEEP_PAYLOAD = "ve-sleep"
#: The baseline: same length, same shape, no semantics.
QUIET_PAYLOAD = "ve-noop0"

#: Samples per population. Even at the fixture's 2s sleep this is the most
#: expensive probe set in the engine — declared as such in the manifest's noise.
SAMPLES_PER_POPULATION = 2

TIMING_BASELINE = "baseline"
TIMING_INJECTED = "injected"


def probe_id(hypothesis: Hypothesis) -> str:
    return f"{NAME}:{hypothesis.surface.host}:{hypothesis.surface.param}"


def _detail(hypothesis: Hypothesis, payload: str, timing_class: str) -> dict:
    surface = hypothesis.surface
    return {
        "url": with_parameter(surface.url, surface.param, payload),
        "method": "GET",
        "timing_class": timing_class,
    }


def probes(hypothesis: Hypothesis) -> list[ProbeSpec]:
    """The alternating baseline/injected population, in send order."""
    surface = hypothesis.surface
    probe = probe_id(hypothesis)
    specs: list[ProbeSpec] = []
    for index in range(SAMPLES_PER_POPULATION):
        for timing_class, payload in (
            (TIMING_BASELINE, QUIET_PAYLOAD),
            (TIMING_INJECTED, SLEEP_PAYLOAD),
        ):
            specs.append(
                ProbeSpec(
                    id=f"{probe}:{timing_class}:{index}",
                    kind=KIND_HTTP,
                    host=surface.host,
                    detail=_detail(hypothesis, payload, timing_class),
                    oracle=ORACLE_TIMING_DIFFERENTIAL,
                    noise={
                        "requests_per_surface": 1,
                        "burstiness": 0.9,
                        "fingerprint_distance": 0.7,
                        "requires_browser": False,
                    },
                    produces="semantic",
                    purpose=PURPOSE_PROPOSE,
                )
            )
    return specs


def measurement_probes(hypothesis: Hypothesis) -> list[ProbeSpec]:
    """The confirmation population the *verifier* executes (deferred by the driver).

    Same grammar, fresh measurements: the verifier re-runs both populations
    itself rather than re-reading the proposer's numbers, which is what makes
    ``differential`` an independent class rather than a second opinion from the
    same data.
    """
    surface = hypothesis.surface
    probe = probe_id(hypothesis)
    specs: list[ProbeSpec] = []
    for index in range(SAMPLES_PER_POPULATION):
        for timing_class, payload in (
            (TIMING_BASELINE, QUIET_PAYLOAD),
            (TIMING_INJECTED, SLEEP_PAYLOAD),
        ):
            specs.append(
                ProbeSpec(
                    id=f"{probe}:verify:{timing_class}:{index}",
                    kind=KIND_HTTP,
                    host=surface.host,
                    detail=_detail(hypothesis, payload, timing_class),
                    oracle=ORACLE_TIMING_DIFFERENTIAL,
                    noise={},
                    produces="differential",
                    purpose="confirm",
                )
            )
    return specs


__all__ = [
    "NAME",
    "QUIET_PAYLOAD",
    "SAMPLES_PER_POPULATION",
    "SLEEP_PAYLOAD",
    "TIMING_BASELINE",
    "TIMING_INJECTED",
    "measurement_probes",
    "probe_id",
    "probes",
]
