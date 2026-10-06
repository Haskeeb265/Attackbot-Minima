"""``elicit.timing`` — does this parameter's value move the server's response time?

The question ``sqli_blind_time`` and ``command_injection`` need answered before
they are worth their loud probe sets. The measurement is deliberately stronger
than one slow payload: alongside the quiet-vs-sleep populations, a
**dose-response pair** asks for the short sleep and the long sleep — a delay
that scales with the dose is a fact about *processing* the value, which is the
claim ``delayed_response`` actually names. A flat one-off spike (a load blip, a
cache miss) does not track the dose and does not establish the fact.
"""

from __future__ import annotations

import statistics

from ...kernel.capability import CapabilityFact
from ...kernel.evidence import EVIDENCE_DIFFERENTIAL
from ...kernel.observation import OBS_HTTP_RESPONSE, Observation
from ...kernel.technique import CAP_DELAYED_RESPONSE, Surface
from ..base import Elicitor
from ..common import Elicitation, fact_for
from .manifest import MANIFEST, NAME

#: The quiet baseline payload — no semantics any interpreter could use.
QUIET_PAYLOAD = "ve-noop0"

#: The sleep doses, seconds. Two doses so the dose-response question has two
#: points; a delay that tracks the dose separates them by roughly the dose gap.
SHORT_DOSE = 2.0
LONG_DOSE = 6.0

#: Samples per population. Two per side survives one outlier.
SAMPLES = 2

#: The margin, seconds: the injected median must beat the quiet median by this
#: much, and the long dose must beat the short dose by a fraction of the dose
#: gap, before the fact is recorded.
MARGIN_SECONDS = 1.0
DOSE_MARGIN_FRACTION = 0.4


def probe_id(surface: Surface) -> str:
    return f"{NAME}:{surface.host}:{surface.param}"


def applies(surface: Surface) -> bool:
    return bool(surface.param) and surface.where in ("query", "body", "path")


def _payloads() -> dict[str, str]:
    """The population payloads, one spelling per population."""
    return {
        "quiet": QUIET_PAYLOAD,
        "sleep": f"1 AND SLEEP({LONG_DOSE})",
        "dose_short": f"1 AND SLEEP({SHORT_DOSE})",
        "dose_long": f"1 AND SLEEP({LONG_DOSE})",
    }


def probes(surface: Surface) -> list[dict]:
    """The populations, interleaved: quiet, sleep, then the dose pair, per round."""
    from ..common_probe import request_detail

    probe = probe_id(surface)
    payloads = _payloads()
    order: list[str] = []
    for _ in range(SAMPLES):
        for population in ("quiet", "sleep", "dose_short", "dose_long"):
            order.append(population)
    specs: list[dict] = []
    for index, population in enumerate(order):
        specs.append(
            {
                "id": f"{probe}:{population}:{index // 4}",
                "kind": "http.request",
                "host": surface.host,
                "detail": request_detail(surface, surface.param, payloads[population]),
                "canary": "",
                "mark": "",
                "population": population,
            }
        )
    return specs


def interpret(
    surface: Surface, observations: list[Observation], *, at: float = 0.0
) -> Elicitation:
    """The dose-tracking test, over this probe's own populations.

    Three answers, honest about what each means:

    * an incomplete population (a refusal, an error, a lost sample) is a
      **negative with the reason named** — the closure pass may retry next run,
      never within it;
    * populations measured but not separated: a negative (a slow target is not
      a capability);
    * quiet-vs-sleep separated **and** the long dose beating the short by the
      dose margin: the fact, at differential grade.
    """
    prefix = probe_id(surface) + ":"
    elapsed: dict[str, list[float]] = {
        "quiet": [],
        "sleep": [],
        "dose_short": [],
        "dose_long": [],
    }
    for item in observations:
        if item.kind != OBS_HTTP_RESPONSE or not item.probe.startswith(prefix):
            continue
        # The population label travels on the observation's ``timing_class``
        # field — the same grouping key the timing techniques' grammar uses —
        # because the response payload carries measurements, not request details.
        population = str(item.payload.get("timing_class") or "")
        value = item.payload.get("elapsed")
        if population in elapsed and isinstance(value, (int, float)):
            elapsed[population].append(float(value))
    required = ("quiet", "sleep", "dose_short", "dose_long")
    missing = [name for name in required if len(elapsed[name]) < SAMPLES]
    if missing:
        return Elicitation.negative(
            f"incomplete populations ({', '.join(missing)}): inconclusive, not refuted"
        )
    quiet = statistics.median(elapsed["quiet"])
    sleep = statistics.median(elapsed["sleep"])
    short = statistics.median(elapsed["dose_short"])
    long = statistics.median(elapsed["dose_long"])
    if sleep - quiet < MARGIN_SECONDS:
        return Elicitation.negative(
            f"sleep vs quiet differ by {sleep - quiet:.2f}s, below the "
            f"{MARGIN_SECONDS:.1f}s margin: no timing influence measured"
        )
    dose_gap = LONG_DOSE - SHORT_DOSE
    if long - short < DOSE_MARGIN_FRACTION * dose_gap:
        return Elicitation.negative(
            f"the delay does not track the dose (long-short = {long - short:.2f}s, "
            f"wanted >= {DOSE_MARGIN_FRACTION * dose_gap:.2f}s): a one-off spike, "
            "not a processing delay"
        )
    fact: CapabilityFact = fact_for(
        surface,
        CAP_DELAYED_RESPONSE,
        grade=EVIDENCE_DIFFERENTIAL,
        probe=probe_id(surface),
        at=at,
    )
    return Elicitation.positive(fact)


ELICITOR = Elicitor(
    name=NAME,
    manifest=MANIFEST,
    capability=CAP_DELAYED_RESPONSE,
    applies=applies,
    probes=probes,
    interpret=interpret,
)


__all__ = [
    "DOSE_MARGIN_FRACTION",
    "ELICITOR",
    "LONG_DOSE",
    "MANIFEST",
    "MARGIN_SECONDS",
    "NAME",
    "SAMPLES",
    "SHORT_DOSE",
    "applies",
    "interpret",
    "probe_id",
    "probes",
]
