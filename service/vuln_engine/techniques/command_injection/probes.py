"""The probe grammar for blind OS command injection via a timing side channel.

Two populations, cheapest first, alternating so drifting server load hits both:

**the baseline** — one quiet request, repeated ``SAMPLES_PER_POPULATION`` times.
``QUIET_PAYLOAD`` is a benign token with no shell meaning: its only job is to
measure the target's ordinary response time on this parameter.

**the injected family** — a benign base value followed by a shell metacharacter
and a delay command, one two-sample population per *interpolation shape*. A
single payload cannot cover a shell grammar the way one SQL string cannot: how
the parameter is interpolated decides which metacharacter takes effect, so the
family is defined by shape — the property of the *class* — never by a target's
name or dialect:

* ``semicolon`` — ``{b}; sleep d``    (a following command always runs)
* ``pipe``      — ``{b}| sleep d``     (the delay command becomes the pipeline)
* ``and``       — ``{b}&& sleep d``    (runs when the base command succeeds)
* ``subshell``  — ``{b}$(sleep d)``    (command substitution, no separator needed)
* ``backtick``  — ``{b}`sleep d`       (the older substitution spelling)

Every variant asks for the same delay; the shapes the target's interpolation
does not honour return fast, which is exactly what makes the comparison honest:
the variant that separates is the one whose metacharacter the target's shell
processed. The interpreter picks the winning variant and carries its payloads in
the candidate's confirmation spec, so the verifier re-measures the *same* shell
text it proposed — never a second copy of the table that could drift.

The base token is deliberately inert and target-independent (``ve-noop0``); a
target that needs a well-formed value for its base command simply fails that
command fast, and the metacharacter still separates.
"""

from __future__ import annotations

from ...kernel.technique import (
    KIND_HTTP,
    ORACLE_TIMING_DIFFERENTIAL,
    PURPOSE_PROPOSE,
    Hypothesis,
    ProbeSpec,
)
from ..common import json_body_request, with_parameter

NAME = "command_injection"

#: The baseline: a benign token with no shell metacharacter and no command.
QUIET_PAYLOAD = "ve-noop0"

#: The delay every variant asks for, in seconds. One number, declared once: the
#: margin (the interpreter's) and the target's latency both read against it.
SLEEP_SECONDS = 4.0

#: Samples per population, alternating.
SAMPLES_PER_POPULATION = 2

#: The inert base the metacharacter is appended to. Target-independent on
#: purpose — a technique that shipped a target's own value would be a lookup
#: table wearing a technique's clothes.
BASE_VALUE = "ve-noop0"

#: The injected family: one interpolation shape and its shell text. ``{b}`` is
#: the base value, ``{d}`` the delay. Defined by shape, not by target.
PAYLOAD_VARIANTS: tuple[tuple[str, str], ...] = (
    ("semicolon", "{b}; sleep {d}"),
    ("pipe", "{b}| sleep {d}"),
    ("and", "{b}&& sleep {d}"),
    ("subshell", "{b}$(sleep {d})"),
    ("backtick", "{b}`sleep {d}`"),
)

#: The body-transport family, for a JSON-API surface whose parameter lives in
#: the request body. The shapes are the same; only the transport differs.
BODY_VARIANTS: tuple[tuple[str, str], ...] = (
    ("json_semicolon", "{b}; sleep {d}"),
    ("json_pipe", "{b}| sleep {d}"),
    ("json_and", "{b}&& sleep {d}"),
    ("json_subshell", "{b}$(sleep {d})"),
    ("json_backtick", "{b}`sleep {d}`"),
)

TIMING_BASELINE = "baseline"
TIMING_INJECTED = "injected"


def probe_id(hypothesis: Hypothesis) -> str:
    return f"{NAME}:{hypothesis.surface.host}:{hypothesis.surface.param}"


def _render(template: str) -> str:
    return template.replace("{b}", BASE_VALUE).replace("{d}", str(SLEEP_SECONDS))


def variant_payload(variant: str) -> str:
    """The shell text for *variant*, or ``""`` when the name is not in a table."""
    for name, template in PAYLOAD_VARIANTS + BODY_VARIANTS:
        if name == variant:
            return _render(template)
    return ""


def _detail(hypothesis: Hypothesis, payload: str, timing_class: str) -> dict:
    """One probe's request detail, shaped by where the parameter lives."""
    surface = hypothesis.surface
    if surface.where == "body":
        url, headers, content = json_body_request(surface, surface.param, payload)
        return {
            "url": url,
            "method": "POST",
            "headers": headers,
            "content": content,
            "timing_class": timing_class,
        }
    return {
        "url": with_parameter(surface.url, surface.param, payload),
        "method": "GET",
        "timing_class": timing_class,
    }


def probes(hypothesis: Hypothesis) -> list[ProbeSpec]:
    """The alternating baseline and injected populations, in send order."""
    surface = hypothesis.surface
    probe = probe_id(hypothesis)
    variants = BODY_VARIANTS if surface.where == "body" else PAYLOAD_VARIANTS
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
        for variant, template in variants:
            specs.append(
                ProbeSpec(
                    id=f"{probe}:{TIMING_INJECTED}:{variant}:{index}",
                    kind=KIND_HTTP,
                    host=surface.host,
                    detail=_detail(hypothesis, _render(template), TIMING_INJECTED),
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
    "BASE_VALUE",
    "BODY_VARIANTS",
    "NAME",
    "PAYLOAD_VARIANTS",
    "QUIET_PAYLOAD",
    "SAMPLES_PER_POPULATION",
    "SLEEP_SECONDS",
    "TIMING_BASELINE",
    "TIMING_INJECTED",
    "probe_id",
    "probes",
    "variant_payload",
]
