"""The probe grammar for stored XSS, as data.

Two HTTP probes, and the *pair* is the proposal:

**the inject** — a POST of the canary to the store surface, carrying the
operator-declared companion fields (a guestbook's submit button is part of the
surface's protocol, not part of any payload). Its oracle is trivially an HTTP
fact; the probe produces no observation anyone reasons over. What matters is
that it happened *before* the read-back.

**the read-back** — a quiet GET of the page where stored input renders. This is
the probe the whole technique proposes from: the observation layer reads the
reflected canary out of the read-back response and names its context, exactly as
it does for a reflected parameter. Every executable context the wire lens
already knows maps to the same breakout payload the reflected grammar uses —
the context decides the payload, not the transport that delivered the input.

Notice what is *not* here: confirmation. The browser run that would prove
execution is a two-step operation (re-inject, then read back), and a probe spec
is one request — so the confirmation lives on the candidate as a
``xss_stored.execute`` spec and a different module (the verifier) runs both
steps. A technique that confirmed itself in its own probe grammar would be a
closed loop with extra steps.
"""

from __future__ import annotations

from ...kernel.technique import (
    KIND_HTTP,
    ORACLE_REFLECTION,
    PURPOSE_PROPOSE,
    Hypothesis,
    ProbeSpec,
)
from ..xss_reflected import probes as reflected_grammar

NAME = "xss_stored"

#: The canary, shared with the reflected grammar on purpose: the observation
#: layer's reflection search and the transformed-mark detection are calibrated
#: to this string's shape, and two canaries would mean two calibrations.
CANARY = reflected_grammar.CANARY
MARK = reflected_grammar.MARK


def _form_body(surface, param: str, value: str) -> str:
    """The urlencoded body for a POST storing *value* in *param*.

    Companion fields are the operator's declaration of the surface's protocol:
    a real guestbook ignores a POST without its submit-button field, and a
    technique that "failed to store" against such a target would actually have
    failed to *speak the form's language*. Bodies are percent-encoded, so a
    payload full of quotes and angle brackets arrives as the characters we meant.
    """
    from urllib.parse import quote

    pairs = [(param, value)]
    for name, fixed in (surface.companions or {}).items():
        if name != param:
            pairs.append((name, fixed))
    return "&".join(f"{quote(name, safe='')}={quote(item, safe='')}" for name, item in pairs)


def inject_spec(hypothesis: Hypothesis, param: str, value: str) -> ProbeSpec:
    """The POST that stores *value* in *param* on the hypothesis's surface."""
    surface = hypothesis.surface
    return ProbeSpec(
        id=f"{NAME}:inject",
        kind=KIND_HTTP,
        host=surface.host,
        detail={
            "url": surface.url,
            "method": "POST",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "content": _form_body(surface, param, value),
        },
        # The inject's answer is an HTTP status, not a reflection: whatever came
        # back, what we reason over is the read-back.
        oracle="",
        noise={
            "requests_per_surface": 1,
            "burstiness": 0.0,
            "fingerprint_distance": 0.0,
            "requires_browser": False,
        },
        produces="hypothesis",
    )


def read_back_spec(hypothesis: Hypothesis) -> ProbeSpec:
    """The quiet GET of the page where stored input renders — the proposal."""
    surface = hypothesis.surface
    read_back = surface.read_back or surface.url
    return ProbeSpec(
        id=f"{NAME}:readback",
        kind=KIND_HTTP,
        host=surface.host,
        detail={"url": read_back, "method": "GET"},
        oracle=ORACLE_REFLECTION,
        canary=CANARY,
        mark=MARK,
        noise={
            "requests_per_surface": 1,
            "burstiness": 0.0,
            "fingerprint_distance": 0.0,
            "requires_browser": False,
        },
        produces="reflection",
    )


def probes(hypothesis: Hypothesis) -> list[ProbeSpec]:
    """Every probe for *hypothesis*: the inject, then the read-back.

    Order matters and is the technique's semantics: the read-back must observe
    what *this* round stored, so the inject always goes first. The driver sorts
    HTTP probes by id within a round — ``inject`` < ``readback`` alphabetically —
    so the ids are chosen to make the driver's stable ordering coincide with the
    semantic ordering rather than fight it.
    """
    surface = hypothesis.surface
    return [
        inject_spec(hypothesis, surface.param, CANARY),
        read_back_spec(hypothesis),
    ]


__all__ = ["CANARY", "MARK", "NAME", "inject_spec", "probes", "read_back_spec"]
