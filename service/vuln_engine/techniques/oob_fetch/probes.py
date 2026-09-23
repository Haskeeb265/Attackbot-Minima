"""The probe grammar for a blind server-side fetch.

One probe, and it carries two things at once:

**the collaborator URL** — a per-probe URL that only this probe knows, so an
interaction that arrives can be attributed to *this* attempt without a lookup
table. It travels as a sentinel
(:func:`...kernel.technique.oob_sentinel`), not as a real URL, because a technique
is pure and cannot ask the OOB transport for anything. The driver substitutes the
real URL just before the request is built.

**the echo canary** — the body the collaborator returns for that probe. If the
response to our request *contains* that body, the server very likely fetched our
URL: a lead, in the reflection class. It is explicitly not the finding. A cached
page, a proxy error quoting our input, or a reflected parameter can all produce
that echo without the server having fetched anything — and the interaction record
cannot be produced by any of them.

The oracle is therefore :data:`ORACLE_REFLECTION` here and
:data:`ORACLE_OOB_INTERACTION` for the verifier. Two oracles for one attempt, in
two different classes, which is the whole shape of independent verification.
"""

from __future__ import annotations

from ...kernel.technique import (
    KIND_HTTP,
    ORACLE_REFLECTION,
    Hypothesis,
    ProbeSpec,
    oob_sentinel,
)
from ..common import with_parameter

NAME = "oob_fetch"

#: What our collaborator answers on an ``/oob/<probe>`` path.  The probe id is
#: appended so the echo is per-probe: a body that an old interaction or a cached
#: page could satisfy would be worthless as a lead.
COLLABORATOR_TOKEN = "vuln-engine-collaborator"

#: The probe id, as one string, so the sentinel, the request and the
#: confirmation all name the same attempt.
def probe_id(hypothesis: Hypothesis) -> str:
    return f"{NAME}:{hypothesis.surface.host}:{hypothesis.surface.param}"


def echo_token(probe: str) -> str:
    """The collaborator response body a successful fetch would bring back."""
    return f"{COLLABORATOR_TOKEN}:{probe}"


def collaborator_path(probe: str) -> str:
    """The path the interaction must have arrived on."""
    return f"/oob/{probe}"


def probes(hypothesis: Hypothesis) -> list[ProbeSpec]:
    """The single triggering probe for *hypothesis*."""
    surface = hypothesis.surface
    probe = probe_id(hypothesis)
    sentinel = oob_sentinel(probe)
    return [
        ProbeSpec(
            id=probe,
            kind=KIND_HTTP,
            host=surface.host,
            detail={
                "url": with_parameter(surface.url, surface.param, sentinel),
                "method": "GET",
            },
            oracle=ORACLE_REFLECTION,
            # The canary is the collaborator's own answer: if it comes back in the
            # response, something on the far side spoke to our collaborator.
            canary=echo_token(probe),
            mark=COLLABORATOR_TOKEN,
            noise={
                "requests_per_surface": 1,
                "burstiness": 0.0,
                "fingerprint_distance": 0.0,
                "requires_browser": False,
            },
            produces="reflection",
        )
    ]


__all__ = [
    "COLLABORATOR_TOKEN",
    "NAME",
    "collaborator_path",
    "echo_token",
    "probe_id",
    "probes",
]
