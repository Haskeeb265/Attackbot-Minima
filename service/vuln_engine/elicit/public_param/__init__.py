"""``elicit.public_param`` — is this parameter client-settable, measurably?

The engine's cheapest capability was also the only gated one nobody could
measure: ``public_param`` appears in more technique preconditions than any other
claim, the graph derives it for *observed* parameters only, and Capability
Closure used to skip it silently (no elicitor answered it), leaving every
surface the operator or the graph did not vouch for a dead arm.

The measurement is a *paired* request, the same honesty rule the timing and
session elicitors apply — one request proves nothing about a parameter's
influence:

* **present** — the surface's own parameter carries our canary;
* **absent** — the identical request carries a parameter name nothing observes.

The pair differs ⇒ the server read *our* name and did something with it: the
parameter is client-settable, established at ``differential`` grade. The pair
agrees byte-for-byte ⇒ no measured influence; the claim stays unestablished and
the negative is recorded (a server may still read the parameter in some other
state — this elicitor records what it could measure, not everything that is
true).

The canary is the reflection elicitor's own spelling: the two elicitors may
both run on a surface, and a log that can tell whose canary it was can tell
which measurement answered what.
"""

from __future__ import annotations

from ...kernel.capability import CapabilityFact
from ...kernel.evidence import EVIDENCE_DIFFERENTIAL
from ...kernel.observation import OBS_HTTP_RESPONSE, Observation
from ...kernel.technique import CAP_PUBLIC_PARAM, Surface
from ..base import Elicitor
from ..common import Elicitation, fact_for
from .manifest import MANIFEST, NAME

#: The canary the *present* request carries — the reflection elicitor's own
#: mark, so a log can tell whose question a reflection row answered.
CANARY = "ve-elicitor-<>=\"'"
#: The name the *absent* request carries instead — deliberately not a parameter
#: the target was ever observed to read.
ABSENT_NAME = "ve-elicitor-absent"

_PRESENT_SUFFIX = ":present"
_ABSENT_SUFFIX = ":absent"


def applies(surface: Surface) -> bool:
    """Any parameterised surface can be asked whether its parameter is settable."""
    return bool(surface.param) and surface.where in ("query", "body", "path")


def probes(surface: Surface) -> list[dict]:
    """The pair: the parameter carrying the canary, then an unobserved name."""
    from ...kernel.technique import KIND_HTTP
    from ..common_probe import request_detail

    probe = f"{NAME}:{surface.host}:{surface.param}"
    return [
        {
            "id": f"{probe}{_PRESENT_SUFFIX}",
            "kind": KIND_HTTP,
            "host": surface.host,
            "detail": request_detail(surface, surface.param, CANARY),
            "canary": CANARY,
            "mark": "ve-elicitor",
        },
        {
            "id": f"{probe}{_ABSENT_SUFFIX}",
            "kind": KIND_HTTP,
            "host": surface.host,
            "detail": request_detail(surface, ABSENT_NAME, CANARY),
        },
    ]


def _response_of(
    observations: list[Observation], probe_id: str
) -> dict | None:
    """The named request's response payload, or ``None`` when it never answered."""
    for item in observations:
        if item.kind == OBS_HTTP_RESPONSE and item.probe == probe_id:
            return dict(item.payload)
    return None


def interpret(
    surface: Surface, observations: list[Observation], *, at: float = 0.0
) -> Elicitation:
    """A pair that differs proves the parameter influences the response."""
    probe = f"{NAME}:{surface.host}:{surface.param}"
    present = _response_of(observations, f"{probe}{_PRESENT_SUFFIX}")
    absent = _response_of(observations, f"{probe}{_ABSENT_SUFFIX}")
    if present is None or absent is None:
        return Elicitation.negative(
            "the paired measurement is incomplete: no influence was measured"
        )
    if not present.get("ok") or not absent.get("ok"):
        return Elicitation.negative(
            "one half of the pair errored, so no influence was measured"
        )
    if present.get("status") == absent.get("status") and present.get(
        "bytes"
    ) == absent.get("bytes"):
        return Elicitation.negative(
            (
                "the parameter's value did not change the response "
                f"(status {absent.get('status')}, {absent.get('bytes')} bytes both ways): "
                "no influence measured on this surface in this state"
            )
        )
    fact: CapabilityFact = fact_for(
        surface,
        CAP_PUBLIC_PARAM,
        grade=EVIDENCE_DIFFERENTIAL,
        probe=f"{probe}{_PRESENT_SUFFIX}",
        at=at,
    )
    return Elicitation.positive(fact)


ELICITOR = Elicitor(
    name=NAME,
    manifest=MANIFEST,
    capability=CAP_PUBLIC_PARAM,
    applies=applies,
    probes=probes,
    interpret=interpret,
)


__all__ = [
    "ABSENT_NAME",
    "CANARY",
    "ELICITOR",
    "MANIFEST",
    "NAME",
    "applies",
    "interpret",
    "probes",
]
