"""``elicit.reflection`` — can a client-set parameter put our canary in the response?

The cheapest question the engine can ask a surface: one GET with a distinctive
canary, read with the same reflection classifier the XSS techniques use. A
positive answer establishes ``http_response_reflects_input`` at ``reflection``
grade — which opens the door for ``xss_reflected``/``xss_dom`` on a surface whose
declared claim was only ``public_param`` (or nothing at all). The XSS technique
still does its own canary and its own context parsing; this elicitor only
measures whether the door is worth walking through.
"""

from __future__ import annotations

from ...kernel.capability import CapabilityFact
from ...kernel.evidence import EVIDENCE_REFLECTION
from ...kernel.observation import OBS_REFLECTION, Observation
from ...kernel.technique import CAP_RESPONSE_REFLECTS_INPUT, Surface
from ..base import Elicitor
from ..common import Elicitation, fact_for
from .manifest import MANIFEST, NAME

#: The elicitor's own canary, distinct from the XSS techniques' so the two
#: questions never answer each other in a log: this spelling measures
#: reflection-for-reflection's-sake, not a payload's placement.
CANARY = "ve-elicitor-<>=\"'"
MARK = "ve-elicitor"


def applies(surface: Surface) -> bool:
    """Any parameterised surface can be asked whether it reflects."""
    return bool(surface.param) and surface.where in ("query", "body", "path")


def probes(surface: Surface) -> list[dict]:
    """One quiet GET carrying the elicitor's own canary."""
    from ...kernel.technique import KIND_HTTP
    from ..common_probe import request_detail

    return [
        {
            "id": f"{NAME}:{surface.host}:{surface.param}",
            "kind": KIND_HTTP,
            "host": surface.host,
            "detail": request_detail(surface, surface.param, CANARY),
            "canary": CANARY,
            "mark": MARK,
        }
    ]


def interpret(
    surface: Surface, observations: list[Observation], *, at: float = 0.0
) -> Elicitation:
    """A reflection row from this probe establishes the capability; else a negative."""
    probe_id = f"{NAME}:{surface.host}:{surface.param}"
    reflected = any(
        item.kind == OBS_REFLECTION
        and item.probe == probe_id
        and (item.payload.get("reflected") or item.payload.get("transformed"))
        for item in observations
    )
    if not reflected:
        return Elicitation.negative("the canary did not come back")
    fact: CapabilityFact = fact_for(
        surface,
        CAP_RESPONSE_REFLECTS_INPUT,
        grade=EVIDENCE_REFLECTION,
        probe=probe_id,
        at=at,
    )
    return Elicitation.positive(fact)


ELICITOR = Elicitor(
    name=NAME,
    manifest=MANIFEST,
    capability=CAP_RESPONSE_REFLECTS_INPUT,
    applies=applies,
    probes=probes,
    interpret=interpret,
)


__all__ = ["CANARY", "ELICITOR", "MANIFEST", "MARK", "NAME", "applies", "interpret", "probes"]
