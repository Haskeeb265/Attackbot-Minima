"""``elicit.remote_fetch`` — will the server fetch a URL we supply?

One request carrying the collaborator URL (as the sentinel the driver
substitutes), answered by the one instrument that cannot be faked: an
interaction record on our own collaborator. This is the elicitor that turns
the graph bridge's name-heuristic SSRF claim (``REMOTE_FETCH_PARAM_HINTS``)
into a measured fact — and the one that lets ``oob_fetch`` fire on a surface
nobody declared as remote-fetch-capable.
"""

from __future__ import annotations

from ...kernel.capability import CapabilityFact
from ...kernel.evidence import EVIDENCE_OOB
from ...kernel.observation import OBS_OOB_INTERACTION, Observation
from ...kernel.technique import (
    CAP_INFLUENCE_REMOTE_FETCH,
    Surface,
    oob_sentinel,
)
from ..base import Elicitor
from ..common import Elicitation, fact_for
from .manifest import MANIFEST, NAME

#: The name hints the graph bridge uses, reused here so an operator-declared
#: surface with a URL-shaped parameter name gets the same treatment as a
#: graph-derived one. A hint is a *priority* signal, not a requirement: the
#: elicitor runs wherever the closure pass sends it.
NAME_HINTS: frozenset[str] = frozenset(
    {"url", "uri", "href", "redirect", "callback", "webhook", "feed", "next"}
)


def applies(surface: Surface) -> bool:
    """URL-shaped parameters first; any parameterised surface is allowed."""
    return bool(surface.param) and surface.where in ("query", "body", "path")


def probe_id(surface: Surface) -> str:
    return f"{NAME}:{surface.host}:{surface.param}"


def probes(surface: Surface) -> list[dict]:
    """One request carrying the collaborator URL as the parameter's value."""
    from ..common_probe import request_detail

    probe = probe_id(surface)
    return [
        {
            "id": probe,
            "kind": "http.request",
            "host": surface.host,
            "detail": request_detail(surface, surface.param, oob_sentinel(probe)),
            "canary": "",
            "mark": "",
        }
    ]


def interpret(
    surface: Surface, observations: list[Observation], *, at: float = 0.0
) -> Elicitation:
    """An interaction record on this probe's collaborator path is the fact."""
    probe = probe_id(surface)
    interactions = [
        item
        for item in observations
        if item.kind == OBS_OOB_INTERACTION and item.probe == probe
    ]
    if not interactions:
        return Elicitation.negative(
            "no interaction arrived on the collaborator (inconclusive or refused)"
        )
    fact: CapabilityFact = fact_for(
        surface,
        CAP_INFLUENCE_REMOTE_FETCH,
        grade=EVIDENCE_OOB,
        probe=probe,
        at=at,
    )
    return Elicitation.positive(fact)


ELICITOR = Elicitor(
    name=NAME,
    manifest=MANIFEST,
    capability=CAP_INFLUENCE_REMOTE_FETCH,
    applies=applies,
    probes=probes,
    interpret=interpret,
)


__all__ = ["ELICITOR", "MANIFEST", "NAME", "NAME_HINTS", "applies", "interpret", "probe_id", "probes"]
