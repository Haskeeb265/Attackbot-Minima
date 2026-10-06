"""``elicit.storage`` — does this surface keep what it is given and serve it back?

The two-request question ``xss_stored`` needs answered before it spends its
louder two-page grammar: submit a unique canary, then read the surface back
(the surface's ``read_back`` URL, or its own URL when none was declared). The
canary returning on the read-back is the fact. A read that happens immediately,
in the same response, is *reflection*, not storage — the canary must come back
on a different request than the one that carried it.
"""

from __future__ import annotations

from ...kernel.capability import CapabilityFact
from ...kernel.evidence import EVIDENCE_REFLECTION
from ...kernel.observation import OBS_REFLECTION, Observation
from ...kernel.technique import CAP_PERSISTENT_STORAGE, Surface
from ..base import Elicitor
from ..common import Elicitation, fact_for
from .manifest import MANIFEST, NAME

#: The storage canary — unique enough that an immediate reflection of it on
#: the submit response cannot be confused with the read-back answer (the
#: reflection row's *probe* tells them apart in the log).
CANARY = "ve-store-7c31"


def probe_id(surface: Surface, leg: str) -> str:
    return f"{NAME}:{surface.host}:{surface.param}:{leg}"


def applies(surface: Surface) -> bool:
    return bool(surface.param) and surface.where in ("query", "body", "path")


def probes(surface: Surface) -> list[dict]:
    """Submit (POST with companions) then read back, in that order."""
    from ..common_probe import request_detail

    submit = request_detail(surface, surface.param, CANARY)
    read_back_url = surface.read_back or surface.url
    return [
        {
            "id": probe_id(surface, "submit"),
            "kind": "http.request",
            "host": surface.host,
            "detail": submit,
            "canary": "",
            "mark": "",
        },
        {
            "id": probe_id(surface, "readback"),
            "kind": "http.request",
            "host": surface.host,
            "detail": {"url": read_back_url, "method": "GET"},
            "canary": CANARY,
            "mark": CANARY,
        },
    ]


def interpret(
    surface: Surface, observations: list[Observation], *, at: float = 0.0
) -> Elicitation:
    """The canary on the *read-back* request is the fact; the submit's own
    reflection is deliberately not — same-request echo is reflection, not
    storage."""
    readback = probe_id(surface, "readback")
    stored = any(
        item.kind == OBS_REFLECTION
        and item.probe == readback
        and (item.payload.get("reflected") or item.payload.get("transformed"))
        for item in observations
    )
    if not stored:
        return Elicitation.negative(
            "the submitted canary did not come back on the read-back request"
        )
    fact: CapabilityFact = fact_for(
        surface,
        CAP_PERSISTENT_STORAGE,
        grade=EVIDENCE_REFLECTION,
        probe=readback,
        at=at,
    )
    return Elicitation.positive(fact)


ELICITOR = Elicitor(
    name=NAME,
    manifest=MANIFEST,
    capability=CAP_PERSISTENT_STORAGE,
    applies=applies,
    probes=probes,
    interpret=interpret,
)


__all__ = ["CANARY", "ELICITOR", "MANIFEST", "NAME", "applies", "interpret", "probe_id", "probes"]
