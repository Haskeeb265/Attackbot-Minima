"""``elicit.sessions`` — do the two declared identities see this object differently?

One request per identity on the operator-declared URL, compared on the same
basis the IDOR interpreter uses (status) plus the one it cannot use (content
shape, via the response byte length). A difference — either status or a
materially different body size — establishes ``access_differs_by_session`` for
the surface, which is what lets ``idor_differential`` and
``generic_differential``'s object-read plans fire without an operator claim.
"""

from __future__ import annotations

from ...kernel.capability import CapabilityFact
from ...kernel.evidence import EVIDENCE_DIFFERENTIAL
from ...kernel.observation import OBS_HTTP_RESPONSE, Observation
from ...kernel.technique import CAP_ACCESS_DIFFERS_BY_SESSION, Surface
from ..base import Elicitor
from ..common import Elicitation, fact_for
from .manifest import MANIFEST, NAME

#: Body-length difference fraction above which the two identities are said to
#: see *different content*, not the same page re-served. Deliberately coarse:
#: the fact only opens a door; the authorization verifier is the instrument
#: that will judge content properly when a candidate exists.
LENGTH_DELTA_FRACTION = 0.5

#: Statuses that count as "denied" for the difference question.
DENIED = frozenset({301, 302, 303, 307, 308, 401, 403, 404})


def probe_id(surface: Surface, session: str) -> str:
    return f"{NAME}:{surface.host}:{surface.param}:{session}"


def applies(surface: Surface) -> bool:
    """Any object URL works — with or without a parameter (an IDOR surface
    usually has none)."""
    return True


def probes(surface: Surface) -> list[dict]:
    """One request per identity; session B asks for the ``_session`` shim."""
    specs: list[dict] = []
    for session in ("a", "b"):
        detail: dict = {"url": surface.url, "method": "GET"}
        if session == "b":
            detail["_session"] = "b"
        specs.append(
            {
                "id": probe_id(surface, session),
                "kind": "http.request",
                "host": surface.host,
                "detail": detail,
                "canary": "",
                "mark": "",
                "population": session,
            }
        )
    return specs


def interpret(
    surface: Surface, observations: list[Observation], *, at: float = 0.0
) -> Elicitation:
    """A status or content-shape difference between the identities is the fact."""
    pid_a = probe_id(surface, "a")
    pid_b = probe_id(surface, "b")
    row_a = _single(observations, pid_a)
    row_b = _single(observations, pid_b)
    if row_a is None or row_b is None:
        return Elicitation.negative(
            "an identity's request was refused or errored: inconclusive, not refuted"
        )
    status_a = row_a.payload.get("status")
    status_b = row_b.payload.get("status")
    if not isinstance(status_a, int) or not isinstance(status_b, int):
        return Elicitation.negative("a response arrived without a status")
    allowed_a = 200 <= status_a < 300
    allowed_b = 200 <= status_b < 300
    differs = allowed_a != allowed_b
    if not differs and allowed_a:
        length_a = row_a.payload.get("bytes")
        length_b = row_b.payload.get("bytes")
        if isinstance(length_a, int) and isinstance(length_b, int) and max(length_a, length_b) > 0:
            fraction = abs(length_a - length_b) / max(length_a, length_b)
            differs = fraction >= LENGTH_DELTA_FRACTION
    if not differs:
        return Elicitation.negative(
            f"both identities answered alike (A={status_a}, B={status_b}): no "
            "session boundary measured here"
        )
    fact: CapabilityFact = fact_for(
        surface,
        CAP_ACCESS_DIFFERS_BY_SESSION,
        grade=EVIDENCE_DIFFERENTIAL,
        probe=pid_a,
        at=at,
    )
    return Elicitation.positive(fact)


def _single(observations: list[Observation], probe: str) -> Observation | None:
    """The one http observation from *probe* whose payload has a status."""
    rows = [
        item
        for item in observations
        if item.kind == OBS_HTTP_RESPONSE
        and item.probe == probe
        and item.payload.get("status") is not None
    ]
    return rows[-1] if rows else None


ELICITOR = Elicitor(
    name=NAME,
    manifest=MANIFEST,
    capability=CAP_ACCESS_DIFFERS_BY_SESSION,
    applies=applies,
    probes=probes,
    interpret=interpret,
)


__all__ = [
    "DENIED",
    "ELICITOR",
    "LENGTH_DELTA_FRACTION",
    "MANIFEST",
    "NAME",
    "applies",
    "interpret",
    "probe_id",
    "probes",
]
