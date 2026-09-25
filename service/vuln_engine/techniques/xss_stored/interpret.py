"""Interpretation: turning the read-back's observations into candidates.

The mirror of ``xss_reflected``'s interpret, with one structural difference at
the top: the read-back page is a *shared* surface — a guestbook renders every
entry ever stored — so a previous round's canary can still be sitting there.
This module reads only this round's observations, and a candidate it produces
is a *proposal*: the confirmation spec re-injects the payload and makes a
browser prove execution, so a stale entry can at worst shape a lead, never a
finding — the verifier's fresh two-step run is the finding's only source.

From there the logic is the reflected grammar's, deliberately: the context
decides everything. An executable context produces a candidate whose
confirmation spec is the **two-step** one — ``xss_stored.execute`` names the
inject (payload + companions) and the read-back page — because execution can
only be proven by putting the payload back and running the page a browser
fetches. A context with no breakout is a lead with no confirmation spec,
recorded and never promoted, exactly as the wire lens does it.
"""

from __future__ import annotations

from ...kernel.evidence import EVIDENCE_REFLECTION, EVIDENCE_SEMANTIC, Evidence
from ...kernel.observation import (
    CONTEXT_JSON_VALUE,
    CONTEXT_UNKNOWN,
    OBS_REFLECTION,
    Observation,
)
from ...kernel.technique import CONFIRM_STORED_EXECUTE, Hypothesis
from ...kernel.verdict import Candidate
from ..common import surface_id_prefix
from ..xss_reflected import probes as reflected_grammar
from . import probes as probe_grammar

NAME = "xss_stored"


def _reflection(observations: list[Observation]) -> Observation | None:
    """The read-back's *reflected* observation, or ``None``.

    Transformed-only does not count, matching the reflected grammar's
    semantics: bytes the server rewrote are a fact about a filter, not a
    reflection of what we sent. A stale entry from a previous round can still
    satisfy this check — the read-back page renders everything ever stored —
    which is why every candidate here stays a proposal until the verifier's
    fresh two-step run proves it.
    """
    for item in reversed(observations):
        if item.kind == OBS_REFLECTION and item.payload.get("reflected"):
            return item
    return None


def candidates(hypothesis: Hypothesis, observations: list[Observation]) -> list[Candidate]:
    """Candidates this hypothesis's observations support.  Usually zero or one."""
    reflection = _reflection(observations)
    if reflection is None:
        return []
    payload = reflection.payload
    if payload.get("escaped_verbatim"):
        # Escaped bytes on the read-back page are a negative result for this
        # class, exactly as they are on a wire reflection: reporting them as a
        # reflection would be the classic false lead.
        return []

    surface = hypothesis.surface
    context = str(payload.get("context") or CONTEXT_UNKNOWN)
    occurrences = int(payload.get("occurrences") or 0)
    grade = EVIDENCE_REFLECTION if context == CONTEXT_UNKNOWN else EVIDENCE_SEMANTIC
    read_back = surface.read_back or surface.url
    surface_dict = {
        "url": surface.url,
        "param": surface.param,
        "where": surface.where,
        "host": surface.host,
        "read_back": read_back,
    }
    candidate_id = surface_id_prefix(NAME, surface)

    spec = reflected_grammar.execution_spec_for(hypothesis, context)
    if spec is None:
        if context == CONTEXT_JSON_VALUE:
            summary = (
                f"stored input in {surface.param!r} renders {occurrences} time(s) in a "
                "JSON document on the read-back page; whether it reaches a client-side "
                "sink is a question for the DOM lens, not the wire lens"
            )
        else:
            summary = (
                f"stored input in {surface.param!r} renders in a "
                f"{context.replace('_', ' ')} context on the read-back page, and no "
                "confirmation payload breaks out of that context"
            )
        return [
            Candidate(
                id=candidate_id,
                technique=NAME,
                vuln_class="xss",
                surface=surface_dict,
                summary=summary,
                evidence=Evidence(
                    kind=OBS_REFLECTION,
                    grade=grade,
                    payload=dict(payload),
                    probe=reflection.probe,
                    at=reflection.at,
                ),
                confirm={},
            )
        ]

    payload_value = reflected_grammar.payload_for(hypothesis, context)
    inject = probe_grammar.inject_spec(hypothesis, surface.param, payload_value)
    markers = dict(spec.detail.get("markers") or {})
    return [
        Candidate(
            id=candidate_id,
            technique=NAME,
            vuln_class="xss",
            surface=surface_dict,
            summary=(
                f"stored input in {surface.param!r} renders {occurrences} time(s) in a "
                f"{context.replace('_', ' ')} context on the read-back page, which a "
                "script tag can break out of"
            ),
            evidence=Evidence(
                kind=OBS_REFLECTION,
                grade=grade,
                payload=dict(payload),
                probe=reflection.probe,
                at=reflection.at,
            ),
            confirm={
                "kind": CONFIRM_STORED_EXECUTE,
                "inject": {
                    "url": inject.detail["url"],
                    "method": "POST",
                    "headers": dict(inject.detail["headers"]),
                    "content": inject.detail["content"],
                },
                "read_back": read_back,
                "markers": markers,
                "context": context,
                "dialog": reflected_grammar.DIALOG_TEXT,
            },
            payload=payload_value,
            repro_url=read_back,
        )
    ]


#: The name the driver and the tests use for this function.
interpret = candidates


__all__ = ["NAME", "candidates", "interpret"]
