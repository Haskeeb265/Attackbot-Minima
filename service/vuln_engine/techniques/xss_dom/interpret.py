"""Interpretation for ``xss_dom``: placements in, candidates out — leads mostly.

The module reads only ``observation.dom_placement`` rows (the wire lens's
reflection rows belong to ``xss_reflected``) and answers one question per
placement: *can this placement be confirmed, and by whom?*

Five honest outcomes, in the same spirit as the sibling technique's:

* **nothing to say** — no browser run, no placement rows, no candidate: the
  hypothesis was tested and the page said nothing worth recording;
* **a negative fact, recorded** — the canary reached the page (``present``)
  but no placement row was true: the value landed and the DOM did not parse it
  anywhere live. That is ``dom_absent`` as a *lead with a reason*, not a
  silence — exactly what a memory layer will one day generalise over;
* **a lead** — a placement exists but has no confirmation payload (text,
  unclassified attribute), or the placement is the ``dom_url_attribute`` one
  whose execution needs a user interaction the verifier does not simulate;
* **a candidate worth a browser** — the placement is markup or script state
  and the payload family has a confirmation spec for it. The evidence
  attached is ``semantic`` (a mapped placement), never a finding grade;
* **a duplicate** — the driver may hand us ``xss_reflected``'s reflection rows
  too (they ride the same observation list); a surface where the *wire* lens
  already found an executable reflection is the same attack path, and this
  technique claims no candidate for it.
"""

from __future__ import annotations

from ...kernel.evidence import EVIDENCE_SEMANTIC, Evidence
from ...kernel.observation import (
    CONTEXT_DOM_ABSENT,
    CONTEXT_DOM_URL_ATTRIBUTE,
    OBS_DOM_PLACEMENT,
    OBS_REFLECTION,
    Observation,
    is_executable_context,
)
from ...kernel.technique import Hypothesis
from ...kernel.verdict import Candidate
from . import probes as probe_grammar

NAME = "xss_dom"


def _placements(observations: list[Observation]) -> list[Observation]:
    """The placement rows, in the order the questions were asked."""
    return [item for item in observations if item.kind == OBS_DOM_PLACEMENT]


def _wire_reflected(observations: list[Observation]) -> bool:
    """True when the *wire* lens already found an unescaped reflection here.

    The dedupe rule's trigger: a server-side reflection in an executable
    context is the same attack path a DOM placement would propose, and the
    technique that found it first owns the candidate.
    """
    for item in observations:
        if item.kind != OBS_REFLECTION:
            continue
        payload = item.payload
        if payload.get("escaped_verbatim"):
            continue
        if payload.get("reflected") and is_executable_context(str(payload.get("context") or "")):
            return True
    return False


def candidates(hypothesis: Hypothesis, observations: list[Observation]) -> list[Candidate]:
    """Candidates this hypothesis's placement observations support."""
    if _wire_reflected(observations):
        # Same attack path, different lens: xss_reflected's candidate stands.
        return []
    placements = _placements(observations)
    surface = hypothesis.surface
    surface_dict = {
        "url": surface.url,
        "param": surface.param,
        "where": surface.where,
        "host": surface.host,
    }
    #: One id per *placement*, not per surface: a surface can yield several
    # candidates (markup, script state, a lead) and a verdict row resolves its
    # summary by candidate id — a collision would report one candidate's
    # summary under another's verdict, which is exactly the bug the first live
    # run caught.
    def _id(context: str) -> str:
        return (
            f"{NAME}:{surface.host}:{surface.url.split('//')[-1]}:"
            f"{surface.param}:{context}"
        )

    if not placements:
        return []

    contexts = {str(row.payload.get("context") or "") for row in placements}
    live = sorted(
        context for context in contexts if context and context != CONTEXT_DOM_ABSENT
    )

    if not live:
        # The value reached the page but the DOM parsed it nowhere live. A
        # recorded negative, not a silence.
        return [
            Candidate(
                id=_id(CONTEXT_DOM_ABSENT),
                technique=NAME,
                vuln_class="xss",
                surface=surface_dict,
                summary=(
                    f"parameter {surface.param!r} reached the rendered page but "
                    "the DOM holds it in no live placement (text/escaped only)"
                ),
                evidence=Evidence(
                    kind=OBS_DOM_PLACEMENT,
                    grade=EVIDENCE_SEMANTIC,
                    payload={"context": CONTEXT_DOM_ABSENT, "questions": sorted(
                        str(row.payload.get("question") or "") for row in placements
                    )},
                    probe=placements[0].probe,
                    at=placements[0].at,
                ),
                confirm={},
            )
        ]

    # One candidate per live placement, in the same order the rows arrived.
    # The id carries the context: a surface can yield several candidates and a
    # verdict row resolves its summary by candidate id, so two candidates must
    # never collide (the bug the first live run caught).
    out: list[Candidate] = []
    for row in placements:
        context = str(row.payload.get("context") or "")
        if not context or context == CONTEXT_DOM_ABSENT:
            continue
        if context == CONTEXT_DOM_URL_ATTRIBUTE:
            # A javascript: URL executes only on user interaction, which the
            # verifier does not simulate — so this placement is a lead with
            # the payload documented, never an auto-confirmed candidate.
            out.append(
                Candidate(
                    id=_id(context),
                    technique=NAME,
                    vuln_class="xss",
                    surface=surface_dict,
                    summary=(
                        f"parameter {surface.param!r} is placed in a URL-parsed "
                        "DOM attribute; a javascript: payload would execute on "
                        "user interaction, which no verifier in this phase simulates"
                    ),
                    evidence=Evidence(
                        kind=OBS_DOM_PLACEMENT,
                        grade=EVIDENCE_SEMANTIC,
                        payload=dict(row.payload),
                        probe=row.probe,
                        at=row.at,
                    ),
                    confirm={},
                )
            )
            continue
        spec = probe_grammar.execution_spec_for(hypothesis, context)
        if spec is None:
            out.append(
                Candidate(
                    id=_id(context),
                    technique=NAME,
                    vuln_class="xss",
                    surface=surface_dict,
                    summary=(
                        f"parameter {surface.param!r} is placed in the DOM as a "
                        f"{context.replace('_', ' ')} context, which has no "
                        "confirmation payload in this phase"
                    ),
                    evidence=Evidence(
                        kind=OBS_DOM_PLACEMENT,
                        grade=EVIDENCE_SEMANTIC,
                        payload=dict(row.payload),
                        probe=row.probe,
                        at=row.at,
                    ),
                    confirm={},
                )
            )
            continue
        markers = dict(spec.detail.get("markers") or {})
        url = str(spec.detail.get("url") or "")
        out.append(
            Candidate(
                id=_id(context),
                technique=NAME,
                vuln_class="xss",
                surface=surface_dict,
                summary=(
                    f"parameter {surface.param!r} is placed in the DOM as "
                    f"{context.replace('_', ' ')}, which a payload can execute from"
                ),
                evidence=Evidence(
                    kind=OBS_DOM_PLACEMENT,
                    grade=EVIDENCE_SEMANTIC,
                    payload=dict(row.payload),
                    probe=row.probe,
                    at=row.at,
                ),
                confirm={
                    "kind": "browser.run",
                    "url": url,
                    "markers": markers,
                    "context": context,
                    "dialog": probe_grammar.DIALOG_TEXT,
                },
                payload=spec.payload,
                repro_url=url,
            )
        )
    return out


#: The name the driver and the tests use for this function. Same alias as the
#: sibling technique's, for the same reason.
interpret = candidates


__all__ = ["NAME", "candidates", "interpret"]
