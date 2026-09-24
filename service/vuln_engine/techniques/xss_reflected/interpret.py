"""Interpretation: turning typed observations into candidates a verifier can act on.

Pure, and deliberately unambitious. Three outcomes, and the difference between
them is the whole point of the module:

* **nothing to say** — the value did not come back. No candidate: a hypothesis
  that was tested and refuted is not a finding and not a lead either;
* **a lead** — the value came back but in a context nothing can be confirmed from
  (a comment, inside a tag name, or a document the scanner could not place). A
  candidate is emitted with **no confirmation spec**, and the verifier refuses it
  with that reason. That is what a lead looks like in this design: recorded, not
  promoted, and visible in the report as "proposed on reflection, unconfirmed";
* **a candidate worth a browser** — the value came back inside a context a payload
  can break out of. The candidate carries the payload, the marker to look for and
  a reproducible URL, and the *verifier* runs the loud half.

The evidence this module attaches is the proposer's, and it is never a finding
grade: ``semantic`` when the reflection's context was parsed, ``reflection`` when
it was not. The execution class is reserved for the verifier, by construction and
by ``verdict.check_independence``.
"""

from __future__ import annotations

from ...kernel.evidence import EVIDENCE_REFLECTION, EVIDENCE_SEMANTIC, Evidence
from ...kernel.observation import CONTEXT_UNKNOWN, OBS_REFLECTION, Observation
from ...kernel.technique import Hypothesis
from ...kernel.verdict import Candidate
from ..common import surface_id_prefix, with_parameter
from . import probes as probe_grammar

NAME = "xss_reflected"


def _reflection(observations: list[Observation]) -> Observation | None:
    """The last reflection observation, or ``None`` when there was none."""
    found = [item for item in observations if item.kind == OBS_REFLECTION]
    return found[-1] if found else None


def candidates(hypothesis: Hypothesis, observations: list[Observation]) -> list[Candidate]:
    """Candidates this hypothesis's observations support.  Usually zero or one."""
    reflection = _reflection(observations)
    if reflection is None:
        return []
    payload = reflection.payload
    if payload.get("escaped_verbatim"):
        # The bytes came back only in escaped form: for this vuln class that is a
        # negative result, and reporting it as a reflection would be the single
        # most common false lead in the engine.
        return []
    if not payload.get("reflected"):
        return []

    surface = hypothesis.surface
    context = str(payload.get("context") or CONTEXT_UNKNOWN)
    occurrences = int(payload.get("occurrences") or 0)
    # ``semantic`` is the class for a reflection whose context was *parsed*;
    # ``reflection`` is the class for one we could not place. The difference is the
    # whole reason the observation layer keeps context as an enum: a mapped context
    # is knowledge, an unmapped one is bytes.
    grade = EVIDENCE_REFLECTION if context == CONTEXT_UNKNOWN else EVIDENCE_SEMANTIC
    surface_dict = {
        "url": surface.url,
        "param": surface.param,
        "where": surface.where,
        "host": surface.host,
    }
    candidate_id = surface_id_prefix(NAME, surface)

    # The question is not "is this context dangerous?" but "do we have a payload
    # that breaks out of it?" — and the honest answer for a context we can reason
    # about but cannot break out of (a JavaScript string, a comment, between
    # attributes) is a *lead*, not a candidate and not a silence.
    spec = probe_grammar.execution_spec_for(hypothesis, context)
    if spec is None:
        return [
            Candidate(
                id=candidate_id,
                technique=NAME,
                vuln_class="xss",
                surface=surface_dict,
                summary=(
                    f"parameter {surface.param!r} is reflected {occurrences} time(s) in a "
                    f"{context.replace('_', ' ')} context, and Phase 1 has no confirmation "
                    "payload for that context"
                ),
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

    markers = dict(spec.detail.get("markers") or {})
    url = str(spec.detail.get("url") or "")
    return [
        Candidate(
            id=candidate_id,
            technique=NAME,
            vuln_class="xss",
            surface=surface_dict,
            summary=(
                f"parameter {surface.param!r} is reflected {occurrences} time(s) inside a "
                f"{context.replace('_', ' ')} context, which a script tag can break out of"
            ),
            evidence=Evidence(
                kind=OBS_REFLECTION,
                grade=grade,
                payload=dict(payload),
                probe=reflection.probe,
                at=reflection.at,
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
    ]


#: The name the driver and the tests use for this function.  ``interpret`` is the
#: contract's word; ``candidates`` is the honest one, and the alias keeps both
#: readable.
interpret = candidates


__all__ = ["NAME", "candidates", "interpret"]
