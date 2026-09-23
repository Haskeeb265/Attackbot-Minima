"""The candidate a technique proposes, and the verifier's deliberately narrow answer.

Two shapes and one function, ported from ``engine_explained.md`` §2.

The rule:

    The thing that proposes cannot be the thing that confirms.

If one accountant both writes the books and signs off on them, you have not
audited anything — you have a closed loop that can be *confidently wrong*. So a
verdict is refused unless its evidence class differs from the proposer's, and
unless it is a class a finding may rest on at all. That check is cheap, and it is
the single check that stops the closed false-positive loop.

Why :class:`Candidate` lives here rather than in its own module: it carries the
proposer's evidence *class*, which is the exact field :func:`Verdict.check_independence`
compares. Splitting them would put the compared field and the comparison in
different files, which is how the comparison eventually stops being made.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .evidence import EVIDENCE_HYPOTHESIS, Evidence, FINDING_GRADES


@dataclass(frozen=True)
class Candidate:
    """Something a technique believes it found, with the class that supports it.

    ``confirm`` is a *request spec* — a plain dict the verifier (through the
    policy gate) turns into an EffectRequest. It is not reasoning: the verifier
    never reads the proposer's rationale, its confidence, or its prose. It reads
    what to do and what the page then did, and answers a narrower question than
    the proposer asked: did the effect actually occur?
    """

    #: Stable, deterministic id: ``<technique>:<host>:<path>:<param>``.
    id: str
    technique: str
    vuln_class: str
    #: The surface this candidate is about — ``url``, ``param``, ``where``.
    surface: dict = field(default_factory=dict)
    #: One short, factual statement of what is believed ("param q reflects in a
    #: double-quoted attribute context"). No confidence wording.
    summary: str = ""
    #: The proposer's own evidence (a lead class in every Phase 1 case).
    evidence: Evidence | None = None
    #: What a verifier should do to confirm: ``{"kind": "browser.run", "url": …}``.
    confirm: dict = field(default_factory=dict)
    #: The payload that makes the candidate reproducible, when there is one.
    payload: str = ""
    #: A URL that reproduces the candidate by hand — the report carries it.
    repro_url: str = ""
    #: Who proposed this candidate: ``""`` (a technique's own grammar, the
    #: ordinary case) or ``world.log.EVENT_CANDIDATE_JUNCTION`` (the Phase 3
    #: synthesize junction, from a model's validated grammar-bounded answer).
    #: Provenance only — verification treats both identically, because the
    #: independence rule it enforces is about *evidence class*, not about who
    #: shaped the proposal. A model-shaped payload is confirmed by the browser
    #: the same way a hand-written one is, or it stays a lead.
    origin: str = ""

    @property
    def proposer_grade(self) -> str:
        return self.evidence.grade if self.evidence is not None else EVIDENCE_HYPOTHESIS

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "technique": self.technique,
            "vuln_class": self.vuln_class,
            "surface": dict(self.surface),
            "summary": self.summary,
            "proposer_grade": self.proposer_grade,
            "payload": self.payload,
            "repro_url": self.repro_url,
            "confirm": dict(self.confirm),
            "origin": self.origin,
        }


@dataclass(frozen=True)
class Verdict:
    """The verifier's answer.  Deliberately narrow: proven or not."""

    candidate_id: str
    proven: bool
    #: The *verifier's* evidence, not the proposer's.
    evidence: Evidence | None = None
    reason: str = ""
    #: The class the proposer rested on, kept so the report can show both halves
    #: ("proposed on reflection, confirmed by execution").
    proposer_grade: str = ""

    @staticmethod
    def check_independence(candidate_grade: str, evidence: Evidence) -> None:
        """Refuse a verdict that reuses the proposer's evidence class.

        This is invariant #8 of ``engine_principles.md`` §5 made executable. It
        raises rather than returning a boolean because there is no correct
        behaviour for a non-independent verdict — silently downgrading it to a
        lead would hide the bug that produced it.
        """
        if evidence.grade == candidate_grade:
            raise ValueError(
                f"verification reuses the proposer's evidence class "
                f"({evidence.grade!r}); choose a different class or report a lead, "
                "not a finding"
            )
        if evidence.grade not in FINDING_GRADES:
            raise ValueError(
                f"grade {evidence.grade!r} cannot support a finding; a finding rests "
                f"on one of: {', '.join(sorted(FINDING_GRADES))}"
            )

    @property
    def grade(self) -> str:
        """The class this verdict rests on — ``""`` when nothing was proven."""
        return self.evidence.grade if (self.proven and self.evidence) else ""

    def to_dict(self) -> dict:
        payload: dict = {
            "candidate": self.candidate_id,
            "proven": self.proven,
            "proposer_grade": self.proposer_grade,
            "reason": self.reason,
        }
        if self.evidence is not None:
            payload["grade"] = self.evidence.grade
            payload["evidence"] = self.evidence.to_dict()
        return payload


def refuse(candidate: Candidate, reason: str) -> Verdict:
    """A verdict that says "not proven" — the honest shape when a confirm probe
    found nothing.  Kept as a function so every verifier refuses the same way."""
    return Verdict(
        candidate_id=candidate.id,
        proven=False,
        reason=reason,
        proposer_grade=candidate.proposer_grade,
    )


__all__ = ["Candidate", "Verdict", "refuse"]
