"""Abduced hypotheses, and the validator's three-valued answer.

A :class:`Proposal` is what an abducer emits: an explanation of one retained
anomaly, expressed as a claim the plan language can speak. It carries the
*plan* it would run (serialized), the class it claims, the witness anomaly that
motivated it, and the confirm kind it would need — so the validator can decide
its fate without running anything.

The validator's vocabulary is deliberately small and closed, the same
discipline every kernel vocabulary uses:

* ``expressible_now`` — a confirm kind exists that can prove this claim shape;
  the proposal may become a probe.
* ``not_yet_expressible`` — the claim is speakable but no verifier can confirm
  it yet; it goes to the holding pen (PRD §6.7), where only a code change can
  free it.
* ``invalid`` — malformed or unspellable; logged and dropped, never held.

Nothing here grades or scores: expressibility is a routing fact, not a measure
of worth, and the validator never invents a verifier (PRD §6.6).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field as _field

#: A confirm kind can prove this claim today.
EXPRESSIBLE_NOW = "expressible_now"
#: Speakable, but no verifier yet — the holding pen's inbox.
NOT_YET_EXPRESSIBLE = "not_yet_expressible"
#: Unspellable or malformed; dropped.
INVALID = "invalid"

VERDICTS: tuple[str, ...] = (EXPRESSIBLE_NOW, NOT_YET_EXPRESSIBLE, INVALID)


@dataclass(frozen=True)
class Proposal:
    """One explanation an abducer produced for one retained anomaly."""

    id: str
    technique: str
    vuln_class: str
    claim_shape: str
    summary: str
    #: The rule that produced it — so a reviewer can see *why* the abducer
    #: believed this, not just what it believed.
    rule: str
    #: The anomaly key that motivated it (``kernel.anomaly.anomaly_key``).
    witness: str
    #: The confirm kind this claim would need, so the pen can name its need.
    needs_verifier: str
    #: The plan, serialized (``DifferentialPlan.to_dict()``).
    plan: dict = _field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("a proposal needs an id")
        if not self.needs_verifier:
            raise ValueError(
                "a proposal must name the verifier its claim would need; an "
                "unnamed need cannot be held honestly"
            )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "technique": self.technique,
            "vuln_class": self.vuln_class,
            "claim_shape": self.claim_shape,
            "summary": self.summary,
            "rule": self.rule,
            "witness": self.witness,
            "needs_verifier": self.needs_verifier,
            "plan": dict(self.plan),
        }

    @classmethod
    def from_dict(cls, row: Mapping[str, object]) -> "Proposal":
        """Rebuild a proposal from its serialized row.

        The inverse of :meth:`to_dict`, needed because a proposal round-trips
        through the world log and the hypothesis pool before the driver runs
        it: the abduced round materializes an experiment from *data*, the same
        discipline the plan table already follows. A row missing a field is
        reconstructed with an empty value; the constructor's own guards (an id,
        a named verifier) then refuse it exactly as they refuse a fresh one.
        """
        plan = row.get("plan")
        return cls(
            id=str(row.get("id", "")),
            technique=str(row.get("technique", "")),
            vuln_class=str(row.get("vuln_class", "")),
            claim_shape=str(row.get("claim_shape", "")),
            summary=str(row.get("summary", "")),
            rule=str(row.get("rule", "")),
            witness=str(row.get("witness", "")),
            needs_verifier=str(row.get("needs_verifier", "")),
            plan=dict(plan) if isinstance(plan, Mapping) else {},
        )


@dataclass(frozen=True)
class Validation:
    """The validator's verdict on one proposal."""

    proposal_id: str
    verdict: str
    reason: str = ""

    def __post_init__(self) -> None:
        if self.verdict not in VERDICTS:
            raise ValueError(
                f"unknown verdict {self.verdict!r}; known: {', '.join(VERDICTS)}"
            )

    @property
    def expressible(self) -> bool:
        return self.verdict == EXPRESSIBLE_NOW

    @property
    def holds(self) -> bool:
        return self.verdict == NOT_YET_EXPRESSIBLE

    def to_dict(self) -> dict:
        return {
            "proposal_id": self.proposal_id,
            "verdict": self.verdict,
            "reason": self.reason,
        }


__all__ = [
    "EXPRESSIBLE_NOW",
    "INVALID",
    "NOT_YET_EXPRESSIBLE",
    "VERDICTS",
    "Proposal",
    "Validation",
]
