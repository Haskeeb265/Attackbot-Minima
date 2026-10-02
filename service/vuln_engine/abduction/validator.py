"""The three-valued validator (PRD §6.6): expressibility, not worth.

Input a proposal, output ``expressible_now | not_yet_expressible | invalid``.
The vocabulary it consults is the set of **claim shapes a live confirm kind can
prove today**, read from the verifier vocabulary registry
(``verification.registry.provable_claim_shapes``, PRD §6.10). The validator
never invents a verifier and never decides novelty: it only reports whether the
engine can *speak* the claim with a proof behind it.

A malformed proposal — one whose claim shape the engine does not recognise at
all — is ``invalid`` and dropped. A claim shape the engine recognises but cannot
yet prove is ``not_yet_expressible`` and goes to the holding pen, where it names
the confirm kind it needs.
"""

from __future__ import annotations

from ..kernel.claim import CLAIM_SHAPES
from .proposal import (
    EXPRESSIBLE_NOW,
    INVALID,
    NOT_YET_EXPRESSIBLE,
    Proposal,
    Validation,
)


def verifier_vocabulary() -> frozenset[str]:
    """The claim shapes a live confirm kind can prove today.

    Read through one function from the verifier vocabulary registry, so nothing
    else in the abducer knows the vocabulary's contents; adding a confirm kind
    is a change in exactly one place.
    """
    from ..verification.registry import provable_claim_shapes

    return frozenset(provable_claim_shapes())


#: Backwards-compatible alias, kept because the name is stamped on early logs.
differential_vocabulary = verifier_vocabulary


class Validator:
    """Routes a proposal by whether a live verifier can prove its claim."""

    def __init__(self, provable: frozenset[str] | None = None) -> None:
        self._provable = provable if provable is not None else verifier_vocabulary()

    @property
    def provable(self) -> frozenset[str]:
        return self._provable

    def validate(self, proposal: Proposal) -> Validation:
        shape = proposal.claim_shape
        if shape not in CLAIM_SHAPES:
            return Validation(
                proposal_id=proposal.id,
                verdict=INVALID,
                reason=f"unknown claim shape {shape!r}: the engine cannot speak it",
            )
        if shape not in self._provable:
            return Validation(
                proposal_id=proposal.id,
                verdict=NOT_YET_EXPRESSIBLE,
                reason=(
                    f"no confirm kind proves {shape!r} at differential yet; "
                    f"needs {proposal.needs_verifier}"
                ),
            )
        return Validation(
            proposal_id=proposal.id,
            verdict=EXPRESSIBLE_NOW,
            reason=f"{shape!r} is provable at differential today",
        )


__all__ = ["Validator", "differential_vocabulary", "verifier_vocabulary"]
