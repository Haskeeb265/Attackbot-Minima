"""Claim shapes: what kind of claim a differential candidate makes.

The spike's scar (NOVELTY.md §5, sharpened 2026-09-30 evening): ``interpret``
emitted the same ``authorization.differential`` confirm spec for *both* plan
shapes, and the verifier proves whatever URL the spec names by re-measuring it
under both sessions. For an object-read plan that re-measure *is* the claim.
For a state-change plan the claim is "the change at T reaches V" — and a
flipped re-measure never re-executes the change, so a verifier-proof of "B can
read V" would be scored ``differential`` while proving the weaker,
often-legitimate claim that V is readable. A false finding at the strongest
grade is exactly the failure the evidence lattice exists to prevent.

The mechanism (NOVELTY.md §7.2), now complete:

* the **plan row declares its own claim shape** — data, like every predicate;
* the claim shape **travels on the candidate's confirm spec** (it is part of
  what the verifier is asked to confirm);
* the verifier **refuses** a shape its measurement cannot prove, with a reason
  naming the shape — logged like every refusal, never silently downgraded;
* the setup-re-executing confirm kind **exists** (``authorization.state_change``,
  ``verification/state_change_verifier.py``): it re-executes the change fresh,
  between two unchanged victim reads, and proves the claim at ``differential``.
  ``state_change`` therefore sits in :data:`DIFFERENTIAL_PROVABLE` — expressible
  in the abductive validator, provable end to end.

What stays capped is *routing*: a ``state_change`` spec routed to the flipped
two-session read verifier is still refused (it proves the read, not the change)
— the misroute reason below says which verifier does prove it.
"""

from __future__ import annotations

#: The classic two-session object read: the claim is exactly "B can read the
#: object A reads", and re-measuring the read under both sessions is the claim.
CLAIM_OBJECT_READ = "object_read"

#: The claim is "the change at T reaches V". Proven by the setup-re-executing
#: confirm kind: the verifier executes the change itself, between two unchanged
#: victim reads under session B, and requires the reads to move — a fresh,
#: drift-controlled before/after, not the proposer's pair.
CLAIM_STATE_CHANGE = "state_change"

#: Every claim shape the engine speaks. An unknown shape is refused, not
#: squinted at: a spec whose shape nobody recognises proves nothing.
CLAIM_SHAPES: tuple[str, ...] = (CLAIM_OBJECT_READ, CLAIM_STATE_CHANGE)

#: The shapes a differential-class verifier may prove. ``state_change`` is here
#: because a confirm kind that re-executes the setup exists; the routing rule
#: below is what keeps each shape with the verifier that actually proves it.
DIFFERENTIAL_PROVABLE: frozenset[str] = frozenset({CLAIM_OBJECT_READ, CLAIM_STATE_CHANGE})

#: The reason a ``state_change`` spec routed to the *flipped two-session read*
#: verifier carries. The read verifier's measurement is "V under B and A" — it
#: never executes the change, so proving "B can read V" would score the weaker,
#: often-legitimate claim at differential. The claim itself is provable — by the
#: verifier whose confirm kind is ``authorization.state_change``.
STATE_CHANGE_MISROUTE_REASON = (
    "a state_change claim is proven by re-executing the change between two "
    "unchanged victim reads (the authorization.state_change confirm kind); a "
    "flipped two-session re-measure proves only the read, never the change"
)

#: Backwards-compatible alias: the constant predates the setup-re-executing
#: confirm kind, when the sentence above *was* a cap on provability rather than
#: a routing rule. Kept so existing imports and report lines keep working.
STATE_CHANGE_CAP_REASON = STATE_CHANGE_MISROUTE_REASON


def is_differential_provable(claim_shape: str) -> bool:
    """True when a differential-class verifier may prove *claim_shape*."""
    return claim_shape in DIFFERENTIAL_PROVABLE


__all__ = [
    "CLAIM_OBJECT_READ",
    "CLAIM_SHAPES",
    "CLAIM_STATE_CHANGE",
    "DIFFERENTIAL_PROVABLE",
    "STATE_CHANGE_CAP_REASON",
    "STATE_CHANGE_MISROUTE_REASON",
    "is_differential_provable",
]
