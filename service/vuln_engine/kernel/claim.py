"""Claim shapes: what kind of claim a differential candidate makes.

The spike's scar (NOVELTY.md §5, sharpened 2026-09-30 evening): ``interpret``
emitted the same ``authorization.differential`` confirm spec for *both* plan
shapes, and the verifier proves whatever URL the spec names by re-measuring it
under both sessions. For an object-read plan that re-measure *is* the claim.
For a state-change plan the claim is "the change at T reaches V" — and the
verifier never re-executes the change, so a verifier-proof of "B can read V"
would be scored ``differential`` while proving the weaker, often-legitimate
claim that V is readable. A false finding at the strongest grade is the exact
failure the evidence lattice exists to prevent.

The fix, per NOVELTY.md §7.2's proposed mechanism:

* the **plan row declares its own claim shape** — data, like every predicate;
* the claim shape **travels on the candidate's confirm spec** (it is part of
  what the verifier is asked to confirm);
* the verifier **refuses** a shape it cannot prove at its grade, with a reason
  naming the cap — logged like every refusal, never silently downgraded.

When a setup-re-executing confirm kind is built ("when the category is real"),
the cap lifts by changing :data:`DIFFERENTIAL_PROVABLE` here — one place, no
technique edits.
"""

from __future__ import annotations

#: The classic two-session object read: the claim is exactly "B can read the
#: object A reads", and re-measuring the read under both sessions is the claim.
CLAIM_OBJECT_READ = "object_read"

#: The claim is "the change at T reaches V". The verifier's flipped re-measure
#: observes V, never re-executes the change — so this shape is *not* provable
#: at ``differential`` until a setup-re-executing confirm kind exists.
CLAIM_STATE_CHANGE = "state_change"

#: Every claim shape the engine speaks. An unknown shape is refused, not
#: squinted at: a spec whose shape nobody recognises proves nothing.
CLAIM_SHAPES: tuple[str, ...] = (CLAIM_OBJECT_READ, CLAIM_STATE_CHANGE)

#: The shapes a differential-class verifier may prove today. One entry to
#: delete when the setup-re-executing confirm kind lands.
DIFFERENTIAL_PROVABLE: frozenset[str] = frozenset({CLAIM_OBJECT_READ})

#: The reason every capped refusal carries — the same sentence, everywhere,
#: so a report (or a test) can name the cap without parsing prose variants.
STATE_CHANGE_CAP_REASON = (
    "no setup-re-executing confirm kind exists: the verifier re-measures the "
    "read, never the change, so a state_change claim cannot be proven at "
    "differential yet"
)


def is_differential_provable(claim_shape: str) -> bool:
    """True when a differential-class verifier may prove *claim_shape* today."""
    return claim_shape in DIFFERENTIAL_PROVABLE


__all__ = [
    "CLAIM_OBJECT_READ",
    "CLAIM_SHAPES",
    "CLAIM_STATE_CHANGE",
    "DIFFERENTIAL_PROVABLE",
    "STATE_CHANGE_CAP_REASON",
    "is_differential_provable",
]
