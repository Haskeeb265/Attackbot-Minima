"""UCB selection over (technique × surface) arms — the pure half of Phase 2.

This is ``engine_explained.md`` §7.2's sketch, made real against the machinery
Phase 1 already proved. Three properties make it trustworthy rather than clever:

* **pure** — a function of the receipts ledger, the manifests and the priors.
  No clock, no network, no technique internals; the same ledger always yields the
  same pick, so a campaign's round order is reproducible offline from its log;
* **history comes from the ledger, not from memory** — ``platform/receipt.py``'s
  semantics unchanged: ``found`` is conclusive reward, ``none`` is conclusive
  no-reward, ``failed`` is *not an attempt* and never enters the math. A refusal
  is not an attempt either, which is why Phase 1 stopped filing receipts for arms
  nothing executed against;
* **the reward is divided by visibility** — the design's own addition (§2.5):
  UCB ranks by what an arm *could be worth*; dividing by the declared
  :class:`~service.vuln_engine.kernel.manifest.NoiseProfile` cost ranks by what it
  could be worth *per unit of the campaign's signature*. Nobody in the surveyed
  literature optimizes this; it is also why a loud technique can lose to a quiet
  one at equal reward.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from ..kernel.manifest import NoiseProfile
from ..kernel.technique import EngagementSeed, Surface

#: Reward for a conclusive outcome, in information-gain units. ``found`` answered
#: the hypothesis's question affirmatively (a candidate was produced); ``none``
#: answered it conclusively negatively — also information, just none we keep.
REWARD_FOUND = 1.0
REWARD_NONE = 0.0

#: Novelty reward, bounded by construction (PRD §6.8, A2). A novelty payout can
#: never outrank a conclusive ``found`` at equal throws: the total the term can
#: add to an arm is strictly below :data:`REWARD_FOUND` — exploration re-orders
#: ties, a measured answer still wins. The two constants below are the whole
#: mechanism; there is nothing to tune, which is the point.
NOVELTY_REWARD_CAP = 0.9
#: What the first entry into a fresh cell pays.
NOVELTY_CELL_REWARD = 0.5
#: Each further entry multiplies that cell's payout — re-entering counted
#: territory pays ≈ 0, so a cheap abducer cannot farm the term.
NOVELTY_CELL_DECAY = 0.5

#: Exploration weight. §7.2's value; deliberately the only knob, and one the
#: replay can freeze per campaign.
DEFAULT_EXPLORATION = 1.4

#: How many consecutive conclusive ``none`` outcomes demote an arm. §7.1's failure
#: back-propagation in its minimal honest form: an arm that answered "nothing
#: here" twice in a row has earned a cooler estimate, not a permanent mark.
NONE_STREAK_DEMOTION = 2


@dataclass(frozen=True)
class Arm:
    """One (technique × surface) choice. History comes from receipts, not from here."""

    technique: str
    surface: str
    #: Conclusive attempts on file (``found`` + ``none``; never ``failed``).
    throws: int = 0
    #: Accumulated reward across those attempts.
    rewards: float = 0.0
    #: TDA-style evidence confidence for this surface — the scorer's prior, when
    #: the recon side has one. Zero until something measured it.
    prior: float = 0.0
    #: Consecutive conclusive ``none`` outcomes, most recent last.
    none_streak: int = 0
    #: The novelty term (A2): bounded below :data:`REWARD_FOUND`, receipts-based
    #: and cell-decaying. Zero unless something was actually retained here.
    novelty: float = 0.0

    def ucb(self, total_throws: int, c: float = DEFAULT_EXPLORATION) -> float:
        """Optimistic estimate. Pure: same inputs, same number, always.

        An untried arm's upper bound is infinite and therefore gets tried once —
        that is the whole exploration schedule, and it needs no tuning. A demoted
        arm (``none`` twice running) is treated as already-explored even at zero
        throws-with-reward, because "we looked twice and found nothing" is the
        opposite of "we never looked".

        The ``prior`` (Phase 3's advisory ranking, wired by the campaign) enters
        the mean, and its influence is bounded by construction rather than by a
        clamp here: the wiring caps any opinion at 0.4 — below the reward a
        single conclusive ``found`` carries — and the found arm draws the same
        optimism the prior arm does, so at equal throws an opinion cannot pass
        a measured answer. UCB's own optimism stays the dominant term; the
        opinion only re-orders otherwise-tied arms and nudges re-exploration.
        With no opinion wired, prior is 0.0 and the math is exactly Phase 2's.
        """
        if self.throws == 0 and self.none_streak == 0:
            return float("inf")  # an untried arm always wins once
        throws = max(self.throws, 1)
        mean = (self.rewards + self.prior + self.novelty) / throws
        optimism = c * math.sqrt(math.log(max(total_throws, 1)) / throws)
        if self.none_streak >= NONE_STREAK_DEMOTION:
            optimism *= 0.5
        return mean + optimism

    @property
    def mean_reward(self) -> float:
        if self.throws == 0:
            return 0.0
        return self.rewards / self.throws

    def to_dict(self) -> dict:
        return {
            "technique": self.technique,
            "surface": self.surface,
            "throws": self.throws,
            "rewards": round(self.rewards, 3),
            "prior": round(self.prior, 3),
            "novelty": round(self.novelty, 3),
            "none_streak": self.none_streak,
        }


@dataclass(frozen=True)
class Pick:
    """Why one arm won, recorded so the log shows the reasoning, not just the winner."""

    arm: Arm
    score: float
    reason: str

    def to_dict(self) -> dict:
        return {
            "arm": self.arm.to_dict(),
            "score": round(self.score, 4),
            "reason": self.reason,
        }


def pick(
    arms: Sequence[Arm],
    *,
    noise: Mapping[str, NoiseProfile | None] | None = None,
    c: float = DEFAULT_EXPLORATION,
) -> Pick | None:
    """Highest upper bound, adjusted for what the attempt will cost in visibility.

    The ``noise`` term is the design's own addition: the reward is *information
    gain*, and the denominator is what the attempt will cost the campaign's
    signature. An arm with no declared profile costs 1.0 — an honest default for
    a technique that has not thought about its footprint, and a mild penalty for
    the ones that have not.

    Returns ``None`` only when there is nothing to choose among.
    """
    if not arms:
        return None
    total = sum(arm.throws for arm in arms)
    if total == 0:
        # Every arm untried: infinite upper bounds cannot order themselves, so
        # the pick falls to declared cost — quiet first. Ties go to the first
        # arm, which keeps the choice deterministic for a given registration order.
        best = min(arms, key=lambda arm: _cost(arm, noise))
        return Pick(
            arm=best,
            score=float("inf"),
            reason=(
                "no arm has been attempted: quiet first (declared noise cost "
                f"{_cost(best, noise):.3g})"
            ),
        )

    def score(arm: Arm) -> float:
        bound = arm.ucb(total, c)
        cost = _cost(arm, noise)
        return bound / cost if bound != float("inf") else float("inf")

    best = max(arms, key=lambda arm: (score(arm), -_cost(arm, noise)))
    best_score = score(best)
    if best_score == float("inf"):
        return Pick(
            arm=best,
            score=best_score,
            reason="untried: an untried arm always wins once (UCB optimism)",
        )
    advisory = f" + advisory prior {best.prior:.2g}" if best.prior else ""
    novelty = f" + novelty {best.novelty:.2g}" if best.novelty else ""
    return Pick(
        arm=best,
        score=best_score,
        reason=(
            f"optimistic bound {best.ucb(total, c):.3g}{advisory}{novelty} ÷ noise cost "
            f"{_cost(best, noise):.3g} = {best_score:.3g}"
        ),
    )


def cell_novelty(times_entered: int) -> float:
    """The payout for a cell entered *times_entered* times (A2, cell-decaying).

    Zero before the first entry, the full cell reward on the first, and a
    geometric decay afterwards: the tenth visit to counted territory pays
    ≈ 0.0. Pure arithmetic — no clock, no ledger read.
    """
    if times_entered <= 0:
        return 0.0
    return NOVELTY_CELL_REWARD * (NOVELTY_CELL_DECAY ** (times_entered - 1))


def novelty_reward(cells: Mapping[str, int]) -> float:
    """One arm's novelty payout from its entered cells, capped below ``found``.

    *cells* maps a derived cell key (see ``kernel.anomaly.anomaly_key``, which
    is surface-scoped and predicate-family-shaped) to how many times that cell
    has been entered. The sum is capped at :data:`NOVELTY_REWARD_CAP`, which is
    strictly below :data:`REWARD_FOUND` — no pile of "new territory" can add up
    to a measured answer.
    """
    total = sum(cell_novelty(count) for count in cells.values())
    return min(total, NOVELTY_REWARD_CAP)


def _cost(arm: Arm, noise: Mapping[str, NoiseProfile | None] | None) -> float:
    profile = (noise or {}).get(arm.technique)
    return profile.cost if profile is not None else 1.0


def arms_from_receipts(
    eligible: Mapping[str, Sequence[str]],
    receipts_by_arm: Mapping[str, Mapping[str, int]],
    *,
    priors: Mapping[str, float] | None = None,
    novelty: Mapping[str, float] | None = None,
) -> list[Arm]:
    """Build the arm set from the ledger and the *declared* eligible surfaces.

    *eligible* maps technique name → surface keys, and it comes from the
    technique's own ``surfaces(seed)`` — the same source the driver reads, so
    there is exactly one authority on where a technique may run and the
    scheduler never re-derives eligibility from manifest preconditions (a
    precondition says what the *world* must claim; ``surfaces()`` also encodes
    how loud the technique is willing to be, which the loud techniques gate on).

    *receipts_by_arm* is the ``views.receipts_by_arm`` shape (``{arm:
    {outcome: count}}``); only conclusive outcomes enter the math, per
    ``platform/receipt.py``. ``failed`` and refusals are absent from ``throws``
    by construction — the ledger of attempts, not the ledger of refusals.

    *priors* maps arm name → the Phase 3 rank junction's advisory prior (also
    arm-keyed, so a technique's opinion spreads over its surfaces). Enters the
    mean and is clamped by :meth:`Arm.ucb` at ``REWARD_FOUND`` — advisory by
    construction. Empty (or absent) is the no-opinion shape: the math is
    exactly Phase 2's.
    """
    priors_map = dict(priors or {})
    novelty_map = dict(novelty or {})
    arms: list[Arm] = []
    seen: set[str] = set()
    for technique, surface_keys in eligible.items():
        for surface_key in surface_keys:
            arm_name = f"{technique}@{surface_key}"
            if arm_name in seen:
                continue
            seen.add(arm_name)
            outcomes = receipts_by_arm.get(arm_name, {})
            found = int(outcomes.get("found", 0))
            none = int(outcomes.get("none", 0))
            throws = found + none
            # A2, receipts-based: novelty is credited only to an arm that
            # actually ran — never for proposed-but-unexecuted territory, so an
            # arm cannot farm the term by emitting cheap explanations.
            reward = novelty_map.get(arm_name, 0.0) if throws > 0 else 0.0
            arms.append(
                Arm(
                    technique=technique,
                    surface=arm_name,
                    throws=throws,
                    rewards=found * REWARD_FOUND,
                    none_streak=none,
                    prior=priors_map.get(arm_name, 0.0),
                    novelty=reward,
                )
            )
    return arms


__all__ = [
    "DEFAULT_EXPLORATION",
    "NONE_STREAK_DEMOTION",
    "NOVELTY_CELL_DECAY",
    "NOVELTY_CELL_REWARD",
    "NOVELTY_REWARD_CAP",
    "REWARD_FOUND",
    "REWARD_NONE",
    "Arm",
    "Pick",
    "arms_from_receipts",
    "cell_novelty",
    "novelty_reward",
    "pick",
]
