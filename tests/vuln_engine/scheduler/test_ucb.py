"""The UCB selector: pure math over the receipts ledger, and its edge cases.

These are the properties the campaign's honesty rests on:

* an untried arm always wins once (exploration needs no schedule);
* history cools the optimism — a proven arm is revisited, a twice-answered
  "nothing here" arm is demoted, and a *failed* attempt is not history at all;
* equal reward is not equal ranking: the louder arm loses, because the objective
  is information gain **per unit of visibility**, not raw information;
* determinism: the same ledger always yields the same pick, which is what makes
  a campaign's round order replayable offline.
"""

from __future__ import annotations

import pytest

from service.vuln_engine.kernel.manifest import NoiseProfile, TechniqueManifest
from service.vuln_engine.kernel.technique import (
    CAP_INFLUENCE_REMOTE_FETCH,
    CAP_PUBLIC_PARAM,
    EngagementSeed,
    Surface,
)
from service.vuln_engine.scheduler.ucb import (
    DEFAULT_EXPLORATION,
    NONE_STREAK_DEMOTION,
    Arm,
    arms_from_receipts,
    pick,
)


# --------------------------------------------------------------------------- #
# Arm.ucb — the optimistic bound
# --------------------------------------------------------------------------- #


def test_an_untried_arm_has_an_infinite_upper_bound() -> None:
    assert Arm(technique="t", surface="s").ucb(0) == float("inf")
    assert Arm(technique="t", surface="s").ucb(10) == float("inf")


def test_history_cools_the_optimism_toward_the_mean() -> None:
    proven = Arm(technique="t", surface="s", throws=10, rewards=10.0)
    first = proven.ucb(20)
    cooled = Arm(technique="t", surface="s", throws=50, rewards=50.0).ucb(100)
    assert proven.mean_reward == 1.0
    assert first > cooled  # the bound falls as n grows
    assert cooled > proven.mean_reward  # but never below the mean


def test_a_twice_answered_nothing_streak_is_demoted() -> None:
    fresh = Arm(technique="t", surface="s", throws=0)
    demoted = Arm(technique="t", surface="s", throws=0, none_streak=NONE_STREAK_DEMOTION)
    # "We looked twice and found nothing" is the opposite of "we never looked":
    # the demoted arm loses the untried arm's infinite optimism, and its bound
    # sits below an arm that has merely been looked at twice — but it stays
    # finite and real, so a re-test remains possible later.
    assert fresh.ucb(10) == float("inf")
    assert demoted.ucb(10) < float("inf")
    assert demoted.ucb(10) < Arm(technique="t", surface="s", throws=2, rewards=0.0).ucb(10)


def test_the_prior_lifts_an_arm_without_lying_about_its_history() -> None:
    plain = Arm(technique="t", surface="s", throws=2, rewards=0.0)
    informed = Arm(technique="t", surface="s", throws=2, rewards=0.0, prior=0.5)
    assert informed.ucb(10) > plain.ucb(10)


# --------------------------------------------------------------------------- #
# pick — the noise division and the ordering rules
# --------------------------------------------------------------------------- #


def test_pick_returns_none_for_an_empty_arm_set() -> None:
    assert pick([]) is None


def test_an_untried_arm_wins_once() -> None:
    tried = Arm(technique="a", surface="s1", throws=5, rewards=5.0)
    fresh = Arm(technique="b", surface="s2", throws=0)
    outcome = pick([tried, fresh])
    assert outcome is not None
    assert outcome.arm is fresh
    assert outcome.score == float("inf")


def test_the_quiet_arm_wins_when_nothing_has_been_attempted() -> None:
    loud = Arm(technique="loud", surface="s1")
    quiet = Arm(technique="quiet", surface="s2")
    outcome = pick(
        [loud, quiet],
        noise={
            "loud": NoiseProfile(requests_per_surface=10, burstiness=0.8),
            "quiet": NoiseProfile(requests_per_surface=2),
        },
    )
    assert outcome is not None
    assert outcome.arm is quiet
    assert outcome.score == float("inf")  # optimism is infinite either way
    assert "quiet first" in outcome.reason


def test_equal_reward_the_louder_arm_loses() -> None:
    quiet = Arm(technique="quiet", surface="s1", throws=4, rewards=4.0)
    loud = Arm(technique="loud", surface="s2", throws=4, rewards=4.0)
    outcome = pick(
        [loud, quiet],
        noise={
            "quiet": NoiseProfile(requests_per_surface=1),
            "loud": NoiseProfile(
                requests_per_surface=3, burstiness=0.5, requires_browser=True
            ),
        },
    )
    assert outcome is not None
    assert outcome.arm is quiet
    assert outcome.arm.mean_reward == loud.mean_reward  # the reward did not decide it
    assert "noise cost" in outcome.reason


def test_a_proven_arm_beats_a_failing_one_at_the_same_cost() -> None:
    proven = Arm(technique="a", surface="s1", throws=3, rewards=3.0)
    barren = Arm(technique="b", surface="s2", throws=3, rewards=0.0)
    outcome = pick([proven, barren])
    assert outcome is not None
    assert outcome.arm is proven


def test_the_pick_is_deterministic_for_a_given_ledger() -> None:
    arms = [
        Arm(technique="a", surface="s1", throws=2, rewards=2.0),
        Arm(technique="b", surface="s2", throws=1, rewards=1.0),
        Arm(technique="c", surface="s3", throws=4, rewards=1.0),
    ]
    first = pick(arms)
    second = pick(list(reversed(arms)))
    assert first is not None and second is not None
    assert first.arm.technique == second.arm.technique
    assert first.score == second.score


def test_the_exploration_weight_is_the_only_knob() -> None:
    exploit = Arm(technique="exploit", surface="s1", throws=10, rewards=9.0)
    explore = Arm(technique="explore", surface="s2", throws=1, rewards=0.0)
    greedy = pick([exploit, explore], c=0.0)
    curious = pick([exploit, explore], c=DEFAULT_EXPLORATION)
    assert greedy is not None and curious is not None
    assert greedy.arm is exploit  # c=0 is pure exploitation
    assert curious.arm is explore  # optimism lifts the barely-tried arm


# --------------------------------------------------------------------------- #
# arms_from_receipts — the ledger is the only history
# --------------------------------------------------------------------------- #


def _manifest(name: str, *preconditions: str) -> TechniqueManifest:
    return TechniqueManifest(
        name=name,
        vuln_class="test",
        preconditions=tuple(preconditions),
        postconditions=("nothing",),
        produces=("reflection",),
        verification_needs="execution",
        noise=NoiseProfile(requests_per_surface=1),
    )


def test_arms_come_from_declared_eligibility_not_imagination() -> None:
    eligible = {
        "xss": ["http://127.0.0.1:8080/search#q"],
        "ssrf": ["http://127.0.0.1:8080/fetch#url"],
    }
    arms = arms_from_receipts(eligible, {})
    assert {arm.surface for arm in arms} == {
        "xss@http://127.0.0.1:8080/search#q",
        "ssrf@http://127.0.0.1:8080/fetch#url",
    }
    assert all(arm.throws == 0 for arm in arms)


def test_a_failed_attempt_is_not_history() -> None:
    ledger = {"xss@http://127.0.0.1:8080/search#q": {"failed": 3}}
    arms = arms_from_receipts({"xss": ["http://127.0.0.1:8080/search#q"]}, ledger)
    assert arms[0].throws == 0  # an errored probe is not an attempt
    # Which means it still gets its one untried pick — an outage must not become
    # a permanent gap, the receipt rule reaching the scheduler unchanged.
    outcome = pick(arms)
    assert outcome is not None
    assert outcome.score == float("inf")


def test_found_and_none_count_but_only_found_rewards() -> None:
    ledger = {
        "xss@http://127.0.0.1:8080/search#q": {"found": 2, "none": 1, "failed": 9}
    }
    arms = arms_from_receipts({"xss": ["http://127.0.0.1:8080/search#q"]}, ledger)
    assert arms[0].throws == 3
    assert arms[0].rewards == pytest.approx(2.0)
    assert arms[0].none_streak == 1


def test_no_eligible_surface_means_no_arm() -> None:
    arms = arms_from_receipts({"xss": []}, {})
    assert arms == []
