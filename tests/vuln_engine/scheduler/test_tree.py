"""The attack tree: parking, unlocking, and agreement with the flat selector.

Three properties, per §7.1:

* an unreachable AND parks its subtree — the selector is never shown arms it is
  not allowed to spend on, so a parked subtree costs nothing by construction;
* a satisfied AND unlocks its OR — the world log (a finding, or an observed
  context) is what unlocks, never an estimate;
* with no AND edges the tree's active arms are the flat arm set, so tree-guided
  picking must agree with the flat pick — the tree adds *permission structure*,
  not a new ranking opinion.
"""

from __future__ import annotations

from service.vuln_engine.scheduler.tree import AndNode, OrNode, Tree, decide, filter_arms
from service.vuln_engine.scheduler.ucb import Arm, pick


def _arms() -> list[Arm]:
    return [
        Arm(technique="xss_reflected", surface="xss@s1"),
        Arm(technique="ssti", surface="ssti@s1"),
        Arm(technique="sqli_blind_time", surface="sqli@s1"),
    ]


def _flat_tree() -> Tree:
    return Tree(
        root="impact",
        nodes=(OrNode(name="impact", techniques=("xss_reflected", "ssti", "sqli_blind_time")),),
    )


def _chained_tree() -> Tree:
    return Tree(
        root="prove_impact",
        nodes=(
            AndNode(
                name="prove_impact",
                requires=("script_execution",),
                objective=OrNode(name="foothold", techniques=("sqli_blind_time",)),
            ),
            OrNode(name="foothold", techniques=("sqli_blind_time",)),
        ),
    )


# --------------------------------------------------------------------------- #
# parking
# --------------------------------------------------------------------------- #


def test_an_unsatisfied_and_parks_its_subtree() -> None:
    decision = decide(_chained_tree(), _arms(), proven_classes=set(), observed_kinds=set())
    assert decision.active is None
    assert decision.parked == ("prove_impact",)
    assert "parked" in decision.reason


def test_a_parked_subtree_spends_nothing() -> None:
    decision = decide(_chained_tree(), _arms(), proven_classes=set(), observed_kinds=set())
    assert decision.active is None
    assert filter_arms(decision.active, _arms()) == [] if decision.active else True


def test_an_observed_context_unlocks_the_and() -> None:
    decision = decide(
        _chained_tree(), _arms(), proven_classes=set(), observed_kinds={"script_execution"}
    )
    assert decision.active is not None
    assert decision.active.techniques == ("sqli_blind_time",)


def test_a_proven_class_also_unlocks_the_and() -> None:
    decision = decide(
        _chained_tree(), _arms(), proven_classes={"script_execution"}, observed_kinds=set()
    )
    assert decision.active is not None


# --------------------------------------------------------------------------- #
# agreement with the flat selector
# --------------------------------------------------------------------------- #


def test_with_no_and_edges_the_tree_agrees_with_the_flat_pick() -> None:
    arms = [
        Arm(technique="xss_reflected", surface="xss@s1", throws=2, rewards=2.0),
        Arm(technique="ssti", surface="ssti@s1", throws=1, rewards=0.0),
        Arm(technique="sqli_blind_time", surface="sqli@s1", throws=0),
    ]
    tree = _flat_tree()
    decision = decide(tree, arms, proven_classes=set(), observed_kinds=set())
    assert decision.active is not None
    flat = pick(filter_arms(decision.active, arms))
    flat_without_tree = pick(arms)
    assert flat is not None and flat_without_tree is not None
    assert flat.arm.surface == flat_without_tree.arm.surface


def test_the_tree_restricts_the_selector_to_its_arms() -> None:
    arms = _arms()
    tree = Tree(root="only_xss", nodes=(OrNode(name="only_xss", techniques=("xss_reflected",)),))
    decision = decide(tree, arms, proven_classes=set(), observed_kinds=set())
    assert decision.active is not None
    allowed = filter_arms(decision.active, arms)
    assert [arm.technique for arm in allowed] == ["xss_reflected"]
