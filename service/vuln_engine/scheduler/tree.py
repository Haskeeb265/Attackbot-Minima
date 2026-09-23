"""The attack tree: AND/OR structure over arms, with parking instead of spending.

§7.1's heist plan, made data: to prove impact you need a foothold AND an evidence
class; either can come from several techniques (OR); some techniques need a
precondition nobody has observed yet (AND edge).

The tree's whole job is deciding **where the scheduler is allowed to spend**, not
what the answer will be:

* an **OR** node is a set of arms that could satisfy it — the UCB selector ranks
  among them exactly as it would flat, which is why a tree with no AND edges must
  agree with the flat pick (there is a test);
* an **AND** node unlocks only when every named precondition is *satisfied* by the
  world — a finding on file, or an observation type the operator named. While a
  precondition is unsatisfied the node is **parked**: its arms are invisible to
  the selector, so nothing is spent on a subtree that cannot pay off yet. §7.1's
  rule verbatim: an unreachable AND parks the subtree; a failed OR marks the node
  and moves on (a conclusive ``none`` cools the arm in the ledger — the failure
  bookkeeping stays in the receipts where it belongs).

The tree holds no state of its own: satisfaction is computed from the world log
each time, so a replayed campaign re-derives the same parking decisions.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Union

from .ucb import Arm


@dataclass(frozen=True)
class OrNode:
    """An objective any one of several arms could satisfy."""

    name: str
    #: Technique names whose arms may be tried for this objective.
    techniques: tuple[str, ...]

    def to_dict(self) -> dict:
        return {"kind": "or", "name": self.name, "techniques": list(self.techniques)}


@dataclass(frozen=True)
class AndNode:
    """An objective unlocked only when every named precondition is satisfied."""

    name: str
    #: Names of other nodes (or observation kinds) that must hold first.
    requires: tuple[str, ...]
    objective: OrNode

    def to_dict(self) -> dict:
        return {
            "kind": "and",
            "name": self.name,
            "requires": list(self.requires),
            "objective": self.objective.to_dict(),
        }


Node = Union[OrNode, AndNode]


@dataclass(frozen=True)
class Tree:
    """A named set of AND/OR nodes over the arm vocabulary."""

    root: str
    nodes: tuple[Node, ...]

    def node(self, name: str) -> Node | None:
        return next((n for n in self.nodes if n.name == name), None)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "nodes": [node.to_dict() for node in self.nodes],
        }


@dataclass(frozen=True)
class TreeDecision:
    """Which node the tree points the scheduler at, and which nodes are parked."""

    #: The unlocked node whose arms are eligible, or ``None`` when nothing is.
    active: OrNode | None
    parked: tuple[str, ...]
    reason: str

    def to_dict(self) -> dict:
        return {
            "active": self.active.to_dict() if self.active else None,
            "parked": list(self.parked),
            "reason": self.reason,
        }


def _satisfied_by_log(name: str, findings_by_class: set[str], observed: set[str]) -> bool:
    """A node name counts as satisfied when it names a proven vuln class or an
    observation kind the run actually recorded."""
    return name in findings_by_class or name in observed


def decide(
    tree: Tree,
    arms: Sequence[Arm],
    *,
    proven_classes: set[str],
    observed_kinds: set[str],
) -> TreeDecision:
    """Walk from the root to the first unlocked OR node.

    *proven_classes* is the set of ``vuln_class`` values with a finding on file;
    *observed_kinds* the observation kinds recorded so far. Both are read from
    the log by the caller — the tree stays a pure function of its inputs.
    """
    parked: list[str] = []
    seen: set[str] = set()

    def walk(name: str) -> OrNode | None:
        if name in seen:  # pragma: no cover - cycles are a construction error
            return None
        seen.add(name)
        node = tree.node(name)
        if node is None:
            # A name that is not a node is a *claim*: satisfied by the log.
            return None
        if isinstance(node, OrNode):
            return node
        unmet = [
            requirement
            for requirement in node.requires
            if not _satisfied_by_log(requirement, proven_classes, observed_kinds)
            and tree.node(requirement) is None
        ]
        if unmet:
            parked.append(node.name)
            return None
        for requirement in node.requires:
            child = walk(requirement)
            if child is not None:
                return child
        return walk(node.objective.name)

    active = walk(tree.root)
    if active is None:
        reason = (
            "parked: " + ", ".join(parked) + " (a precondition no observation supports)"
            if parked
            else "nothing unlocked"
        )
        return TreeDecision(active=None, parked=tuple(parked), reason=reason)
    return TreeDecision(
        active=active,
        parked=tuple(parked),
        reason=f"{active.name} unlocked ({len(active.techniques)} technique(s))",
    )


def filter_arms(active: OrNode, arms: Sequence[Arm]) -> list[Arm]:
    """The arms the unlocked node is allowed to spend on."""
    allowed = set(active.techniques)
    return [arm for arm in arms if arm.technique in allowed]


__all__ = ["AndNode", "OrNode", "Tree", "TreeDecision", "decide", "filter_arms"]
