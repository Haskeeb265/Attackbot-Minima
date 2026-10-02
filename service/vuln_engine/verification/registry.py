"""The verifier vocabulary registry (PRD §6.10): the bottleneck made explicit.

The engine's confirm kinds have always existed as a dispatch table
(:data:`verification.CONFIRM_VERIFIERS`), but nothing recorded *what each kind
can prove*. That is the whole question the abductive loop asks when it decides
an explanation is expressible: is there a verifier that can confirm this claim
shape? So each confirm kind gets a small, first-class record here — the claim
shapes it supports, its measurement class, and whether it re-executes the setup
or only re-measures.

Two rules this module exists to make cheap:

* **the standing process (A4).** Every new hypothesis shape either lands a
  verifier in the same cycle or lands in the holding pen. The pen names the
  confirm kind it needs; this registry is where that kind appears when the PR
  that adds it lands. Promotion is a code change, owned like one.
* **no drift.** :func:`check_alignment` cross-checks this vocabulary against the
  dispatch table, so a kind that dispatches but is unlisted (or listed but
  undispatched) is a test failure, not a silent gap.

Nothing here runs a verifier; it only describes them. A registry entry with an
empty ``claim_shapes`` is honest: those verifiers confirm classes whose claims
are not expressed as differential claim shapes today.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field as _field

from ..kernel.claim import CLAIM_SHAPES, DIFFERENTIAL_PROVABLE


@dataclass(frozen=True)
class VerifierKind:
    """What one confirm kind is, and what it can prove."""

    #: The dispatcher's name (``CONFIRM_VERIFIERS`` value).
    name: str
    #: The confirmation-spec kind the candidate carries.
    confirm_kind: str
    #: Evidence class the confirmation rests on (execution/oob/differential).
    measurement: str
    #: Claim shapes this kind can prove. Empty means it confirms classes whose
    #: claims are not differential claim shapes today.
    claim_shapes: frozenset[str] = _field(default_factory=frozenset)
    #: True when the verifier re-executes the setup (not merely re-measures it);
    #: the state-change cap rests on ``authorization.differential`` being False.
    re_executes_setup: bool = False
    #: The confirmation is an independent measurement, never the proposer's own.
    independent: bool = True

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "confirm_kind": self.confirm_kind,
            "measurement": self.measurement,
            "claim_shapes": sorted(self.claim_shapes),
            "re_executes_setup": self.re_executes_setup,
            "independent": self.independent,
        }


#: The vocabulary. One entry per live confirm kind. Adding a confirm kind is a
#: PR that adds it here *and* to ``verification.CONFIRM_VERIFIERS``; the
#: alignment check keeps the two honest.
VERIFIER_KINDS: tuple[VerifierKind, ...] = (
    VerifierKind(
        name="authorization",
        confirm_kind="authorization.differential",
        measurement="differential",
        claim_shapes=frozenset(DIFFERENTIAL_PROVABLE),
        re_executes_setup=False,
    ),
    VerifierKind(
        name="timing",
        confirm_kind="timing.differential",
        measurement="differential",
    ),
    VerifierKind(
        name="oob",
        confirm_kind="oob.read",
        measurement="oob",
    ),
    VerifierKind(
        name="browser",
        confirm_kind="browser.run",
        measurement="execution",
        re_executes_setup=True,
    ),
    VerifierKind(
        name="stored",
        confirm_kind="xss_stored.execute",
        measurement="execution",
        re_executes_setup=True,
    ),
)


def registry() -> dict[str, VerifierKind]:
    """The vocabulary keyed by confirm kind (the candidate's spec kind)."""
    return {kind.confirm_kind: kind for kind in VERIFIER_KINDS}


def by_name() -> dict[str, VerifierKind]:
    """The vocabulary keyed by dispatcher name."""
    return {kind.name: kind for kind in VERIFIER_KINDS}


def provable_claim_shapes() -> frozenset[str]:
    """Every claim shape a live confirm kind can prove today.

    The abductive validator's expressibility question, answered from one place:
    a claim shape is expressible exactly when some registered verifier lists it.
    """
    shapes: frozenset[str] = frozenset()
    for kind in VERIFIER_KINDS:
        shapes |= kind.claim_shapes
    return shapes


def check_alignment(dispatch: Mapping[str, str]) -> list[str]:
    """Cross-check the vocabulary against *dispatch* (``CONFIRM_VERIFIERS``).

    Returns the problems — a kind that dispatches without a registry entry, or
    vice versa, or a name mismatch. An empty list is the healthy answer; the
    test suite asserts it, so the registry cannot drift from the dispatcher.
    """
    problems: list[str] = []
    registered = registry()
    for confirm_kind, name in dispatch.items():
        entry = registered.get(confirm_kind)
        if entry is None:
            problems.append(f"{confirm_kind!r} dispatches but is not registered")
        elif entry.name != name:
            problems.append(
                f"{confirm_kind!r} dispatches to {name!r} but is registered as {entry.name!r}"
            )
    for kind in VERIFIER_KINDS:
        if kind.confirm_kind not in dispatch:
            problems.append(f"{kind.confirm_kind!r} is registered but does not dispatch")
        for shape in kind.claim_shapes:
            if shape not in CLAIM_SHAPES:
                problems.append(
                    f"{kind.confirm_kind!r} claims unknown shape {shape!r}"
                )
    return problems


__all__ = [
    "VERIFIER_KINDS",
    "VerifierKind",
    "by_name",
    "check_alignment",
    "provable_claim_shapes",
    "registry",
]
