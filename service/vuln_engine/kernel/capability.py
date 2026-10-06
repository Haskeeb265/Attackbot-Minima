"""Capability facts: a measured precondition, carried like any other evidence.

The engine's ``surfaces()`` gates used to read one thing: the *declared*
``Surface.capability`` string. That string came from an operator flag or a graph
heuristic, and nothing in the engine could raise one — so a technique whose
precondition nobody had declared was inert, however correct its probes. This
module is the record type that changes the direction of supply: an elicitor
measures the target, produces one of these, and the technique's gate reads the
measured set like any other claim — the same rule, one more source.

A fact is **not** a finding. It never grades evidence upward: establishing
``http_response_reflects_input`` at ``reflection`` grade does not make an XSS
finding, it makes a surface *eligible* for ``xss_reflected``, which still has to
produce a candidate and pass an independent verifier in a different class. The
evidence lattice is untouched; facts only decide which doors open.

The grade is an ordinary ``EVIDENCE_*`` constant so a reader of the log can see
*how* a precondition came to be established — a declared claim has no grade and
reads as ``EVIDENCE_HYPOTHESIS``; a measured one carries the class that measured
it (``reflection`` for a canary, ``oob`` for the collaborator, ``differential``
for the timing and session probes).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .evidence import EVIDENCE_HYPOTHESIS
from .technique import CAPABILITIES, EngagementSeed

#: The log row type one measured capability fact is appended as. One spelling,
#: shared with the two-gate prober's rows, so a reader of either ledger reads
#: the same fact the same way.
EVENT_CAPABILITY_FACT = "capability.measured"


@dataclass(frozen=True)
class CapabilityFact:
    """One measured precondition, on one surface, at one evidence grade."""

    surface_key: str
    #: One of :data:`kernel.technique.CAPABILITIES`.
    capability: str
    #: The evidence class that established it. An empty spelling means the
    #: claim was *declared* (the operator's word, no measurement), which the
    #: accessor renders as the hypothesis grade.
    grade: str = ""
    #: Which probe established it, when one did — the correlation key that
    #: ties the fact back to the requests that measured it.
    probe: str = ""
    at: float = 0.0

    def __post_init__(self) -> None:
        if not self.surface_key:
            raise ValueError("a capability fact must name its surface")
        if not self.capability:
            raise ValueError("a capability fact must name its capability")
        if self.capability not in CAPABILITIES:
            raise ValueError(
                f"unknown capability {self.capability!r}; known: {', '.join(CAPABILITIES)}"
            )

    @property
    def declared(self) -> bool:
        """True when this is a claim nobody measured (no grade attached)."""
        return not self.grade

    @property
    def evidence_grade(self) -> str:
        """The grade a report shows for this fact: declared reads as hypothesis."""
        return self.grade or EVIDENCE_HYPOTHESIS

    def to_dict(self) -> dict:
        return {
            "surface_key": self.surface_key,
            "capability": self.capability,
            "grade": self.evidence_grade,
            "declared": self.declared,
            "probe": self.probe,
            "at": self.at,
        }


@dataclass(frozen=True)
class CapabilityFacts:
    """The world's capability answers for one run, keyed by surface.

    Declared facts (the seed's own claims, which have no measurement behind
    them) are entered once at construction; elicited facts are appended as
    the closure pass measures. Lookup is by ``Surface.key`` — the join key
    every other half of the engine already uses.
    """

    declared: tuple[CapabilityFact, ...] = ()
    elicited: tuple[CapabilityFact, ...] = ()
    #: Per-surface keys of facts, precomputed so lookup is a dict read.
    _by_surface: dict[str, tuple[CapabilityFact, ...]] = field(
        default_factory=dict, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        by_surface: dict[str, list[CapabilityFact]] = {}
        for fact in (*self.declared, *self.elicited):
            by_surface.setdefault(fact.surface_key, []).append(fact)
        # A frozen dataclass cannot assign in __post_init__ without object
        # cruelty; the dict field is mutable by declaration, so fill in place.
        self._by_surface.update(
            {key: tuple(facts) for key, facts in by_surface.items()}
        )

    def capabilities_for(self, surface_key: str) -> frozenset[str]:
        """Every capability any fact — declared or measured — establishes."""
        return frozenset(
            fact.capability for fact in self._by_surface.get(surface_key, ())
        )

    def facts_for(self, surface_key: str) -> tuple[CapabilityFact, ...]:
        """Every fact for one surface, declared first then elicited, in order."""
        return self._by_surface.get(surface_key, ())

    def all_facts(self) -> tuple[CapabilityFact, ...]:
        """Every fact, declared first then elicited, in insertion order."""
        return (*self.declared, *self.elicited)


def declared_facts(seed: EngagementSeed) -> tuple[CapabilityFact, ...]:
    """The seed's own claims as declared facts, in surface order.

    Each surface contributes exactly one fact — its ``capability`` string —
    and only when it actually claims one. A surface with no claim contributes
    nothing: absence of a claim is not a fact about the target.
    """
    facts: list[CapabilityFact] = []
    for surface in seed.surfaces:
        if surface.capability and surface.capability in CAPABILITIES:
            facts.append(
                CapabilityFact(
                    surface_key=surface.key,
                    capability=surface.capability,
                    grade="",
                )
            )
    return tuple(facts)


__all__ = [
    "EVENT_CAPABILITY_FACT",
    "CapabilityFact",
    "CapabilityFacts",
    "declared_facts",
]
