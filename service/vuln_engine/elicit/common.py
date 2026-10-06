"""Shared pure helpers for the elicitor folders.

An elicitor is **four pure functions and a manifest**, the same shape as a
technique: ``applies(surface)``, ``probes(surface)``, ``interpret(surface,
observations)``, plus the manifest. The driver composes them exactly as it
composes techniques, so nothing here imports policy, transports or the
scheduler.

The one shared shape is the :class:`Elicitation` result — the answer one
elicitor has about one surface, as data. It is a fact or a measured negative,
never a silence: a negative is a recorded answer the world log can show, and
it is what stops the closure pass from re-asking the same question of the
same surface in the same run (the world log dedups by fact key, exactly as
receipts dedup technique arms).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..kernel.capability import CapabilityFact

#: The manifest's ``vuln_class`` spelling for elicitors — deliberately unused
#: by the elicitor contract, filled so the shared manifest validator passes.
ELICITOR_CLASS = "capability-elicitation"


@dataclass(frozen=True)
class Elicitation:
    """One elicitor's answer about one surface, as data."""

    fact: CapabilityFact | None
    reason: str = ""

    @property
    def established(self) -> bool:
        """True when the elicitor measured the capability present."""
        return self.fact is not None

    @classmethod
    def positive(cls, fact: CapabilityFact) -> "Elicitation":
        return cls(fact=fact)

    @classmethod
    def negative(cls, reason: str) -> "Elicitation":
        return cls(fact=None, reason=reason)


def fact_for(
    surface,  # noqa: ANN001 - Surface, untyped to keep this module kernel-only
    capability: str,
    *,
    grade: str,
    probe: str,
    at: float,
) -> CapabilityFact:
    """The fact an elicitor records when its measurement came back positive."""
    return CapabilityFact(
        surface_key=surface.key,
        capability=capability,
        grade=grade,
        probe=probe,
        at=at,
    )


__all__ = ["ELICITOR_CLASS", "Elicitation", "fact_for"]
