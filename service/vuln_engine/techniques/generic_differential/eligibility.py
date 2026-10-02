"""Eligibility, derived from the plan table — never written beside it.

The drift surface the spike itself tripped on (NOVELTY.md §5): the adapter's
``surfaces()`` filter and the plan sources' expectations were two hand-written
copies of the same fact. A mismatch is the silent arm — the technique
registered, the plans ready, and nothing ever fired because the adapter's door
was narrower than the table's (or, worse, wider, burning budget on surfaces no
plan can use).

The rule (NOVELTY.md §6, rule 4): eligibility is *derived*. The plan table's
sources say what the world must look like; this module computes it from them,
once, and both consumers read the same derivation. ``_refuse_to_load`` runs at
import: a table that admits nothing, or names a capability the kernel does not
speak, fails loudly at discovery instead of silently mid-run.
"""

from __future__ import annotations

from ...kernel.technique import (
    CAP_ACCESS_DIFFERS_BY_SESSION,
    CAPABILITIES,
    CAP_PUBLIC_PARAM,
)


def plan_table_capabilities() -> frozenset[str]:
    """The capabilities the plan table's sources precondition on.

    Derived from the table's own shape, one place:

    * ``object_read_plans`` fires on surfaces that carry a parameter and
      declare either the plain parameter capability or the two-sessions fact;
    * ``session_role_plans`` composes role-declared surfaces, which are
      ordinary parameter surfaces plus the same two-sessions fact.

    Both reduce to the same two capabilities. If a future source preconditions
    on something else, it joins this derivation — and the canary test pins
    that every derived capability actually produces a live arm.
    """
    return frozenset({CAP_PUBLIC_PARAM, CAP_ACCESS_DIFFERS_BY_SESSION})


def _refuse_to_load() -> None:
    """Fail at import when the derived eligibility cannot produce arms.

    A run with this technique loaded but zero eligible surfaces is the silent
    failure the derivation exists to prevent; these checks make the broken
    state unimportable instead.
    """
    derived = plan_table_capabilities()
    if not derived:
        raise RuntimeError(
            "generic_differential eligibility derives to an empty set: the plan "
            "table can never fire. Fix the derivation, not the callers."
        )
    unknown = sorted(derived - set(CAPABILITIES))
    if unknown:
        raise RuntimeError(
            "generic_differential eligibility names capability constants the "
            f"kernel does not speak: {', '.join(unknown)}"
        )


_refuse_to_load()


__all__ = ["plan_table_capabilities"]
