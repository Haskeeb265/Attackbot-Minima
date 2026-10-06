"""``generic_differential`` — the technique folder, and therefore the registration.

The spike's adapter, and it is thin by necessity: a technique whose hypotheses
are plan rows has almost nothing to adapt. Two contract bends, both explicit:

* the contract hands ``hypotheses()`` one surface at a time, but the plans
  are *seed-level* facts (the role composition needs both of its sides), so
  the adapter returns every plan's hypotheses from the seed's first eligible
  surface and nothing from the rest — the dedup guard keeps the arm count
  honest;
* the seed arrives in ``surfaces()``, the contract's own first call, and is
  bound there: plans are precomputed once per run, on the module-level
  singleton. (A singleton shared across runs is this engine's existing shape
  — every technique folder registers one — and ``surfaces()`` is called
  before every ``hypotheses()`` in the driver's loop, so the bind point is
  deterministic for both the one-pass engine and the campaign.)
"""

from __future__ import annotations

from ...kernel.observation import Observation
from ...kernel.technique import EngagementSeed, Hypothesis, ProbeSpec, Surface
from ...kernel.verdict import Candidate
from . import hypothesis as hypothesis_mod
from . import interpret as interpret_mod
from . import probes as probe_mod
from .eligibility import plan_table_capabilities
from .manifest import MANIFEST, NAME
from .plan import plan_from_dict, validate_plan


class GenericDifferential:
    """Differential vuln classes from plan rows: propose from the pair, confirm flipped."""

    manifest = MANIFEST

    def __init__(self) -> None:
        self._bound_seed: EngagementSeed | None = None

    def surfaces(self, seed: EngagementSeed) -> list[Surface]:
        """Every surface the plan sources can read — and the seed bind point.

        The eligibility is *derived* (``eligibility.py``): the same set both
        plan sources read. A mismatch here would be the silent arm — the
        technique registered, the plans ready, and nothing ever fired because
        the adapter's door was narrower than the table's.
        """
        self._bound_seed = seed
        eligible = plan_table_capabilities()
        return [
            surface
            for surface in seed.with_param()
            if surface.capability in eligible
            or surface.capabilities and (surface.capabilities & eligible)
        ]

    def hypotheses(self, surface: Surface) -> list[Hypothesis]:
        """All of this technique's hypotheses, emitted exactly once.

        The driver calls this per surface; the plans are seed-level, so they
        are emitted from the first eligible surface (deterministic: the seed
        preserves order) and the rest return empty.
        """
        if self._bound_seed is None:
            return []
        eligible = plan_table_capabilities()
        eligible_surfaces = [
            s
            for s in self._bound_seed.with_param()
            if s.capability in eligible
            or s.capabilities and (s.capabilities & eligible)
        ]
        if not eligible_surfaces or surface.url != eligible_surfaces[0].url:
            return []
        return hypothesis_mod.hypotheses_for_seed(self._bound_seed)

    def probes(self, hypothesis: Hypothesis) -> list[ProbeSpec]:
        return probe_mod.probes(hypothesis)

    def hypothesis_for_proposal(self, proposal) -> Hypothesis | None:
        """Materialize one abduced proposal into a runnable hypothesis.

        Optional contract hook (read by the driver with ``getattr``, the same
        courtesy ``synthesis_grammar()`` gets): the abduced round hands the
        technique a proposal — a plan row as *data* — and the technique turns it
        into a hypothesis, or ``None`` when the row is unusable. The driver never
        looks inside, so the technique folder stays removable.
        """
        plan = plan_from_dict(dict(proposal.plan))
        if plan is None:
            return None
        if validate_plan(plan):
            return None  # unspeakable rows are refused, never half-run
        return hypothesis_mod.hypothesis_for_plan(plan)

    def interpret(
        self, hypothesis: Hypothesis, observations: list[Observation]
    ) -> list[Candidate]:
        return interpret_mod.candidates(hypothesis, observations)


TECHNIQUE = GenericDifferential()

__all__ = ["MANIFEST", "NAME", "GenericDifferential", "TECHNIQUE"]
