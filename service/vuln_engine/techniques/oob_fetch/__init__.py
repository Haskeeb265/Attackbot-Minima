"""``oob_fetch`` — the blind technique folder, and therefore the registration.

Same four-file shape as ``xss_reflected``: manifest, hypothesis, probes,
interpret. That sameness is the contract working — the second technique needed no
change anywhere else in the engine, which is what "adding SSTI must never require
editing anything outside ``techniques/ssti/``" actually means in practice.
"""

from __future__ import annotations

from ...kernel.observation import Observation
from ...kernel.technique import EngagementSeed, Hypothesis, ProbeSpec, Surface
from ...kernel.verdict import Candidate
from . import hypothesis as hypothesis_mod
from . import interpret as interpret_mod
from . import probes as probe_grammar
from .manifest import MANIFEST, NAME


class OobFetch:
    """Blind server-side fetch: proposed from an echo, confirmed by a listener."""

    manifest = MANIFEST

    def surfaces(self, seed: EngagementSeed) -> list[Surface]:
        """Surfaces claiming the capability this technique needs, and no others."""
        return [
            surface
            for surface in seed.for_capability("can_influence_remote_fetch")
            if surface.param
        ]

    def hypotheses(self, surface: Surface) -> list[Hypothesis]:
        return hypothesis_mod.hypotheses(surface)

    def probes(self, hypothesis: Hypothesis) -> list[ProbeSpec]:
        return probe_grammar.probes(hypothesis)

    def interpret(
        self, hypothesis: Hypothesis, observations: list[Observation]
    ) -> list[Candidate]:
        return interpret_mod.candidates(hypothesis, observations)


TECHNIQUE = OobFetch()

__all__ = ["MANIFEST", "NAME", "TECHNIQUE", "OobFetch"]
