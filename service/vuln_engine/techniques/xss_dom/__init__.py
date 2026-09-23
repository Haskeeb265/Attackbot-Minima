"""``xss_dom`` — the technique folder, and therefore the registration.

Four pure modules and this class, the same thin adapter every other technique
has. The contract's acid test (``engine_principles.md`` §5) cuts both ways:
adding this folder must have required *nothing* outside it (one context, one
observation kind and one shared marker table in the kernel/techniques-common
layer, which the engine already owns), and deleting it must leave the engine
running exactly as before.
"""

from __future__ import annotations

from ...kernel.observation import Observation
from ...kernel.technique import EngagementSeed, Hypothesis, ProbeSpec, Surface
from ...kernel.verdict import Candidate
from . import hypothesis as hypothesis_mod
from . import interpret as interpret_mod
from . import probes as probe_grammar
from .manifest import MANIFEST, NAME


class XssDom:
    """DOM-based XSS: the browser is the parser; the verifier stays the proof."""

    manifest = MANIFEST

    def surfaces(self, seed: EngagementSeed) -> list[Surface]:
        """Parameterised surfaces, deliberately overlapping xss_reflected's.

        Both techniques ask different questions of the same surface ("did the
        server echo?" vs. "did the page render?"). On an SPA the first settles
        ``none`` and this technique gets to work; the scheduler's noise
        division keeps the loud question from being asked where the cheap one
        already answered it.
        """
        return [
            surface
            for surface in seed.with_param()
            if surface.capability in ("", "public_param")
        ]

    def hypotheses(self, surface: Surface) -> list[Hypothesis]:
        return hypothesis_mod.hypotheses(surface)

    def probes(self, hypothesis: Hypothesis) -> list[ProbeSpec]:
        return probe_grammar.probes(hypothesis)

    def interpret(
        self, hypothesis: Hypothesis, observations: list[Observation]
    ) -> list[Candidate]:
        return interpret_mod.candidates(hypothesis, observations)


TECHNIQUE = XssDom()

__all__ = ["MANIFEST", "NAME", "TECHNIQUE", "XssDom"]
