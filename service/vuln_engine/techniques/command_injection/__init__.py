"""``command_injection`` — the technique folder, and therefore the registration.

Same shape as the other timing technique: four pure modules and this thin
adapter. The confirmation population the *verifier* executes is derived from the
candidate's confirmation spec — which carries the winning variant's payloads —
so the grammar stays the one definition of the family and the verifier
re-measures the same shell text it was handed. The driver still defers every
``purpose="confirm"`` spec, so the engine never measures the verifier's
population twice.
"""

from __future__ import annotations

from ...kernel.observation import Observation
from ...kernel.technique import (
    CAP_DELAYED_RESPONSE,
    EngagementSeed,
    Hypothesis,
    ProbeSpec,
    Surface,
)
from ...kernel.verdict import Candidate
from . import hypothesis as hypothesis_mod
from . import interpret as interpret_mod
from . import probes as probe_grammar
from .manifest import MANIFEST, NAME


class CommandInjection:
    """Blind OS command injection via a timing side channel."""

    manifest = MANIFEST

    def surfaces(self, seed: EngagementSeed) -> list[Surface]:
        """Only surfaces whose *declared claim* is the timing influence.

        The same deliberate narrowness the SQLi timing technique applies: the
        loudest probe set in the engine is not spent on a surface whose declared
        purpose is an ordinary search box. The operator's ``delayed_response``
        claim is what makes the spend legitimate — and it is the *same* claim
        the SQLi technique reads, because both are explanations of one declared
        fact ("time depends on this parameter"). Which of them is right is the
        measurement's job, not the operator's.
        """
        return [
            surface
            for surface in seed.with_param()
            if surface.capability == CAP_DELAYED_RESPONSE
        ]

    def hypotheses(self, surface: Surface) -> list[Hypothesis]:
        return hypothesis_mod.hypotheses(surface)

    def probes(self, hypothesis: Hypothesis) -> list[ProbeSpec]:
        return probe_grammar.probes(hypothesis)

    def interpret(
        self, hypothesis: Hypothesis, observations: list[Observation]
    ) -> list[Candidate]:
        return interpret_mod.candidates(hypothesis, observations)


TECHNIQUE = CommandInjection()

__all__ = ["MANIFEST", "NAME", "CommandInjection", "TECHNIQUE"]
