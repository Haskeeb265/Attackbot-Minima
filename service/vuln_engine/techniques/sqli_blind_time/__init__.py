"""``sqli_blind_time`` — the technique folder, and therefore the registration.

Same shape as the Phase 1 techniques: four pure modules and this thin adapter.
The one Phase 2 addition is :func:`measurement_probes` — the confirmation
population the *verifier* executes, exposed as module data so the differential
verifier can read the grammar without importing anything impure. The driver
still defers every ``purpose="confirm"`` spec, so the engine never measures the
verifier's population twice.
"""

from __future__ import annotations

from ...kernel.observation import Observation
from ...kernel.technique import (
    CAP_DELAYED_RESPONSE,
    CAP_PUBLIC_PARAM,
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


class SqliBlindTime:
    """Blind SQLi via a timing side channel: propose from the gap, confirm fresh."""

    manifest = MANIFEST

    def surfaces(self, seed: EngagementSeed) -> list[Surface]:
        """Only surfaces whose *declared claim* is the timing influence.

        Unlike the cheap techniques, this one does not fire on ``public_param``:
        six bursty, distinctive requests per surface is the loudest probe set in
        the engine, and spending it on a surface whose declared purpose is an
        ordinary search box would be exactly the spend the noise budget exists
        to prevent. The operator's ``delayed_response`` claim is what makes the
        spend legitimate — the same discipline ``oob_fetch`` applies to the
        remote-fetch claim.
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


TECHNIQUE = SqliBlindTime()

__all__ = ["MANIFEST", "NAME", "SqliBlindTime", "TECHNIQUE"]
