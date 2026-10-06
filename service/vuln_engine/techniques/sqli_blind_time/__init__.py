"""``sqli_blind_time`` — the technique folder, and therefore the registration.

Same shape as the Phase 1 techniques: four pure modules and this thin adapter.
The confirmation population the *verifier* executes is derived from the
candidate's confirmation spec — which carries the winning variant's payloads —
so the grammar stays the one definition of the family and the verifier re-
measures the same SQL it was handed. The driver still defers every
``purpose="confirm"`` spec, so the engine never measures the verifier's
population twice.
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

    #: What ``surfaces()`` actually reads — the manifest's ``preconditions``
    #: names ``public_param`` (the cheap door this technique does NOT fire on,
    #: deliberately), so the closure pass needs this declared separately to
    #: know which claims open *this* technique's gate.
    gate_capabilities = (CAP_DELAYED_RESPONSE,)

    def surfaces(self, seed: EngagementSeed) -> list[Surface]:
        """Surfaces with an established timing influence — declared or measured.

        Unlike the cheap techniques, this one does not fire on ``public_param``:
        six bursty, distinctive requests per surface is the loudest probe set in
        the engine, and spending it on a surface whose declared purpose is an
        ordinary search box would be exactly the spend the noise budget exists
        to prevent. The claim is what makes the spend legitimate — and since
        Capability Closure it no longer has to be the operator's word: a
        surface the elicitor measured (``delayed_response`` established at
        differential grade by the dose-response probe) carries it in its
        ``capabilities`` set, and this gate reads both sources.
        """
        return [
            surface
            for surface in seed.with_param()
            if surface.claims(CAP_DELAYED_RESPONSE)
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
