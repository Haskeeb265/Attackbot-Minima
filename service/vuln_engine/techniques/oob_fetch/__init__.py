"""``oob_fetch`` — the blind technique folder, and therefore the registration.

Same four-file shape as ``xss_reflected``: manifest, hypothesis, probes,
interpret. That sameness is the contract working — the second technique needed no
change anywhere else in the engine, which is what "adding SSTI must never require
editing anything outside ``techniques/ssti/``" actually means in practice.
"""

from __future__ import annotations

from ...kernel.observation import Observation
from ...kernel.technique import (
    CAP_INFLUENCE_REMOTE_FETCH,
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


class OobFetch:
    """Blind server-side fetch: proposed from an echo, confirmed by a listener."""

    manifest = MANIFEST

    def surfaces(self, seed: EngagementSeed) -> list[Surface]:
        """Surfaces with an established remote-fetch capability — declared or measured.

        The declared route is the operator's word (``for_capability``, unchanged);
        the measured route is Capability Closure's: the remote-fetch elicitor
        plants our collaborator URL and the interaction record establishes the
        claim at ``oob`` grade, which this gate now reads from the surface's
        ``capabilities`` set. Either way the technique still proposes candidates
        that only the OOB verifier can prove.
        """
        return [
            surface
            for surface in seed.for_capability(CAP_INFLUENCE_REMOTE_FETCH)
            + [
                candidate
                for candidate in seed.with_param()
                if candidate.capabilities
                and CAP_INFLUENCE_REMOTE_FETCH in candidate.capabilities
            ]
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
