"""``xss_stored`` — the technique folder, and therefore the registration.

Same four-module shape as its reflected sibling, with the stored class's one
structural difference made visible in the surface filter: this technique only
considers surfaces the operator *declared as storing* (``server_stores_input``).
That is the complement of ``xss_reflected``'s filter, and it is what keeps two
techniques from probing the same body parameter for different questions: a body
parameter on an ordinary form is the wire lens's territory; a body parameter on
a surface that persists is this one's.

The class is a thin adapter over the four functions, exactly as the contract
prescribes — the logic lives where it can be tested without an instance, a
driver or a network.
"""

from __future__ import annotations

from ...kernel.observation import Observation
from ...kernel.technique import (
    CAP_PERSISTENT_STORAGE,
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


class XssStored:
    """Stored XSS: propose from the read-back reflection, never confirm it."""

    manifest = MANIFEST

    def surfaces(self, seed: EngagementSeed) -> list[Surface]:
        """Surfaces the operator declared as *storing*, with a body parameter.

        A stored technique on an ordinary form surface would double-probe it for
        half the information; the capability claim is what separates the two
        classes' territories.
        """
        return [
            surface
            for surface in seed.with_param()
            if surface.capability == CAP_PERSISTENT_STORAGE
        ]

    def hypotheses(self, surface: Surface) -> list[Hypothesis]:
        return hypothesis_mod.hypotheses(surface)

    def probes(self, hypothesis: Hypothesis) -> list[ProbeSpec]:
        return probe_grammar.probes(hypothesis)

    def interpret(
        self, hypothesis: Hypothesis, observations: list[Observation]
    ) -> list[Candidate]:
        return interpret_mod.candidates(hypothesis, observations)


TECHNIQUE = XssStored()

__all__ = ["MANIFEST", "NAME", "TECHNIQUE", "XssStored"]
