"""``idor_differential`` — the technique folder, and therefore the registration.

Same shape as every technique: four pure modules and this thin adapter. The
technique is deliberately small — one hypothesis, two probes, one comparison —
because the hard part of an authorization test is not the probing, it is the
*identities*: the operator's two declared sessions are the entire source of
truth for what "should not be readable" means. The technique never invents
object references, never mutates ids, and never decides alone that a mismatch
is a bug; the differential verifier's flipped re-measurement is what promotes
a lead to a finding.
"""

from __future__ import annotations

from ...kernel.observation import Observation
from ...kernel.technique import (
    CAP_ACCESS_DIFFERS_BY_SESSION,
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


class IdorDifferential:
    """IDOR via a two-session differential: propose from the pair, confirm flipped."""

    manifest = MANIFEST

    def surfaces(self, seed: EngagementSeed) -> list[Surface]:
        """Only surfaces the operator claimed differ by session.

        Unlike the parameter techniques, ``with_param()`` does not apply: an
        object reference lives in the *path* (``/api/invoices/4821``), not in
        a query parameter, and requiring a param would silently exclude the
        technique's whole surface class. The capability claim is the only
        gate — the operator's statement that two identities exist here and
        that their access should differ — the same discipline that gates
        ``oob_fetch`` behind the remote-fetch claim and ``sqli_blind_time``
        behind the timing claim.
        """
        return [
            surface
            for surface in seed.surfaces
            if surface.capability == CAP_ACCESS_DIFFERS_BY_SESSION
        ]

    def hypotheses(self, surface: Surface) -> list[Hypothesis]:
        return hypothesis_mod.hypotheses(surface)

    def probes(self, hypothesis: Hypothesis) -> list[ProbeSpec]:
        return probe_grammar.probes(hypothesis)

    def interpret(
        self, hypothesis: Hypothesis, observations: list[Observation]
    ) -> list[Candidate]:
        return interpret_mod.candidates(hypothesis, observations)


TECHNIQUE = IdorDifferential()

__all__ = ["MANIFEST", "NAME", "IdorDifferential", "TECHNIQUE"]
