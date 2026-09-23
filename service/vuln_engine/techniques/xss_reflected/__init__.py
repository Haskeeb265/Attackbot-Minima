"""``xss_reflected`` — the technique folder, and therefore the registration.

Four pure modules and this class. Adding a technique means adding a folder like
this one; deleting it must leave the engine running exactly as before, which is
the contract's acid test (``engine_principles.md`` §5). Nothing outside this folder
knows it exists except the registry, which discovers it.

The class is a thin adapter over the four functions, and that thinness is the
point: the logic lives in ``hypothesis.py``, ``probes.py`` and ``interpret.py``,
where it can be read and tested without an instance, a driver or a network.
"""

from __future__ import annotations

from ...kernel.observation import Observation
from ...kernel.technique import (
    CAP_PUBLIC_PARAM,
    EngagementSeed,
    Hypothesis,
    ProbeGrammar,
    ProbeSpec,
    Surface,
)
from ...kernel.verdict import Candidate
from . import hypothesis as hypothesis_mod
from . import interpret as interpret_mod
from . import probes as probe_grammar
from .manifest import MANIFEST, NAME


class XssReflected:
    """Reflected XSS: propose from the reflection's context, never confirm it."""

    manifest = MANIFEST

    def surfaces(self, seed: EngagementSeed) -> list[Surface]:
        """Parameterised surfaces, in the order the operator declared them.

        A surface the operator declared with a *different* capability is left
        alone. That is what keeps a capability claim meaningful in both directions:
        ``oob_fetch`` fires only where the surface claims the server fetches, and
        this technique does not spend a canary on a parameter whose declared purpose
        is to carry a URL somebody else fetches.
        """
        return [
            surface
            for surface in seed.with_param()
            if surface.capability in ("", CAP_PUBLIC_PARAM)
        ]

    def hypotheses(self, surface: Surface) -> list[Hypothesis]:
        return hypothesis_mod.hypotheses(surface)

    def probes(self, hypothesis: Hypothesis) -> list[ProbeSpec]:
        return probe_grammar.probes(hypothesis)

    def interpret(
        self, hypothesis: Hypothesis, observations: list[Observation]
    ) -> list[Candidate]:
        return interpret_mod.candidates(hypothesis, observations)

    def synthesis_grammar(self) -> ProbeGrammar:
        """What the Phase 3 synthesis junction may reuse, as an argument.

        Optional per the technique contract: a technique without this method
        simply has nothing for the junction to synthesize against. Everything
        here is this folder's own deterministic output — the junction never
        imports this module, which is what keeps the removability contract
        intact (delete the folder and ``getattr`` finds no grammar; the driver
        logs the degraded reason and moves on).
        """
        from . import probes as grammar

        return ProbeGrammar(
            technique_name=NAME,
            mark=grammar.MARK,
            script_body_for=grammar.script_body,
            breakout_prefix_for=grammar._payload_prefix,
            stock_payload_for=grammar.payload_for,
        )


TECHNIQUE = XssReflected()

__all__ = ["MANIFEST", "NAME", "TECHNIQUE", "XssReflected"]
