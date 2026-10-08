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
    CAP_RESPONSE_REFLECTS_INPUT,
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

    #: What ``surfaces()`` actually reads — the OR-gate in full. The manifest's
    #: ``preconditions`` names only the declared claim (``public_param``); the
    #: *measured* route (Capability Closure's reflection elicitor, or a graph
    #: derivation that carries the claim in the surface's capabilities set) is
    #: the second half of the gate. Closure reads this attribute to know which
    #: capabilities it must be able to measure — declaring it here is what makes
    #: the measured route reachable instead of a silent dead arm.
    gate_capabilities = (CAP_PUBLIC_PARAM, CAP_RESPONSE_REFLECTS_INPUT)

    #: The positions this technique's canary can aim at (item 3.2) — the
    #: classic core's three plus ``header``/``url``, reached through the
    #: shared ``header_request`` / ``with_url_parameter`` builders. Kept here
    #: rather than widened in ``EngagementSeed.with_param`` on purpose: the
    #: kernel accessor still answers for the *classic* grammar every technique
    #: inherits, and only a technique whose probes actually aim at the new
    #: positions offers itself to them. The manifest's ``gate_where`` names the
    #: same set for the loud where-gate.
    CANARY_WHERE = ("query", "body", "path", "header", "url")

    def surfaces(self, seed: EngagementSeed) -> list[Surface]:
        """Parameterised surfaces, in the order the operator declared them.

        A surface whose *declared* claim is another technique's territory is
        left alone — that is what keeps a capability claim meaningful in both
        directions: ``oob_fetch`` fires where the surface claims the server
        fetches, and this technique does not spend a canary on a parameter the
        operator declared for that purpose. Every other route in is open: an
        undeclared parameter, a declared ``public_param``, a *derived* or
        *measured* ``public_param`` riding the surface's capabilities set, and a
        surface the reflection elicitor measured as reflecting (Capability
        Closure). ``claims()`` is the one accessor that reads both sources.
        Item 3.2 widens the position filter to this technique's own
        ``CANARY_WHERE``: a header or url surface is probeable here now, while
        the kernel's classic accessor stays the classic grammar.
        """
        return [
            surface
            for surface in seed.surfaces
            if surface.param
            and surface.where in self.CANARY_WHERE
            and (
                surface.capability in ("", CAP_PUBLIC_PARAM)
                or surface.claims(CAP_PUBLIC_PARAM)
                or surface.claims(CAP_RESPONSE_REFLECTS_INPUT)
            )
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
