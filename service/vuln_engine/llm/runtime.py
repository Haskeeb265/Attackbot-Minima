"""The junctions' runtime: ask the model once, then hand the pure half the answer.

The split is deliberate: :mod:`.synthesize` (the grammar, the validation, the
payload construction) is pure and testable against canned answers;
:class:`SynthesisJunction` is the only place that talks to the client. It keeps
the ask→validate→construct→spec sequence in one reviewable place, and it takes
the technique's :class:`~...kernel.technique.ProbeGrammar` **as an argument** —
it never imports a technique module, so deleting a technique folder leaves the
junction with nothing to synthesize for rather than a broken import.

What the junction returns is a :class:`~...kernel.technique.ProbeSpec` with
``purpose=PURPOSE_PROPOSE``: the driver runs it like any other canary, the
technique interprets it like any other observation, and confirmation stays
with the verifier. The model added a probe to the grammar's frontier; it did
not add a conclusion.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..kernel.technique import (
    KIND_HTTP,
    ORACLE_REFLECTION,
    PURPOSE_PROPOSE,
    Hypothesis,
    ProbeGrammar,
    ProbeSpec,
)
from ..techniques.common import with_parameter
from . import synthesize
from .client import LLMClient

NAME = "synthesize"


@dataclass(frozen=True)
class SynthesisResult:
    """One junction call's outcome, as the driver needs it."""

    #: The synthesized probe spec, or ``None`` when nothing passed validation.
    spec: ProbeSpec | None
    #: The payload the spec carries, for the log (echoes ``spec.payload``).
    payload: str = ""

    @property
    def synthesized(self) -> bool:
        return self.spec is not None


class SynthesisJunction:
    """Ask the model for a breakout shape and turn a *valid* answer into a spec."""

    def __init__(self, client: LLMClient) -> None:
        self.client = client

    @property
    def available(self) -> bool:
        return self.client.available

    def probe_for(
        self,
        grammar: ProbeGrammar,
        hypothesis: Hypothesis,
        context: str,
        reflection_payload: dict,
        *,
        world=None,
        now: float = 0.0,
    ) -> SynthesisResult:
        """The synthesized canary spec for *context*, or ``None``.

        ``None`` when: the context is outside the grammar (the junction is not
        even asked), the model path is unavailable, the answer failed
        validation, or the chosen shape reproduces the stock payload (the
        grammar already has that probe — a duplicate would spend a request to
        learn nothing).
        """
        _ = grammar.technique_name  # the id prefix comes from the caller's spec id
        if not synthesize.supported(hypothesis, context):
            return SynthesisResult(spec=None)
        if not self.client.available:
            return SynthesisResult(spec=None)

        input = synthesize.build_input(hypothesis, context, reflection_payload)
        prompt, system = synthesize.build_prompt(input)
        opinion = self.client.ask(
            junction=NAME,
            input=input,
            prompt=prompt,
            system=system,
            validate=synthesize.validate_answer(context),
            world=world,
            now=now,
        )
        if not opinion.validated:
            return SynthesisResult(spec=None)

        payload = synthesize.construct_payload(
            context,
            opinion.answer,
            script_body=grammar.script_body_for(hypothesis, context),
            close_prefix=grammar.breakout_prefix_for(hypothesis, context),
        )
        stock = grammar.stock_payload_for(hypothesis, context)
        if payload == stock:
            return SynthesisResult(spec=None)

        spec_id = f"{grammar.technique_name}:synth:{context}"
        surface = hypothesis.surface
        url = with_parameter(surface.url, surface.param, payload)
        return SynthesisResult(
            spec=ProbeSpec(
                id=spec_id,
                kind=KIND_HTTP,
                host=surface.host,
                detail={"url": url, "method": "GET"},
                oracle=ORACLE_REFLECTION,
                canary=payload,
                mark=grammar.mark,
                noise={
                    "requests_per_surface": 1,
                    "burstiness": 0.0,
                    "fingerprint_distance": 0.0,
                    "requires_browser": False,
                },
                produces="reflection",
                purpose=PURPOSE_PROPOSE,
                payload=payload,
            ),
            payload=payload,
        )


__all__ = ["NAME", "SynthesisJunction", "SynthesisResult"]
