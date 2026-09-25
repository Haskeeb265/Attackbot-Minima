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
    EngagementSeed,
    Hypothesis,
    ProbeGrammar,
    ProbeSpec,
    Surface,
)
from ..techniques.common import with_parameter
from . import hypothesize, reflect, synthesize
from .client import LLMClient

NAME = "synthesize"
HYPOTHESIZE_NAME = "hypothesize"
REFLECT_NAME = "reflect"


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


# --------------------------------------------------------------------------- #
# junction 4 — hypothesize: propose surfaces from recon artifacts, nothing else
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class HypothesizeResult:
    """One junction call's outcome, as the CLI needs it."""

    #: The proposed surfaces, deduped against the operator's seed (head intact).
    surfaces: tuple[Surface, ...]
    #: How many raw proposals the model made before dedup against the seed.
    proposed_raw: int
    #: The merged seed: operator surfaces first, proposals appended.
    seed: EngagementSeed
    #: ``live`` | ``cached`` | ``degraded`` — for the report and the CLI line.
    source: str = "degraded"
    #: The acceptance label or the degradation reason.
    reason: str = ""

    @property
    def added(self) -> int:
        return len(self.surfaces)

    def to_dict(self) -> dict:
        """The provenance record a consumer embeds (the campaign report)."""
        return {
            "junction": HYPOTHESIZE_NAME,
            "source": self.source,
            "reason": self.reason,
            "proposed_raw": self.proposed_raw,
            "added": self.added,
            "surfaces": [surface.to_dict() for surface in self.surfaces],
        }


class HypothesisJunction:
    """Ask the model which measured parameters deserve a declared surface."""

    def __init__(self, client: LLMClient) -> None:
        self.client = client

    @property
    def available(self) -> bool:
        return self.client.available

    def propose_surfaces(
        self,
        seed: EngagementSeed,
        *,
        parameters_rows: list[dict],
        alive_urls: list[str],
        memory: dict | None = None,
        world=None,
        now: float = 0.0,
    ) -> HypothesizeResult:
        """The widened seed, or the operator's unchanged.

        Every proposed URL is validated against recon's observed set; anything
        else degrades the opinion whole and the seed comes back exactly as it
        arrived. ``memory`` (a previous engagement's distilled record) becomes
        part of the question — a run informed by memory asks a different
        question than one without it, and both are digest-keyed, so a replay
        reproduces each with the key removed.
        """
        input = hypothesize.build_input(parameters_rows, alive_urls, memory)
        known_urls = {entry["url"] for entry in input["parameters"]}
        known_urls.update(u.strip().rstrip("/") for u in alive_urls if u.strip())
        prompt, system = hypothesize.build_prompt(input)
        opinion = self.client.ask(
            junction=HYPOTHESIZE_NAME,
            input=input,
            prompt=prompt,
            system=system,
            validate=hypothesize.validate_answer(known_urls),
            world=world,
            now=now,
        )
        if not opinion.validated:
            return HypothesizeResult(
                surfaces=(),
                proposed_raw=0,
                seed=seed,
                source=opinion.source,
                reason=opinion.validation if opinion.validated else opinion.reason,
            )
        proposals = hypothesize.extract(opinion.answer, known_urls)
        proposed_surfaces = tuple(hypothesize.to_surface(p) for p in proposals)
        merged = hypothesize.merge_surfaces(seed.surfaces, proposed_surfaces)
        # The delta, not the raw list: a proposal of an already-declared surface
        # widens nothing and must not be counted as if it did.
        declared_keys = {surface.key for surface in seed.surfaces}
        added_surfaces = tuple(
            surface for surface in proposed_surfaces if surface.key not in declared_keys
        )
        return HypothesizeResult(
            surfaces=added_surfaces,
            proposed_raw=len(proposals),
            seed=EngagementSeed(target=seed.target, surfaces=merged),
            source=opinion.source,
            reason=opinion.validation,
        )


# --------------------------------------------------------------------------- #
# junction 5 — reflect: one bounded re-ask of a probe the pass already ran
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ReflectDecision:
    """One junction call's outcome, as the driver needs it."""

    #: ``stop`` or ``recheck``.
    action: str
    #: The probe id to re-ask (``""`` when stopping).
    probe_id: str = ""
    #: The model's one-phrase reason, when rechecking.
    reason: str = ""
    #: ``live`` | ``cached`` | ``degraded``.
    source: str = "degraded"
    #: The acceptance label or the degradation reason.
    detail: str = ""

    @property
    def recheck(self) -> bool:
        return self.action == reflect.ACTION_RECHECK

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "probe_id": self.probe_id,
            "reason": self.reason,
            "source": self.source,
            "detail": self.detail,
        }


class ReflectJunction:
    """Ask the model whether the pass's own readings warrant one re-ask."""

    def __init__(self, client: LLMClient) -> None:
        self.client = client

    @property
    def available(self) -> bool:
        return self.client.available

    def decide(
        self,
        *,
        hypothesis: dict,
        probe_rows: list[dict],
        observations_summary: list[dict],
        world=None,
        now: float = 0.0,
    ) -> ReflectDecision:
        """Stop-or-recheck, from typed readings only.

        Degraded in every honest direction: no client, a refused answer, or a
        ``recheck`` naming a probe the pass never ran all come back as
        ``stop`` — the engine's pre-reflect behavior, unchanged.
        """
        if not self.client.available:
            return ReflectDecision(action=reflect.ACTION_STOP, source="degraded", detail=self.client.health.reason)
        known_ids = {str(row.get("id", "")) for row in probe_rows}
        input = reflect.build_input(hypothesis, probe_rows, observations_summary)
        prompt, system = reflect.build_prompt(input)
        opinion = self.client.ask(
            junction=REFLECT_NAME,
            input=input,
            prompt=prompt,
            system=system,
            validate=reflect.validate_answer(known_ids),
            world=world,
            now=now,
        )
        if not opinion.validated:
            return ReflectDecision(
                action=reflect.ACTION_STOP,
                source=opinion.source,
                detail=opinion.reason,
            )
        action, probe_id, reason = reflect.extract(opinion.answer, known_ids)
        return ReflectDecision(
            action=action,
            probe_id=probe_id,
            reason=reason,
            source=opinion.source,
            detail=opinion.validation,
        )


__all__ = [
    "NAME",
    "HYPOTHESIZE_NAME",
    "REFLECT_NAME",
    "HypothesisJunction",
    "HypothesizeResult",
    "ReflectDecision",
    "ReflectJunction",
    "SynthesisJunction",
    "SynthesisResult",
]
