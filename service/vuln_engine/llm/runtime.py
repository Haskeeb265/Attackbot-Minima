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

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace

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
from ..abduction.deterministic import proposal_for as abduction_proposal
from ..abduction.proposal import Proposal
from ..techniques.common import with_parameter
from . import abduce, graph_nav, hypothesize, reflect, synthesize
from .client import LLMClient

NAME = "synthesize"
HYPOTHESIZE_NAME = "hypothesize"
REFLECT_NAME = "reflect"
GRAPH_NAV_NAME = "graph.navigate"
ABDUCE_NAME = "abduce"
PROPERTY_NAME = "propose.properties"


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
        graph_context: list[dict] | None = None,
        world=None,
        now: float = 0.0,
    ) -> HypothesizeResult:
        """The widened seed, or the operator's unchanged.

        Every proposed URL is validated against recon's observed set — the URL
        artifacts **and** the recon graph's linked assets; anything else
        degrades the opinion whole and the seed comes back exactly as it
        arrived. ``memory`` (a previous engagement's distilled record) and
        ``graph_context`` (the graph's own candidate rows) each become part of
        the question, so a run informed by either is a different question than
        one without it, and both are digest-keyed, so a replay reproduces each
        with the key removed.
        """
        input = hypothesize.build_input(parameters_rows, alive_urls, memory, graph_context)
        known_urls = {entry["url"] for entry in input["parameters"]}
        known_urls.update(u.strip().rstrip("/") for u in alive_urls if u.strip())
        known_urls.update(entry["url"] for entry in input.get("graph_context", []))
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


# --------------------------------------------------------------------------- #
# junction 6 — graph navigation: explore the recon graph tool by tool
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class GraphNavigation:
    """One navigation's outcome: the steps taken and the nodes it selected.

    ``selected_nodes`` are *candidate* node ids, not surfaces — the caller
    expands them through ``seed.candidates_for_nodes``, which re-applies the
    whole-graph rule and the scope filter.  ``source`` is ``live`` / ``cached`` /
    ``degraded`` for a model finish, or ``budget`` when the step cap stopped it.
    """

    steps: tuple[dict, ...] = ()
    selected_nodes: tuple[str, ...] = ()
    source: str = "degraded"
    reason: str = ""

    @property
    def observations(self) -> int:
        return len(self.steps)

    def to_dict(self) -> dict:
        return {
            "junction": GRAPH_NAV_NAME,
            "source": self.source,
            "reason": self.reason,
            "steps": [dict(step) for step in self.steps],
            "selected_nodes": list(self.selected_nodes),
        }


class GraphNavigator:
    """Run the bounded tool-calling loop against a dispatch callable.

    ``dispatch(tool_name, arguments) -> str`` is the composition root's wiring of
    ``platform.graph.tools.dispatch`` over a chosen backend; it is passed in as a
    plain callable so this layer never imports the recon platform's tool module
    (the same reason the grammars are wired in from ``run_engine``).
    """

    def __init__(self, client: LLMClient) -> None:
        self.client = client

    @property
    def available(self) -> bool:
        return self.client.available

    def navigate(
        self,
        goal: str,
        *,
        tool_names: list[str],
        dispatch: Callable[[str, dict], str],
        world=None,
        now: float = 0.0,
        max_steps: int = graph_nav.MAX_STEPS,
    ) -> GraphNavigation:
        """Explore until the model stops or the step budget runs out.

        Every step is one validated decision and one logged opinion; a step whose
        opinion is refused, or a dispatch that raises, ends the navigation with
        what it found so far rather than spinning.  The loop is deterministic in
        its *bounds* and its *validation*, not in the model's choices — which is
        exactly the advisory position every other junction holds.
        """
        if not self.client.available:
            return GraphNavigation(
                source="degraded", reason=self.client.health.reason
            )
        known = {str(name) for name in tool_names if str(name)}
        if not known:
            return GraphNavigation(
                source="degraded", reason="no graph tools were offered to the navigator"
            )
        transcript: list[dict] = []
        for step in range(1, max(1, int(max_steps)) + 1):
            input = graph_nav.build_input(goal, sorted(known), transcript)
            prompt, system = graph_nav.build_prompt(input)
            opinion = self.client.ask(
                junction=GRAPH_NAV_NAME,
                input=input,
                prompt=prompt,
                system=system,
                validate=graph_nav.validate_answer(known),
                world=world,
                now=now,
            )
            if not opinion.validated:
                return GraphNavigation(
                    steps=tuple(transcript),
                    source=opinion.source,
                    reason=opinion.reason or "navigation step refused",
                )
            action, tool, arguments, reason, nodes = graph_nav.extract(opinion.answer, known)
            if action == graph_nav.ACTION_STOP:
                return GraphNavigation(
                    steps=tuple(transcript),
                    selected_nodes=tuple(nodes),
                    source=opinion.source,
                    reason=reason or opinion.validation,
                )
            # One tool call, bounded and error-tolerant: a tool that raises is an
            # observation the next step can react to, never a crashed run.
            try:
                raw = dispatch(tool, arguments)
            except Exception as exc:  # noqa: BLE001 - a failed tool is a readable observation
                raw = json.dumps({"error": f"{type(exc).__name__}: {exc}"})
            transcript.append(
                {
                    "step": step,
                    "tool": tool,
                    "arguments": arguments,
                    "observation": graph_nav.summarize_tool_result(raw),
                }
            )
        return GraphNavigation(
            steps=tuple(transcript),
            source="budget",
            reason=f"step budget ({max(1, int(max_steps))}) exhausted before the model stopped",
        )


# --------------------------------------------------------------------------- #
# junction 7 — abduce: explain a retained surprise (A3's primary source)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class AbductionResult:
    """One abduction (or property) call's outcome, as the loop needs it."""

    #: The proposals the model's validated answer turned into, plan attached.
    proposals: tuple[Proposal, ...] = ()
    #: ``live`` | ``cached`` | ``degraded``.
    source: str = "degraded"
    reason: str = ""

    @property
    def proposed(self) -> int:
        return len(self.proposals)

    def to_dict(self) -> dict:
        return {
            "proposals": [proposal.to_dict() for proposal in self.proposals],
            "source": self.source,
            "reason": self.reason,
        }


class AbductionJunction:
    """Ask the model to explain a typed surprise, or to propose a property.

    Both channels go through the same shape: a bounded JSON answer naming a
    declared surface and a claim shape the ontology offers. The junction turns
    each validated row into a :class:`~...abduction.proposal.Proposal` over a
    real plan-table row; the three-valued validator downstream decides whether
    any verifier can prove it. Degraded (no key, refused answer, an invented
    surface) is an empty result — the deterministic abducer's control arm is
    unaffected.
    """

    def __init__(self, client: LLMClient) -> None:
        self.client = client

    @property
    def available(self) -> bool:
        return self.client.available

    def explain(
        self,
        anomaly: dict,
        surfaces: Sequence[Surface],
        *,
        memory: dict | None = None,
        world=None,
        now: float = 0.0,
    ) -> AbductionResult:
        """Explain one retained anomaly, or return nothing (degraded)."""
        if not self.client.available:
            return AbductionResult(source="degraded", reason=self.client.health.reason)
        known_keys = {surface.key for surface in surfaces}
        input = abduce.build_abduce_input(anomaly, surfaces, memory=memory)
        prompt, system = abduce.build_abduce_prompt(input)
        opinion = self.client.ask(
            junction=ABDUCE_NAME,
            input=input,
            prompt=prompt,
            system=system,
            validate=abduce.validate_answer("hypotheses", abduce.MAX_ABDUCED, known_keys),
            world=world,
            now=now,
        )
        if not opinion.validated:
            return AbductionResult(source=opinion.source, reason=opinion.reason)
        rows = abduce.extract(
            opinion.answer, list_name="hypotheses", cap=abduce.MAX_ABDUCED, known_surface_keys=known_keys
        )
        return AbductionResult(
            proposals=tuple(_proposals_from(rows, surfaces, witness=str(anomaly.get("arm", "")))),
            source=opinion.source,
            reason=opinion.validation,
        )

    def propose_properties(
        self,
        surfaces: Sequence[Surface],
        *,
        world=None,
        now: float = 0.0,
    ) -> AbductionResult:
        """A3's no-anomaly channel: properties from static context alone."""
        if not self.client.available:
            return AbductionResult(source="degraded", reason=self.client.health.reason)
        known_keys = {surface.key for surface in surfaces}
        input = abduce.build_property_input(surfaces)
        prompt, system = abduce.build_property_prompt(input)
        opinion = self.client.ask(
            junction=PROPERTY_NAME,
            input=input,
            prompt=prompt,
            system=system,
            validate=abduce.validate_answer("properties", abduce.MAX_PROPERTIES, known_keys),
            world=world,
            now=now,
        )
        if not opinion.validated:
            return AbductionResult(source=opinion.source, reason=opinion.reason)
        rows = abduce.extract(
            opinion.answer, list_name="properties", cap=abduce.MAX_PROPERTIES, known_surface_keys=known_keys
        )
        # A property has no anomaly to witness it, so its witness names the
        # property itself (surface + plan) — a constant witness would let the
        # pool collapse several distinct properties into one entry, and only the
        # first would ever run.
        proposals = tuple(
            replace(proposal, witness=f"property:{proposal.plan.get('plan_id', proposal.id)}")
            for proposal in _proposals_from(rows, surfaces, witness="property")
        )
        return AbductionResult(
            proposals=proposals,
            source=opinion.source,
            reason=opinion.validation,
        )


def _proposals_from(rows: list[dict], surfaces: Sequence[Surface], *, witness: str) -> list[Proposal]:
    """Turn validated rows into proposals over real plan rows, in order."""
    by_key = {surface.key: surface for surface in surfaces}
    out: list[Proposal] = []
    for row in rows:
        surface = by_key.get(str(row.get("surface_key", "")))
        if surface is None:
            continue
        proposal = abduction_proposal(
            surface=surface,
            surfaces=surfaces,
            claim_shape=str(row.get("claim_shape", "")),
            witness=witness,
            vuln_class=str(row.get("vuln_class", "")),
            summary=str(row.get("summary", "")),
        )
        if proposal is not None:
            out.append(proposal)
    return out


__all__ = [
    "ABDUCE_NAME",
    "GRAPH_NAV_NAME",
    "NAME",
    "HYPOTHESIZE_NAME",
    "PROPERTY_NAME",
    "REFLECT_NAME",
    "AbductionJunction",
    "AbductionResult",
    "GraphNavigation",
    "GraphNavigator",
    "HypothesisJunction",
    "HypothesizeResult",
    "ReflectDecision",
    "ReflectJunction",
    "SynthesisJunction",
    "SynthesisResult",
]
