"""The advisory wiring: how the junctions attach without owning anything.

One object (:class:`Advisory`) holds the client and the three junctions and is
*passed in* to the driver, the campaign and the CLI. With no key configured,
building one is a no-op: every junction reports its degraded health, the
engine's inputs are exactly what Phases 1 and 2 ran with, and the e2e suite
runs green with no key — which is the design's own exit criterion, inherited
from Phase 1 and unchanged.

The three attach points, each advisory in a *checked* rather than promised way:

* **rank → campaign** — the ranking becomes an ``Arm.prior``, and the UCB math
  clamps the mean at ``REWARD_FOUND``: an opinion can lift an unproven arm
  toward a measured one, never past a proven one. That clamp (pinned by
  ``test_the_prior_never_outranks_a_measured_reward``) is what makes
  "advisory" structural: even a hostile or simply wrong opinion cannot outrank
  a measured reward;
* **synthesize → driver** — a valid answer adds *at most one* propose-purpose
  probe spec, which the driver runs through the ordinary gate. The model
  added a probe to the frontier; it did not add a conclusion;
* **write → CLI** — prose is drafted from typed finding fields and written
  into ``report.json`` beside the canonical lines, flagged as model-drafted.
  The canonical lines themselves remain pure derivations of the log.

Every junction call lands in the world log as an ``llm.junction`` row keyed by
input digest, so a replay reproduces the model's influence with the key
removed — the same property the gate's decisions and the scheduler's picks
already have.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ..kernel.technique import EngagementSeed, ProbeGrammar, ProbeSpec
from .client import EVENT_LLM_JUNCTION, Health, LLMClient, Opinion
from . import rank, synthesize, write
from .runtime import SynthesisJunction

log = logging.getLogger("vuln_engine.llm")


@dataclass
class Advisory:
    """The junctions, as one injectable object the consumers take or leave."""

    client: LLMClient
    #: Set only when the engine has a synthesis capability wired (the driver
    #: reads it via :func:`grammar_for`); ``None`` means "no technique offered
    #: a grammar", which is the ordinary shape for a registry of techniques
    #: that do not implement ``synthesis_grammar()``.
    synthesis: SynthesisJunction | None = None
    #: Grammars by technique name, read from the registry at wiring time.
    grammars: dict[str, ProbeGrammar] = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> "Advisory":
        """Build from the environment.  Always succeeds; health says the rest."""
        client = LLMClient()
        return cls(client=client, synthesis=SynthesisJunction(client))

    @property
    def health(self) -> Health:
        return self.client.health

    @property
    def available(self) -> bool:
        return self.client.available

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            **self.client.to_dict(),
        }

    # ------------------------------------------------------------------ #
    # junction 1 — rank
    # ------------------------------------------------------------------ #

    def ranking(self, seed: EngagementSeed, registry, *, log_handle=None, now: float = 0.0):
        """The advisory ranking over the registry's techniques, or the empty one.

        ``registry`` is a :class:`~..registry.TechniqueRegistry`; passing it
        unpacked keeps this module from importing it (and keeps the junctions
        importable from a context that has no registry).
        """
        techniques = [
            (registration.name, registration.manifest) for registration in registry.all()
        ]
        surfaces = [surface.key for surface in seed.surfaces]
        input = rank.build_input(techniques, surfaces)
        prompt, system = rank.build_prompt(input)
        known = [name for name, _manifest in techniques]
        opinion = self.client.ask(
            junction="rank",
            input=input,
            prompt=prompt,
            system=system,
            validate=rank.validate_answer(known),
            world=log_handle,
            now=now,
        )
        if not opinion.validated:
            return rank.Ranking(
                opinions={},
                degraded=True,
                reason=opinion.reason,
                model=opinion.model,
                source=opinion.source,
            )
        return rank.Ranking(
            opinions=rank.extract(opinion.answer),
            degraded=False,
            reason=opinion.validation,
            model=opinion.model,
            source=opinion.source,
        )

    def priors(self, seed: EngagementSeed, registry, *, log_handle=None, now: float = 0.0):
        """``{arm: prior}`` for the campaign: the ranking spread over the
        registry's (technique × surface) arms. Empty when degraded."""
        ranking = self.ranking(seed, registry, log_handle=log_handle, now=now)
        if ranking.empty:
            return {}
        return {
            f"{registration.name}@{surface.key}": ranking.prior_for(registration.name)
            for registration in registry.all()
            for surface in registration.technique.surfaces(seed)
        }

    # ------------------------------------------------------------------ #
    # junction 2 — synthesize
    # ------------------------------------------------------------------ #

    def grammar_for(self, technique_name: str) -> ProbeGrammar | None:
        """The synthesis grammar a technique exposed, or ``None``."""
        return self.grammars.get(technique_name)

    def synthesized_probe(
        self,
        technique_name: str,
        hypothesis,
        context: str,
        reflection_payload: dict,
        *,
        world=None,
        now: float = 0.0,
    ) -> ProbeSpec | None:
        """At most one synthesized canary spec, or ``None``.

        ``None`` when no grammar was wired (the technique does not implement
        ``synthesis_grammar()``), the model path is unavailable, the answer
        failed validation, or the chosen shape duplicates the stock payload.
        The opinion is on the record either way.
        """
        grammar = self.grammar_for(technique_name)
        if grammar is None or self.synthesis is None:
            return None
        result = self.synthesis.probe_for(
            grammar,
            hypothesis,
            context,
            reflection_payload,
            world=world,
            now=now,
        )
        return result.spec

    # ------------------------------------------------------------------ #
    # junction 3 — write
    # ------------------------------------------------------------------ #

    def draft_report(self, findings: list[dict], *, log_handle=None, now: float = 0.0) -> list[dict]:
        """Advisory prose for each finding, flagged as model-drafted.

        Degraded findings get an empty draft with the reason — the report
        shows *why* there is no prose, which is the no-key story in miniature.
        """
        drafts: list[dict] = []
        for finding in findings:
            input = write.finding_input(finding)
            prompt, system = write.build_prompt(input)
            opinion = self.client.ask(
                junction="write",
                input=input,
                prompt=prompt,
                system=system,
                validate=write.validate_answer(input),
                world=log_handle,
                now=now,
            )
            draft = write.Draft(
                candidate_id=str(finding.get("candidate_id", "")),
                prose=str(opinion.answer.get("prose", "")) if opinion.validated else "",
                degraded=not opinion.validated,
                reason=opinion.validation if opinion.validated else opinion.reason,
                model=opinion.model,
                source=opinion.source,
            )
            drafts.append(draft.to_dict())
        return drafts


def logged_opinions(log_handle) -> list[dict]:
    """Every ``llm.junction`` row on a log — the audit view of the model's say."""
    if log_handle is None:
        return []
    return log_handle.events(EVENT_LLM_JUNCTION)


def opinion_row(opinion: Opinion) -> dict:
    """The opinion as a plain dict — what a caller embeds in its own report."""
    return opinion.to_dict()


__all__ = [
    "Advisory",
    "logged_opinions",
    "opinion_row",
]
