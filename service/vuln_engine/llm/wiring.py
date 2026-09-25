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

import json
import logging
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from ..kernel.technique import CAP_DELAYED_RESPONSE, CAP_INFLUENCE_REMOTE_FETCH, CAP_PUBLIC_PARAM, EngagementSeed, ProbeGrammar, ProbeSpec, Surface

if TYPE_CHECKING:
    from .runtime import HypothesizeResult, ReflectDecision
from .client import EVENT_LLM_JUNCTION, Health, LLMClient, Opinion
from . import rank, synthesize, write
from .runtime import HypothesisJunction, ReflectJunction, SynthesisJunction

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
    #: Junction 4 (hypothesize), built in ``from_env``. Present whenever an
    #: Advisory exists; it is only *asked* when the operator requests it (the
    #: CLI's ``--hypothesize-from-recon``), because widening the seed is an
    #: operator decision, not a default behaviour.
    hypothesize: HypothesisJunction | None = None
    #: Junction 5 (reflect), built in ``from_env``. Asked by the driver after
    #: an empty interpretation, bounded by ``reflect.MAX_REFLECT_ROUNDS``; a
    #: degraded opinion leaves the one-pass behavior unchanged.
    reflect: ReflectJunction | None = None

    @classmethod
    def from_env(cls) -> "Advisory":
        """Build from the environment.  Always succeeds; health says the rest."""
        client = LLMClient()
        return cls(
            client=client,
            synthesis=SynthesisJunction(client),
            hypothesize=HypothesisJunction(client),
            reflect=ReflectJunction(client),
        )

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
    # junction 4 — hypothesize (asked only on the operator's request)
    # ------------------------------------------------------------------ #

    def hypothesized_seed(
        self,
        seed: EngagementSeed,
        *,
        parameters_rows: list[dict],
        alive_urls: list[str],
        memory: dict | None = None,
        log_handle=None,
        now: float = 0.0,
    ) -> "HypothesizeResult":
        """The junction-4 result for *seed* over the given recon artifacts.

        Thin pass-through so callers do not import the runtime; degrades to
        the operator's unchanged seed whenever the junction is missing or the
        model path is unavailable.
        """
        from .runtime import HypothesizeResult

        if self.hypothesize is None or not self.available:
            return HypothesizeResult(
                surfaces=(),
                proposed_raw=0,
                seed=seed,
                source="degraded",
                reason=self.health.reason if not self.available else "no hypothesize junction wired",
            )
        return self.hypothesize.propose_surfaces(
            seed,
            parameters_rows=parameters_rows,
            alive_urls=alive_urls,
            memory=memory,
            world=log_handle,
            now=now,
        )

    # ------------------------------------------------------------------ #
    # junction 5 — reflect (asked by the driver after an empty interpretation)
    # ------------------------------------------------------------------ #

    def reflected_decision(
        self,
        *,
        hypothesis: dict,
        probe_rows: list[dict],
        observations_summary: list[dict],
        log_handle=None,
        now: float = 0.0,
    ) -> "ReflectDecision":
        """The junction-5 decision for one finished pass.

        Thin pass-through; degrades to ``stop`` — the exact pre-reflect
        behavior — whenever the junction is missing or the model is not
        available.
        """
        from .runtime import ReflectDecision

        if self.reflect is None:
            return ReflectDecision(
                action="stop",
                source="degraded",
                detail="no reflect junction wired",
            )
        return self.reflect.decide(
            hypothesis=hypothesis,
            probe_rows=probe_rows,
            observations_summary=observations_summary,
            world=log_handle,
            now=now,
        )

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


def hypothesized_seed_advisory(
    advisory: "Advisory | None",
    seed: EngagementSeed,
    *,
    parameters_rows: list[dict],
    alive_urls: list[str],
    memory: dict | None = None,
    log_handle=None,
    now: float = 0.0,
):
    """Module-level convenience for a caller that may have no advisory at all."""
    if advisory is None:
        from .runtime import HypothesizeResult

        return HypothesizeResult(
            surfaces=(),
            proposed_raw=0,
            seed=seed,
            source="degraded",
            reason="no advisory wired",
        )
    return advisory.hypothesized_seed(
        seed,
        parameters_rows=parameters_rows,
        alive_urls=alive_urls,
        memory=memory,
        log_handle=log_handle,
        now=now,
    )


def load_recon_artifacts(recon_dir: Path | str) -> tuple[list[dict], list[str]]:
    """Read the two artifacts the hypothesize junction consumes.

    ``recon_dir`` is the ``url_endpoint`` pipeline directory (the one holding
    ``output/parameters.jsonl`` and ``output/url_validation.jsonl``). Both are
    optional on disk — a run that skipped the URL pipeline yields empty lists
    and the junction degrades to "nothing measured". Malformed lines are
    skipped, like every JSONL reader in this codebase.
    """
    base = Path(recon_dir)
    rows: list[dict] = []
    for path, keys in (
        (base / "output" / "parameters.jsonl", ("url", "parameter", "location", "kind")),
    ):
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                payload = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(payload, dict) and all(key in payload for key in keys):
                rows.append({key: payload[key] for key in keys})

    alive: list[str] = []
    validation = base / "output" / "url_validation.jsonl"
    if validation.is_file():
        for line in validation.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                payload = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(payload, dict):
                continue
            if payload.get("alive") and payload.get("url"):
                alive.append(str(payload["url"]))
    return rows, alive


def remember(log_path: Path | str, target: str) -> dict:
    """Distill one engagement's world log into a memory record.

    The safe form of AWE's long-term cross-target memory (RnD addendum M3.3):
    a **deterministic** extraction of what previous engagements of this target
    saw — per-arm receipt outcomes, the reflection contexts each surface
    produced, status distributions, timing medians, and the leads that stayed
    leads. No model call, no fine-tuning: the file is an *input* the next
    run's hypothesize junction reads, which keeps it replayable — a memory
    that changes answers is part of the digest, and a memory that is wrong is
    in the repository where an operator can read and correct it.

    Returns the record (also the caller's cue to write it where they want it).
    """
    from ..world.log import WorldLog as _Log
    from ..world import views as _views

    log = _Log(log_path)
    rows = log.rows

    arms: dict[str, dict] = {}
    for row in rows:
        if row.get("type") != "receipt":
            continue
        arm = str(row.get("arm", ""))
        entry = arms.setdefault(arm, {"arm": arm, "outcomes": {}})
        outcome = str(row.get("outcome", ""))
        entry["outcomes"][outcome] = entry["outcomes"].get(outcome, 0) + 1

    contexts: dict[str, set[str]] = {}
    statuses: dict[str, list[int]] = {}
    elapsed: dict[str, list[float]] = {}
    for item in log.observations():
        key = str(item.probe or "")
        if not key:
            continue
        context = item.payload.get("context")
        if context:
            contexts.setdefault(key, set()).add(str(context))
        status = item.payload.get("status")
        if status is not None:
            try:
                statuses.setdefault(key, []).append(int(status))  # type: ignore[arg-type]
            except (TypeError, ValueError):
                pass
        timing = item.payload.get("timing_class")
        if timing:
            try:
                elapsed.setdefault(f"{key}:{timing}", []).append(float(item.payload.get("elapsed", 0.0)))  # type: ignore[arg-type]
            except (TypeError, ValueError):
                pass

    leads = [str(row.get("id", "")) for row in _views.leads(log.since(0.0))]
    return {
        "target": target,
        "runs": sum(1 for row in rows if row.get("type") == "run.begin"),
        "arms": sorted(arms.values(), key=lambda entry: entry["arm"]),
        "probes": [
            {
                "probe": key,
                "contexts": sorted(contexts.get(key, set())),
                "statuses": sorted(statuses.get(key, [])),
            }
            for key in sorted(set(contexts) | set(statuses))
        ],
        "timing_medians": {
            key: round(statistics.median(values), 4)
            for key, values in sorted(elapsed.items())
            if values
        },
        "leads": leads,
    }


def load_memory(path: Path | str) -> dict:
    """Read a memory file, or ``{}`` when absent/corrupt — never an error."""
    file = Path(path)
    if not file.is_file():
        return {}
    try:
        payload = json.loads(file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, ValueError, OSError):
        return {}
    return payload if isinstance(payload, dict) else {}


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
    "hypothesized_seed_advisory",
    "load_memory",
    "load_recon_artifacts",
    "logged_opinions",
    "opinion_row",
    "remember",
]
