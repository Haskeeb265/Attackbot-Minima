"""The platform contract: what it takes to *be* a recon pipeline.

A pipeline is a **folder** under ``service/recon_pipeline/pipelines/`` that
satisfies this contract.  Adding a new asset pipeline is nothing but adding a
folder; the platform's :mod:`..registry` discovers it at run time and the
runner, CLI, report and report-assembly pick it up without a single edit
elsewhere.

The contract has three parts:

1. **A manifest** — a small :class:`Manifest` instance exposed as module-level
   ``MANIFEST`` in the folder's ``__init__.py`` (or in ``pipeline.py``).  It
   declares the pipeline's name, the asset types it produces, the stages it
   exposes and the artifact paths other consumers may read.

2. **A pipeline class** — subclass of :class:`Pipeline`, exposed as
   module-level ``PIPELINE`` in the same module.  It implements
   :meth:`Pipeline.run` for each declared stage.

The contract may live in ``contract.py`` (preferred — it can never collide
with an implementation module named ``pipeline.py``), in ``pipeline.py``, or
in the folder's ``__init__``.  The registry checks them in that order.

3. **Standard settings** — a ``settings.py`` in the folder reading ``<NAME>_*``
   environment variables, honouring the platform's prefix conventions.

Everything else is *consumed from the platform*, never re-implemented:
host canonicalization and IO helpers from :mod:`platform.common`, scope
decisions from :mod:`platform.scope`, asset scoring from
:mod:`platform.scoring`, active-traffic shaping from
:mod:`platform.stealth`, hot caching from :mod:`platform.cache`, and the
graph write seam from :mod:`platform.graph` (journaled until a schema is
designed from observed runs).  A pipeline receives these through the
:class:`RunContext` handed to :meth:`Pipeline.run` — it does not import
services directly, which is what keeps a pipeline folder self-contained and
the platform swappable.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

#: Where all pipeline folders live (the only registration point).
PIPELINES_PACKAGE = "service.recon_pipeline.pipelines"

#: The modules a pipeline folder may expose its contract from, in order:
#: ``contract.py`` (preferred — never collides with an implementation module
#: named ``pipeline.py``), then ``pipeline.py``, then the folder's ``__init__``.
CONTRACT_MODULE = "contract"
CONTRACT_MODULE_FALLBACKS = ("pipeline", "__init__")


@dataclass(frozen=True)
class Stage:
    """One independently-runnable stage of a pipeline."""

    name: str
    description: str = ""


@dataclass(frozen=True)
class Manifest:
    """The declarative half of the pipeline contract.

    ``name`` is the folder name (validated against it at discovery time);
    ``asset_types`` are the ``recon.md`` §3 rows this pipeline collects;
    ``provides`` names the graph kinds it can populate; ``consumes`` names
    the artifact paths of *other* pipelines it reads (declared, so the runner
    can order pipelines and the report can show the data flow); ``stages``
    are the independently-runnable stages in run order.
    """

    name: str
    title: str
    asset_types: tuple[str, ...]
    description: str = ""
    provides: tuple[str, ...] = ()
    consumes: tuple[str, ...] = ()
    stages: tuple[Stage, ...] = ()
    #: When True the pipeline never sends traffic to the target (passive-only
    #: collection).  The dispatcher may still gate it; the flag is what the
    #: report and the safety checks read.
    passive_only: bool = False
    #: Artifact paths (relative to the pipeline folder) whose *contents* are this
    #: pipeline's contribution to the **discovery frontier**.  The convergence
    #: driver (:mod:`.convergence`) reads them after every round and canonicalises
    #: each line into an asset token (``host:``/``ip:``/``url:``/``net:``) to
    #: answer one question: did this round put anything new on the table?
    #: Empty means the pipeline contributes no frontier — it is one-shot or a pure
    #: model reader.
    frontier_artifacts: tuple[str, ...] = ()
    #: Stages worth re-running when the frontier has grown (rounds 2+).  Empty
    #: means the pipeline runs **once** per engagement: re-running it would ask a
    #: question whose answer cannot have changed (an apex-wide archive query, a
    #: seed-keyed registry lookup).  Declaring this is the difference between
    #: "iterate until exhausted" and "re-ask the same question five times".
    repeat_stages: tuple[str, ...] = ()
    #: Which frontier **kinds** make repeating this pipeline worth a request
    #: (``host`` / ``ip`` / ``url`` / ``net`` — the prefix of a canonical token).
    #: A round in which nothing new of these kinds appeared skips the pipeline
    #: entirely, which is how "only spend requests on genuinely new assets" is
    #: enforced in one place instead of re-derived per stage.  Empty means "any
    #: new asset" — the conservative default, since a pipeline that declares no
    #: repeat stages is never gated and one that does usually knows what it wants.
    repeat_on: tuple[str, ...] = ()

    def stage_names(self) -> tuple[str, ...]:
        return tuple(stage.name for stage in self.stages)

    @property
    def repeatable(self) -> bool:
        """True when this pipeline has stages worth re-running on new assets."""
        return bool(self.repeat_stages)

    def wanted_by(self, kinds: Iterable[str]) -> bool:
        """Would a round with new assets of *kinds* be worth repeating this pipeline?

        Allowed-by-default: with no ``repeat_on`` declaration any new asset is
        reason enough, so declaring nothing never silently disables a pipeline.
        """
        if not self.repeatable:
            return False
        if not self.repeat_on:
            return True
        return any(kind in self.repeat_on for kind in kinds)


@dataclass
class RunContext:
    """Everything a pipeline run may consume from the platform.

    Handed to :meth:`Pipeline.run`; a pipeline takes what it needs and ignores
    the rest.  Services degrade gracefully: a missing Redis yields a cache
    object that reports ``available=False`` with a reason instead of raising,
    and the run report carries the degradation forward. The graph sink does
    the same — and until a schema is designed from observed data (2026-09-19
    removed the pre-run guess), every write is journaled and ``available`` is
    False with that reason.
    """

    #: The apex domain this run targets.
    target: str
    #: Declared + discovered scope, with the §5.4 gate decisions.
    scope: Any = None
    #: The S2 scoring engine (pure).
    scoring: Any = None
    #: The S8 hot cache; ``available=False`` when Redis is down.
    cache: Any = None
    #: Graph sink; ``available=False`` when Neo4j is down.
    graph: Any = None
    #: Stealth session factory for any active step (already configured).
    stealth: Any = None
    #: The S10 dispatcher/gate for active steps; None in passive-only runs.
    dispatcher: Any = None
    #: The S9 stream queue; degrades to a local spool without Redis.
    queue: Any = None
    #: S13 LLM enrichment; ``available=False`` without keys.
    enricher: Any = None
    #: This run's observability record (S14) — timings land here automatically.
    run_record: Any = None
    #: Per-pipeline settings namespace (env prefix derived from the manifest).
    env_prefix: str = ""
    #: Extra options forwarded from the CLI (``--set key=value``).
    options: dict[str, str] = field(default_factory=dict)
    #: Pipeline outputs go here (the runner owns the directory layout).
    output_dir: Any = None
    #: The program block (S4): what the scraper's program declared and how it
    #: was applied to this run's scope engine — handle, declared counts,
    #: refusals, and the scope file the port stage reads. ``None`` for a
    #: classic single-target run (the ``-t``/``TARGET`` path, unchanged).
    program: dict | None = None

    def log(self) -> Any:
        """The platform's structured logger (colorlog-backed)."""
        import shared.colorlog as colorlog

        return colorlog.log


@runtime_checkable
class Pipeline(Protocol):
    """The behavioural half of the contract.

    ``run(stage, context)`` executes one declared stage and returns a
    JSON-serialisable dict — the stage's machine report.  The runner persists
    it, times it, and folds failures into the run report; a pipeline raises to
    fail a stage and the platform decides what that means for the rest of the
    run.
    """

    manifest: Manifest

    def run(self, stage: str, context: RunContext) -> dict[str, Any]: ...


class BasePipeline:
    """Convenience base for pipeline classes — provides ``self.log``.

    Subclassing is *optional* (the registry accepts any object satisfying the
    :class:`Pipeline` protocol), but most pipelines want the logger.
    """

    manifest: Manifest

    @staticmethod
    def log() -> Any:
        import shared.colorlog as colorlog

        return colorlog.log

    def reset(self) -> None:
        """Drop per-pass cached state; called before each convergence round.

        Most pipelines are stateless between calls — they read artifacts and
        write artifacts.  A few cache the first stage's intermediate work so the
        second and third stages of *the same pass* do not redo it (\
        ``graph_normalize``'s collected facts, ``asn_cidr``'s already-produced
        artifacts).  Without a reset those caches would hand round 2 the results
        of round 1, and the loop would look convergent precisely because it was
        stale.  The default is a no-op, so a pipeline that does not override it
        is safe either way.
        """
        return None
