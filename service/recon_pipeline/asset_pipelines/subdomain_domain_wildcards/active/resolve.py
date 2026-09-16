"""
Resolution engines, bruteforce, and recursion.

Everything that turns *candidate names* into *live hosts* lives here, behind one
small interface::

    Engine.resolve(candidates, ctx) -> EngineResult
    Engine.bruteforce(words, ctx)   -> EngineResult

Two engines ship (``puredns`` and ``shuffledns``, both massdns wrappers) and the
pipeline takes an engine object rather than a name, so tests substitute a fake
engine and never touch Docker or DNS.

Why two subcommands of the same tool
------------------------------------
Level-1 bruteforce uses ``puredns bruteforce`` (the engine streams the wordlist
itself, which is what lets a 110k-word SecLists list run without materialising a
giant file here).  Recursion cannot use it: ``puredns bruteforce`` takes exactly
one apex, while recursion brute-forces *many* parents at once.  Those parents are
expanded into ``word.parent`` names locally and resolved in a single
``puredns resolve`` call — one container and the same query count, instead of one
container per parent.

Why recursion exists at all
---------------------------
A boring generic wordlist finds ``dev.example.com``.  Only a *second* pass under
it finds ``api.dev.example.com`` — the names that are usually both less
monitored and more likely to be an unauthenticated staging copy.  The pass is
bounded three ways (``RECURSION_MAX_DEPTH``, ``RECURSION_MAX_PARENTS``,
``RECURSION_WORD_LIMIT``) so it stays a widening step, not an open-ended sweep:
at most 25 parents × 250 words = 6,250 extra queries per level.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ..passive.docker_tool import DockerTimeoutError, DockerUnavailableError, ContainerRun
from ..passive.normalize import canonicalize_host, normalize_host_list, parent_of
from .settings import (
    DEFAULT_SOURCE_TIMEOUT,
    PUREDNS_RATE_LIMIT,
    PUREDNS_WILDCARD_TESTS,
    RECURSION_MAX_DEPTH,
    RECURSION_MAX_PARENTS,
    RECURSION_WORD_LIMIT,
)
from .tools import (
    WORKDIR,
    WORK_CANDIDATES,
    WORK_RESOLVERS,
    WORK_TRUSTED,
    WORK_WORDLIST,
    last_error,
    puredns_bruteforce_args,
    puredns_resolve_args,
    run_tool,
    shuffledns_args,
)

log = logging.getLogger("active.resolve")

# --- artefact names inside output/ (= inside the container's /work) ---------
RESOLVE_OUTPUT = "puredns.txt"
BRUTEFORCE_OUTPUT = "puredns-bruteforce.txt"
RESOLVE_WILDCARDS = "puredns-wildcards.txt"
BRUTEFORCE_WILDCARDS = "puredns-bruteforce-wildcards.txt"

#: Local input artefact names; they mirror the container paths in ``tools``.
CANDIDATES_NAME = "candidates.txt"
WORDLIST_NAME = "wordlist.txt"


def _work(name: str) -> str:
    """Container path for an artefact in the mounted output directory."""
    return f"{WORKDIR}/{name}"


def phase_name(name: str, ctx: ResolveContext) -> str:
    """Suffix an artefact name with the context's phase label.

    ``puredns.txt`` for a stage's primary resolve becomes
    ``puredns-recursive-1.txt`` for the first recursion pass, so each phase keeps
    its own inputs and raw results side by side.
    """
    if not ctx.label:
        return name
    stem, _, extension = name.partition(".")
    return f"{stem}-{ctx.label}.{extension}" if extension else f"{stem}-{ctx.label}"


def write_list_file(path: Path | str, lines: Iterable[str]) -> Path:
    """Write newline-terminated lines atomically, **preserving order**.

    ``passive.normalize.write_host_list`` sorts, which is right for host lists
    and wrong for a wordlist: recursion shortlists the *first* N words, so the
    operator's priority order has to survive the round trip to disk.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(f"{line}\n" for line in lines if line)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(body, encoding="utf-8", newline="\n")
    tmp.replace(path)
    return path


# --------------------------------------------------------------------------- #
# Context and results
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ResolveContext:
    """Everything an engine needs to run one resolution job.

    ``label`` distinguishes the *phase* a call belongs to.  A stage resolves more
    than once against the same output directory (candidates, then each recursion
    pass), and without a label every call would reopen the same
    ``candidates.txt`` / ``puredns.txt`` — leaving only the last phase's raw
    evidence on disk.  The pipeline labels recursion passes; the default leaves
    the plain names for a stage's primary resolve.
    """

    apex: str
    output_dir: Path
    resolvers: list[str] = field(default_factory=list)
    trusted: list[str] = field(default_factory=list)
    timeout: float = DEFAULT_SOURCE_TIMEOUT
    wildcard_tests: int = PUREDNS_WILDCARD_TESTS
    rate_limit: int = PUREDNS_RATE_LIMIT
    label: str = ""

    @property
    def trusted_path(self) -> str | None:
        """Container path of the trusted list, or ``None`` to skip validation.

        The file only exists meaningfully when trusted resolvers passed
        validation, and passing an empty file would make puredns validate
        against nothing — so ``None`` (``--skip-validation``) is the honest
        signal.
        """
        return WORK_TRUSTED if self.trusted else None


@dataclass
class EngineResult:
    """Outcome of one engine invocation."""

    engine: str
    mode: str
    candidates: int = 0
    resolved: set[str] = field(default_factory=set)
    #: Wildcard parents the engine itself filtered (cross-checks our detector).
    wildcards: list[str] = field(default_factory=list)
    ok: bool = True
    seconds: float = 0.0
    error: str | None = None
    output: str | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "engine": self.engine,
            "mode": self.mode,
            "candidates": self.candidates,
            "resolved": len(self.resolved),
            "ok": self.ok,
            "seconds": round(self.seconds, 2),
        }
        if self.wildcards:
            payload["wildcards"] = list(self.wildcards)
        if self.output:
            payload["output"] = self.output
        if self.error:
            payload["error"] = self.error
        return payload


# --------------------------------------------------------------------------- #
# Reading tool output
# --------------------------------------------------------------------------- #


def read_resolved_file(path: Path | str, apex: str) -> set[str]:
    """Read a massdns-wrapper ``-w`` file into canonical, in-scope hosts."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    return set(normalize_host_list(text.splitlines(), apex))


def read_wildcard_file(path: Path | str) -> list[str]:
    """Read an engine's ``--write-wildcards`` file into bare parent names.

    Engines have printed both ``example.com`` and ``*.example.com`` across
    versions, so both forms are accepted; anything unparseable is dropped rather
    than guessed at.
    """
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    roots: set[str] = set()
    for line in text.splitlines():
        entry = line.strip().lstrip("*.").rstrip(".").lower()
        host = canonicalize_host(entry)
        if host:
            roots.add(host)
    return sorted(roots)


def _run_engine(
    *,
    engine: str,
    mode: str,
    candidates: int,
    runner: Callable[[], ContainerRun],
    read: Callable[[], tuple[set[str], list[str]]],
) -> EngineResult:
    """Shared timing / failure handling around one engine invocation."""
    started = time.monotonic()
    try:
        run = runner()
    except DockerTimeoutError as exc:
        log.error("%s %s timed out: %s", engine, mode, exc)
        return EngineResult(
            engine=engine, mode=mode, candidates=candidates, ok=False,
            seconds=time.monotonic() - started, error=str(exc),
        )
    except DockerUnavailableError as exc:
        return EngineResult(
            engine=engine, mode=mode, candidates=candidates, ok=False,
            seconds=time.monotonic() - started, error=str(exc),
        )

    elapsed = time.monotonic() - started
    if not run.ok:
        reason = last_error(run)
        log.error("%s %s failed: %s", engine, mode, reason)
        return EngineResult(
            engine=engine, mode=mode, candidates=candidates, ok=False,
            seconds=elapsed, error=reason, output=Path(run.stdout_path).as_posix(),
        )

    resolved, wildcards = read()
    return EngineResult(
        engine=engine,
        mode=mode,
        candidates=candidates,
        resolved=resolved,
        wildcards=wildcards,
        ok=True,
        seconds=elapsed,
        output=Path(run.stdout_path).as_posix(),
    )


# --------------------------------------------------------------------------- #
# puredns
# --------------------------------------------------------------------------- #


def puredns_resolve(candidates: Sequence[str], ctx: ResolveContext) -> EngineResult:
    """Bulk-resolve *candidates* with ``puredns resolve`` (wildcard-filtered)."""
    names = list(dict.fromkeys(candidates))
    if not names:
        return EngineResult(engine="puredns", mode="resolve", candidates=0)

    write_list_file(ctx.output_dir / phase_name(CANDIDATES_NAME, ctx), names)
    args = puredns_resolve_args(
        input_path=_work(phase_name(CANDIDATES_NAME, ctx)),
        output_path=_work(phase_name(RESOLVE_OUTPUT, ctx)),
        wildcards_path=_work(phase_name(RESOLVE_WILDCARDS, ctx)),
        resolvers=WORK_RESOLVERS,
        trusted=ctx.trusted_path,
        wildcard_tests=ctx.wildcard_tests,
        rate_limit=ctx.rate_limit,
    )
    return _run_engine(
        engine="puredns",
        mode="resolve",
        candidates=len(names),
        runner=lambda: run_tool(
            "puredns", args, output_dir=ctx.output_dir, timeout=ctx.timeout, suffix="-resolve"
        ),
        read=lambda: (
            read_resolved_file(ctx.output_dir / phase_name(RESOLVE_OUTPUT, ctx), ctx.apex),
            read_wildcard_file(ctx.output_dir / phase_name(RESOLVE_WILDCARDS, ctx)),
        ),
    )


def puredns_bruteforce(words: Sequence[str], ctx: ResolveContext) -> EngineResult:
    """Enumerate ``word.apex`` for every word with ``puredns bruteforce``."""
    labels = list(dict.fromkeys(words))
    if not labels:
        return EngineResult(engine="puredns", mode="bruteforce", candidates=0)

    write_list_file(ctx.output_dir / WORDLIST_NAME, labels)
    args = puredns_bruteforce_args(
        ctx.apex,
        wordlist=WORK_WORDLIST,
        output_path=_work(BRUTEFORCE_OUTPUT),
        wildcards_path=_work(BRUTEFORCE_WILDCARDS),
        resolvers=WORK_RESOLVERS,
        trusted=ctx.trusted_path,
        wildcard_tests=ctx.wildcard_tests,
        rate_limit=ctx.rate_limit,
    )
    return _run_engine(
        engine="puredns",
        mode="bruteforce",
        candidates=len(labels),
        runner=lambda: run_tool(
            "puredns",
            args,
            output_dir=ctx.output_dir,
            timeout=ctx.timeout,
            suffix="-bruteforce",
        ),
        read=lambda: (
            read_resolved_file(ctx.output_dir / BRUTEFORCE_OUTPUT, ctx.apex),
            read_wildcard_file(ctx.output_dir / BRUTEFORCE_WILDCARDS),
        ),
    )


# --------------------------------------------------------------------------- #
# shuffledns
# --------------------------------------------------------------------------- #


def _shuffledns(
    mode: str, names: Sequence[str], ctx: ResolveContext, *, suffix: str
) -> EngineResult:
    """Shared implementation of the shuffledns engine's two modes."""
    items = list(dict.fromkeys(names))
    if not items:
        return EngineResult(engine="shuffledns", mode=mode, candidates=0)

    base_name = CANDIDATES_NAME if mode == "resolve" else WORDLIST_NAME
    input_name = phase_name(base_name, ctx)
    input_path = _work(input_name)
    write_list_file(ctx.output_dir / input_name, items)

    args = shuffledns_args(
        ctx.apex,
        mode=mode,
        wordlist=input_path if mode != "resolve" else None,
        list_path=input_path if mode == "resolve" else None,
        resolvers=WORK_RESOLVERS,
    )
    return _run_engine(
        engine="shuffledns",
        mode=mode,
        candidates=len(items),
        runner=lambda: run_tool(
            "shuffledns",
            args,
            output_dir=ctx.output_dir,
            timeout=ctx.timeout,
            suffix=f"{suffix}{'-' + ctx.label if ctx.label else ''}",
            stdout_name=phase_name(f"shuffledns-{mode}.txt", ctx),
        ),
        read=lambda: (
            set(
                normalize_host_list(
                    read_stdout_output(ctx, phase_name(f"shuffledns-{mode}.txt", ctx)),
                    ctx.apex,
                )
            ),
            [],
        ),
    )


def read_stdout_output(ctx: ResolveContext, name: str) -> list[str]:
    """Read a stdout-captured tool output file by name."""
    try:
        text = (ctx.output_dir / name).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return text.splitlines()


def shuffledns_resolve(candidates: Sequence[str], ctx: ResolveContext) -> EngineResult:
    """Resolve *candidates* with ``shuffledns -mode resolve``."""
    return _shuffledns("resolve", candidates, ctx, suffix="-resolve")


def shuffledns_bruteforce(words: Sequence[str], ctx: ResolveContext) -> EngineResult:
    """Enumerate ``word.apex`` with ``shuffledns -mode bruteforce``."""
    return _shuffledns("bruteforce", words, ctx, suffix="-bruteforce")


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Engine:
    """A resolution engine: a named pair of resolve/bruteforce callables."""

    name: str
    resolve: Callable[[Sequence[str], ResolveContext], EngineResult]
    bruteforce: Callable[[Sequence[str], ResolveContext], EngineResult]
    description: str = ""


ENGINES: dict[str, Engine] = {
    "puredns": Engine(
        name="puredns",
        resolve=puredns_resolve,
        bruteforce=puredns_bruteforce,
        description="massdns + heuristic wildcard filtering + trusted-resolver "
        "poisoning validation (default)",
    ),
    "shuffledns": Engine(
        name="shuffledns",
        resolve=shuffledns_resolve,
        bruteforce=shuffledns_bruteforce,
        description="massdns wrapper with strict-wildcard checks; the fallback "
        "when puredns' heuristic disagrees with a target",
    ),
}

DEFAULT_ENGINE = "puredns"

#: Aliases so ``--engine`` accepts the convenience spellings operators type.
ENGINE_ALIASES = {"dnsx": "shuffledns", "massdns": "puredns"}


def get_engine(name: str) -> Engine:
    """Look up an engine by name (following aliases)."""
    key = ENGINE_ALIASES.get(name, name)
    try:
        return ENGINES[key]
    except KeyError:
        raise KeyError(
            f"unknown engine {name!r}; known: {', '.join(ENGINES)}"
        ) from None


def select_engine(names: Iterable[str] = ()) -> Engine:
    """First requested engine that exists; the default when none is named."""
    for name in names:
        return get_engine(name)
    return ENGINES[DEFAULT_ENGINE]


def describe_engines() -> list[dict[str, str]]:
    """Human-readable engine summary (used by ``pipeline --list``)."""
    return [
        {"name": engine.name, "description": engine.description}
        for engine in ENGINES.values()
    ]


# --------------------------------------------------------------------------- #
# Candidate derivation
# --------------------------------------------------------------------------- #


def depth_below(name: str, apex: str) -> int:
    """How many labels *name* has below *apex* (``api.dev.x.com`` -> 2)."""
    if name == apex or not name.endswith("." + apex):
        return 0
    return len(name[: -(len(apex) + 1)].split("."))


def apex_candidates(words: Iterable[str], apex: str) -> list[str]:
    """``word.apex`` for every word — the level-1 candidate set."""
    return [f"{word}.{apex}" for word in dict.fromkeys(words)]


def recursion_parents(
    known: Iterable[str],
    apex: str,
    *,
    max_depth: int = RECURSION_MAX_DEPTH,
    max_parents: int = RECURSION_MAX_PARENTS,
    prefer: Iterable[str] = (),
) -> list[str]:
    """Hosts worth brute-forcing *under*, best candidates first.

    Two kinds of parent qualify, both capped at *max_depth* labels below the
    apex:

    * **the known host itself** — ``dev.example.com`` is where
      ``api.dev.example.com`` would live, so a live host is the first place to
      brute; and
    * **its ancestors** — ``api.dev.example.com`` is evidence that
      ``dev.example.com`` is a real environment even when that name itself never
      resolved (it can legitimately have no A record while its children do).

    *prefer* (normally the set of hosts that actually resolved) orders those
    parents first: they are proven live, so a query spent under them is likelier
    to hit than one spent under an unresolved ancestor.  Depth is the tie-breaker,
    since a shallow parent is where a generic wordlist is most likely to land.
    """
    preferred = set(prefer)
    parents: set[str] = set()
    for name in known:
        if depth_below(name, apex) < max_depth:
            parents.add(name)
        current = parent_of(name)
        while current and current != apex:
            if depth_below(current, apex) >= max_depth:
                break
            parents.add(current)
            current = parent_of(current)

    ordered = sorted(
        parents,
        key=lambda parent: (
            0 if parent in preferred else 1,
            depth_below(parent, apex),
            parent,
        ),
    )
    if len(ordered) > max_parents:
        log.info(
            "recursion: %d candidate parent(s), capped at %d (live parents first, "
            "then shallowest)",
            len(ordered),
            max_parents,
        )
    return ordered[:max_parents]


def recursive_candidates(
    parents: Iterable[str], words: Iterable[str], *, word_limit: int = RECURSION_WORD_LIMIT
) -> list[str]:
    """``word.parent`` for every (parent, word) pair, shortlisting the words."""
    shortlist = list(dict.fromkeys(words))[: max(1, word_limit)]
    return [f"{word}.{parent}" for parent in parents for word in shortlist]

