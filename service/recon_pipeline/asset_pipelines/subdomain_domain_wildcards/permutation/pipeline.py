"""
End-to-end runner for the permutation stage.

::

    collect known hosts -> generate permutations (dnsgen)
                        -> resolve them (the active stage's engine)
                        -> wildcard filter -> write output/

Output contract (``permutation/output/``)
-----------------------------------------
======================= =====================================================
``known.txt``           the known hosts fed to the generator (shallowest first)
``dnsgen-raw.txt``      the generator's raw output, before filtering
``candidates.txt``      **generated candidates that are in scope and new**
``resolved.txt``        candidates that actually resolve (the artifact
                        downstream stages consume)
``wildcards.txt``       wildcard records confirmed while filtering
``wildcard_suppressed.txt`` generated names dropped as wildcard noise
``report.json``         machine-readable run report
``dnsgen.log``          generator stderr
======================= =====================================================

Reuse, not duplication
----------------------
This stage owns *generation* and nothing else.  Resolution is delegated to the
active stage's engine (``puredns`` by default) and wildcard handling to the
passive stage's detector, so all three stages share one definition of "resolves"
and one definition of "wildcard".  The validated resolver pool the active stage
wrote is reused by default rather than re-probed, so both stages resolve against
exactly the same resolvers.

No foreign-domain abort here, on purpose: the permutation stage cannot import a
stale target the way the other two can, because its only inputs are (a) names
already normalised into the apex's scope and (b) candidates it synthesises from
those names, which are re-normalised against the apex before anything is
queried.  A stale known-host file yields *no* known hosts, which is reported as
a fatal condition with an explicit message.
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path

import shared.colorlog as colorlog

from service.recon_pipeline.asset_pipelines.config import TARGET

from ....stealth.session import StealthConfig, StealthSession
from ..active import resolvers as resolver_mod
from ..active.resolve import DEFAULT_ENGINE, ENGINES, Engine, ResolveContext, get_engine
from ..active.resolvers import Query, dnspython_query
from ..active.settings import PASSIVE_ONLY, PUREDNS_RATE_LIMIT, QUARANTINE_FILE, STEALTH_ENABLED
from ..active.tools import ToolImageMissingError, ensure_image
from ..passive.normalize import canonicalize_host, normalize_host_list
from ..passive.wildcard import Resolver, detect_wildcards, filter_wildcard_noise
from .generate import (
    CANDIDATES_FILE,
    DOCKER_GENERATORS,
    GENERATORS,
    Generator,
    generate,
)
from .settings import (
    ACTIVE_RESOLVED_FILE,
    ACTIVE_RESOLVERS_FILE,
    ACTIVE_TRUSTED_FILE,
    MAX_CANDIDATES,
    OUTPUT_DIR,
    PASSIVE_SUBDOMAINS_FILE,
    REUSE_RESOLVERS,
    TIMEOUT,
)

log = logging.getLogger("permutation.pipeline")

RESOLVED_FILE = "resolved.txt"
WILDCARDS_FILE = "wildcards.txt"
SUPPRESSED_FILE = "wildcard_suppressed.txt"
REPORT_FILE = "report.json"


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #


@dataclass
class PermutationReport:
    """Machine-readable summary of one permutation stage run."""

    target: str
    generator: str
    engine: str
    started_at: str
    finished_at: str = ""
    seconds: float = 0.0
    ok: bool = True
    fatal: str | None = None
    resolvers: dict[str, object] = field(default_factory=dict)
    generation: dict[str, object] = field(default_factory=dict)
    steps: list[dict[str, object]] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    wildcards: list[str] = field(default_factory=list)
    suppressed: dict[str, str] = field(default_factory=dict)
    #: Stealth layer state (transport, identities, pacing, DNS budget, quarantine).
    #: Permutations are DNS-only work, so the DNS budget is what matters here.
    stealth: dict[str, object] = field(default_factory=dict)
    outputs: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(self.__dict__, indent=2, sort_keys=False)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _write_lines(path: Path, lines: Iterable[str]) -> Path:
    """Write newline-terminated lines atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(f"{line}\n" for line in lines if line)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(body, encoding="utf-8", newline="\n")
    tmp.replace(path)
    return path


def _write_json(path: Path, report: PermutationReport) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(report.to_json(), encoding="utf-8", newline="\n")
    tmp.replace(path)
    return path


# --------------------------------------------------------------------------- #
# Inputs
# --------------------------------------------------------------------------- #


def read_host_file(path: Path | str, apex: str) -> set[str]:
    """Read a host list, normalised into *apex*'s scope."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return set()
    except OSError as exc:
        log.warning("could not read %s (%s)", path, exc)
        return set()
    return set(normalize_host_list(text.splitlines(), apex))


def load_known_hosts(
    apex: str,
    *,
    files: Iterable[Path | str] = (),
    hosts: Iterable[str] = (),
    from_active: bool = True,
    from_passive: bool = True,
) -> dict[str, set[str]]:
    """Collect known hosts from every source, with provenance.

    Returns ``{source_label: hosts}``; ordering is stable so the report reads the
    same on every run.
    """
    sources: dict[str, set[str]] = {}
    if from_active:
        hosts_from_active = read_host_file(ACTIVE_RESOLVED_FILE, apex)
        if hosts_from_active:
            sources["active"] = hosts_from_active
    if from_passive:
        hosts_from_passive = read_host_file(PASSIVE_SUBDOMAINS_FILE, apex)
        if hosts_from_passive:
            sources["passive"] = hosts_from_passive
    for path in files:
        found = read_host_file(path, apex)
        if found:
            sources[Path(path).name] = found
    inline = set(normalize_host_list(hosts, apex))
    if inline:
        sources["inline"] = inline
    return sources


# --------------------------------------------------------------------------- #
# Stage
# --------------------------------------------------------------------------- #


def run_permutation_stage(
    target: str = TARGET,
    *,
    generator: Generator | str = "dnsgen",
    engine: Engine | str = DEFAULT_ENGINE,
    known_files: Iterable[Path | str] = (),
    known_hosts: Iterable[str] = (),
    from_active: bool = True,
    from_passive: bool = True,
    max_candidates: int = MAX_CANDIDATES,
    wildcards: bool = True,
    reuse_resolvers: bool = REUSE_RESOLVERS,
    resolvers: Iterable[str] | None = None,
    trusted_resolvers: Iterable[str] | None = None,
    timeout: float = TIMEOUT,
    output_dir: Path | str = OUTPUT_DIR,
    query: Query = dnspython_query,
    resolver: Resolver | None = None,
    stealth: bool = STEALTH_ENABLED,
    session: StealthSession | None = None,
) -> PermutationReport:
    """Generate, resolve and filter permutations of *target*'s known hosts.

    Parameters
    ----------
    generator / engine:
        A registered generator / engine, or its name.  Tests inject fakes.
    known_files / known_hosts / from_active / from_passive:
        Where the known hosts come from.
    max_candidates:
        Cap on generated candidates (``0`` disables the cap).
    reuse_resolvers:
        Reuse the active stage's validated pool instead of re-probing.
    query:
        Injected resolver-validation query, used only when the cached pool is
        unusable and the curated seed has to be probed (tests).
    resolver:
        Injected DNS resolver for the wildcard layer (tests).

    Returns
    -------
    PermutationReport
        Also written to ``output/report.json``.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    apex = canonicalize_host(target)
    if apex is None:
        raise ValueError(
            f"target {target!r} is not a valid domain (expected e.g. 'example.com')"
        )

    generator_obj = (
        generator if isinstance(generator, Generator) else _get_generator(generator)
    )
    engine_obj = engine if isinstance(engine, Engine) else get_engine(engine)

    started = time.monotonic()
    report = PermutationReport(
        target=apex,
        generator=generator_obj.name,
        engine=engine_obj.name,
        started_at=_utc_now(),
    )

    def finish() -> PermutationReport:
        report.finished_at = _utc_now()
        report.seconds = time.monotonic() - started
        if session is not None:
            report.stealth = session.to_dict()
            session.save()
        report.outputs["report"] = _write_json(output_dir / REPORT_FILE, report).as_posix()
        _log_summary(report)
        return report

    def abort(message: str) -> PermutationReport:
        log.error(message)
        report.ok = False
        report.fatal = message
        return finish()

    # 1. Stealth layer first: permutations are generated names resolved by brute
    #    force, i.e. the most clearly "enumerating" traffic this stage produces,
    #    so the passive-only gate and the DNS budget apply before anything runs.
    if session is None and stealth:
        session = StealthSession(
            StealthConfig.from_settings(
                quarantine_path=QUARANTINE_FILE,
                passive_only=PASSIVE_ONLY,
            )
        )
    if session is not None and session.passive_only:
        return abort(
            "passive-only mode is active (PASSIVE_ONLY, or a WAF quarantine carried over): "
            "refusing to resolve permutations"
        )

    # 2. Both the generator and the engine run out of the stage image.
    if engine_obj.name in ENGINES or generator_obj.name in DOCKER_GENERATORS:
        try:
            ensure_image()
        except ToolImageMissingError as exc:
            return abort(str(exc))
        except Exception as exc:
            return abort(f"Docker is not available: {exc}")

    # 3. Resolver pool: reuse the active stage's validated pool when possible.
    pool, reused = _prepare_resolvers(
        output_dir=output_dir,
        reuse=reuse_resolvers,
        resolvers=resolvers,
        trusted_resolvers=trusted_resolvers,
        query=query,
    )
    report.resolvers = {**pool.to_dict(), "reused": reused}
    if not pool.enough:
        return abort(
            f"only {len(pool.valid)} working resolver(s) available - refusing to "
            "resolve permutations against an unreliable pool"
        )

    # 3. Known hosts.
    sources = load_known_hosts(
        apex,
        files=known_files,
        hosts=known_hosts,
        from_active=from_active,
        from_passive=from_passive,
    )
    known: set[str] = set().union(*sources.values()) if sources else set()
    if not known:
        return abort(
            "no known hosts to permute - run the passive and/or active stage "
            "first (permutation derives candidates from names that already exist)"
        )
    log.info(
        "known hosts: %d from %s",
        len(known),
        ", ".join(f"{name}({len(hosts)})" for name, hosts in sources.items()),
    )

    # 4. Generate candidates.
    generation = generate(
        known,
        apex=apex,
        generator=generator_obj,
        output_dir=output_dir,
        timeout=timeout,
        limit=max_candidates,
    )
    report.generation = generation.to_dict()
    if not generation.ok:
        report.ok = False
    _write_lines(output_dir / CANDIDATES_FILE, generation.candidates)
    report.outputs[CANDIDATES_FILE] = (output_dir / CANDIDATES_FILE).as_posix()

    # 5. Resolve them with the active stage's engine, in shuffled, budget-sized
    #    batches when the stealth layer is active (see the active stage's
    #    ``resolve_all``: the budget is a name *count* per resolver, so it is
    #    enforced by batching, not by slowing one blast down).
    context = ResolveContext(
        apex=apex,
        output_dir=output_dir,
        resolvers=pool.valid,
        trusted=pool.trusted,
        timeout=timeout,
        rate_limit=PUREDNS_RATE_LIMIT or (session.dns_rate_limit(resolver_count=len(pool.valid)) if session else 0),
    )
    resolved: set[str] = set()
    if generation.candidates:
        if session is None:
            verdict = engine_obj.resolve(generation.candidates, context)
            report.steps.append(dict(verdict.to_dict(), step="resolve"))
            if not verdict.ok:
                report.ok = False
            resolved = verdict.resolved
        else:
            plan = session.plan_dns(list(generation.candidates), pool.valid, seed=apex)
            single = len(plan.batches) <= 1
            for batch in plan.batches:
                if batch.index:
                    session.pause_between_batches(batch.index)
                batch_context = context if single else replace(context, label=f"batch-{batch.index + 1}")
                verdict = engine_obj.resolve(list(batch.labels), batch_context)
                report.steps.append(
                    dict(verdict.to_dict(), step="resolve" if single else f"resolve-{batch.index + 1}")
                )
                if not verdict.ok:
                    report.ok = False
                resolved |= verdict.resolved

    # 6. Wildcard filter — applied only to the *generated* names.  A known host
    #    was established by an earlier stage and must not be re-argued here.
    verdicts = []
    suppressed: dict[str, str] = {}
    if wildcards and resolved:
        verdicts = detect_wildcards(apex, known | resolved, resolver=resolver)
        filtered = filter_wildcard_noise(
            {host: {"permutation"} for host in resolved}, verdicts, resolver=resolver
        )
        resolved = set(filtered.kept)
        suppressed = filtered.suppressed

    report.wildcards = sorted({v.pattern for v in verdicts if v.is_wildcard})
    report.suppressed = suppressed

    # 7. Outputs.  Keys are the artifact *filenames* (the constants above) because
    #    that is how the orchestrator looks up a stage's live-host list -- it
    #    imports each stage's ``RESOLVED_FILE`` and reads
    #    ``report.outputs[RESOLVED_FILE]``.  Naming these keys "resolved" instead
    #    made the lookup miss silently, and the union artifact was written without
    #    this stage's hosts.
    report.outputs[RESOLVED_FILE] = _write_lines(
        output_dir / RESOLVED_FILE, sorted(resolved)
    ).as_posix()
    report.outputs[WILDCARDS_FILE] = _write_lines(
        output_dir / WILDCARDS_FILE, report.wildcards
    ).as_posix()
    report.outputs[SUPPRESSED_FILE] = _write_lines(
        output_dir / SUPPRESSED_FILE, sorted(suppressed)
    ).as_posix()

    report.counts = {
        "known": len(known),
        "generated": int(generation.generated),
        "candidates": len(generation.candidates),
        "truncated": generation.truncated,
        "resolved": len(resolved),
        "wildcards": len(report.wildcards),
        "wildcard_suppressed": len(suppressed),
    }
    return finish()


def _get_generator(name: str) -> Generator:
    """Look up a registered generator, with a helpful message when unknown."""
    try:
        return GENERATORS[name]
    except KeyError:
        raise KeyError(
            f"unknown generator {name!r}; known: {', '.join(GENERATORS)}"
        ) from None


def _prepare_resolvers(
    *,
    output_dir: Path,
    reuse: bool,
    resolvers: Iterable[str] | None,
    trusted_resolvers: Iterable[str] | None,
    query: Query = dnspython_query,
):
    """Return ``(ResolverPreparation, reused)``.

    Reuse only applies when the caller did not pass explicit resolver lists: an
    operator who named resolvers wants *those* probed, not a cached pool.
    """
    if reuse and resolvers is None and trusted_resolvers is None:
        cached = [
            address
            for address in resolver_mod.load_resolvers_file(ACTIVE_RESOLVERS_FILE)
        ]
        if len(cached) >= resolver_mod.RESOLVER_MIN_VALID:
            trusted = resolver_mod.load_resolvers_file(ACTIVE_TRUSTED_FILE)
            trusted_valid = [address for address in trusted if address in set(cached)]
            log.info(
                "reusing the active stage's validated resolver pool (%d resolver(s), "
                "%d trusted)",
                len(cached),
                len(trusted_valid),
            )
            # The pool is *copied* into this stage's output directory rather than
            # referenced where the active stage wrote it: engines are pointed at
            # paths inside the mounted output dir, and only that directory is
            # visible to the container.  Referencing the active stage's file
            # would look fine here and fail inside puredns with "no such file".
            preparation = resolver_mod.ResolverPreparation(
                valid=cached,
                trusted=trusted_valid,
                paths={
                    "resolvers": resolver_mod.write_resolver_file(
                        output_dir / resolver_mod.OUTPUT_RESOLVERS_FILE, cached
                    ).as_posix(),
                    "resolvers_trusted": resolver_mod.write_resolver_file(
                        output_dir / resolver_mod.OUTPUT_TRUSTED_FILE, trusted_valid
                    ).as_posix(),
                    "source": Path(ACTIVE_RESOLVERS_FILE).as_posix(),
                },
            )
            return preparation, True
        log.warning(
            "no reusable resolver pool at %s - validating from the curated seed "
            "instead (run the active stage to populate it)",
            ACTIVE_RESOLVERS_FILE,
        )

    return (
        resolver_mod.prepare_resolvers(
            output_dir=output_dir,
            resolvers=resolvers,
            trusted=trusted_resolvers,
            query=query,
        ),
        False,
    )


def _log_summary(report: PermutationReport) -> None:
    counts = report.counts
    if report.fatal:
        colorlog.log.failed(f"permutation stage for {report.target}: {report.fatal}")
        return

    colorlog.log.info(
        f"permutation stage for {report.target}: {counts.get('resolved', 0)} new "
        f"live host(s) from {counts.get('candidates', 0)} candidate(s) "
        f"({counts.get('generated', 0)} generated from {counts.get('known', 0)} "
        f"known) in {report.seconds:.1f}s"
    )
    if counts.get("truncated"):
        colorlog.log.warn(
            f"generator output was capped: {counts['truncated']} candidate(s) "
            "dropped (raise PERMUTATION_MAX_CANDIDATES to keep them)"
        )
    if report.wildcards:
        colorlog.log.warn(
            "wildcard DNS present; generated names only explained by it were "
            f"dropped ({', '.join(report.wildcards)})"
        )
    if report.ok:
        colorlog.log.success(
            f"permuted live hosts written to {report.outputs.get(RESOLVED_FILE, RESOLVED_FILE)}"
        )
    else:
        colorlog.log.failed(
            f"permutation stage for {report.target} completed with failures - see "
            f"{report.outputs.get('report', REPORT_FILE)}"
        )


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m "
        "service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.permutation.pipeline",
        description=(
            "Generate permutations of the known hosts, resolve them with the "
            "active stage's engine, and write permutation/output/."
        ),
    )
    parser.add_argument(
        "-t", "--target", default=TARGET, help=f"apex domain (default: {TARGET})"
    )
    parser.add_argument(
        "--generator", default="dnsgen", help="candidate generator (default: dnsgen)"
    )
    parser.add_argument(
        "--engine", default=DEFAULT_ENGINE,
        help=f"resolution engine (default: {DEFAULT_ENGINE})",
    )
    parser.add_argument(
        "--known-file", action="append", default=[],
        help="extra known-host file (repeatable)",
    )
    parser.add_argument(
        "--no-active", action="store_true",
        help="do not seed known hosts from active/output/resolved.txt",
    )
    parser.add_argument(
        "--no-passive", action="store_true",
        help="do not seed known hosts from passive/output/subdomains.txt",
    )
    parser.add_argument(
        "--max-candidates", type=int, default=MAX_CANDIDATES,
        help=f"cap on generated candidates (default: {MAX_CANDIDATES})",
    )
    parser.add_argument(
        "--no-wildcards", action="store_true",
        help="skip wildcard detection and wildcard-flood suppression",
    )
    parser.add_argument(
        "--no-reuse-resolvers", action="store_true",
        help="re-validate resolvers instead of reusing the active stage's pool",
    )
    parser.add_argument(
        "--resolvers", action="append", default=[],
        help="resolver list to probe instead of the curated seed (repeatable)",
    )
    parser.add_argument(
        "--trusted-resolvers", action="append", default=[],
        help="trusted resolver list for poisoning validation (repeatable)",
    )
    parser.add_argument(
        "--timeout", type=float, default=TIMEOUT,
        help=f"per-tool timeout in seconds (default: {TIMEOUT})",
    )
    parser.add_argument(
        "--output-dir", default=str(OUTPUT_DIR),
        help=f"output directory (default: {OUTPUT_DIR})",
    )
    parser.add_argument(
        "--list", action="store_true", help="list generators and engines, then exit"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="show debug logging"
    )
    return parser


def _read_resolver_args(paths: Iterable[str]) -> list[str] | None:
    paths = list(paths)
    if not paths:
        return None
    addresses: list[str] = []
    for path in paths:
        addresses += resolver_mod.load_resolvers_file(path)
    return addresses


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.  Returns a process exit code."""
    args = _build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-7s %(name)s: %(message)s",
    )

    if args.list:
        from .generate import describe_generators

        print("generators")
        print("-" * 78)
        for row in describe_generators():
            print(f"  {row['name']:<12} {row['description']}")
        print("\nengines")
        print("-" * 78)
        from ..active.resolve import describe_engines

        for row in describe_engines():
            print(f"  {row['name']:<12} {row['description']}")
        return 0

    try:
        report = run_permutation_stage(
            args.target,
            generator=args.generator,
            engine=args.engine,
            known_files=args.known_file,
            from_active=not args.no_active,
            from_passive=not args.no_passive,
            max_candidates=args.max_candidates,
            wildcards=not args.no_wildcards,
            reuse_resolvers=not args.no_reuse_resolvers,
            resolvers=_read_resolver_args(args.resolvers),
            trusted_resolvers=_read_resolver_args(args.trusted_resolvers),
            timeout=args.timeout,
            output_dir=args.output_dir,
        )
    except (ValueError, KeyError) as exc:
        colorlog.log.failed(str(exc))
        return 2

    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
