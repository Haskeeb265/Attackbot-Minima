"""``python -m service.recon_pipeline`` — the canonical operator CLI.

Subcommands:

- ``list``                 — every discovered pipeline (name, asset types, stages)
- ``run``                  — run pipelines against a target (the default action)
- ``run --program HANDLE`` — engage an ingested program: scope comes from the
  scraper's tables (S4), one engagement per declared domain, fail-fast on
  anything the database cannot answer
- ``run --list-programs``  — every ingested program, with its scope-row counts
- ``history``              — the run registry (last N runs)
- ``dlq``                  — inspect the dead-letter queue
- ``replay``               — reports the journaled graph writes awaiting the future schema (no schema exists yet)

``run_recon.py`` remains for the legacy combined-report workflow; everything
it does routes through this module's runner.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import shared.colorlog as colorlog


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m service.recon_pipeline",
        description="The ASM platform: discover pipelines, run them, score and persist.",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("list", help="list discovered pipelines and exit")

    run = sub.add_parser("run", help="run pipelines against a target")
    run.add_argument(
        "-t", "--target",
        help="apex domain (default: TARGET from .env; names the engagement with --scope-file; not with --program)",
    )
    run.add_argument(
        "--program", metavar="HANDLE",
        help=(
            "engage an ingested program: scope comes from the scraper's tables "
            "(one engagement per declared domain, fail-fast on unknown handles). "
            "Long-only on purpose: -p is --pipeline"
        ),
    )
    run.add_argument(
        "--domain", metavar="DOMAIN",
        help="with --program: run a single engagement for this one declared domain",
    )
    run.add_argument(
        "--scope-file", action="append", default=[], dest="scope_files", metavar="PATH",
        help=(
            "operator-authored scope file (one asset per line: domain:cidr:ip:" 
            "wildcard:value or bare; # comments). Repeatable; replaces the .env TARGET"
        ),
    )
    run.add_argument(
        "--asset", action="append", default=[], dest="assets", metavar="ASSET",
        help="inline declared asset, classified by the same rules (repeatable)",
    )
    run.add_argument(
        "--list-programs", action="store_true",
        help="list ingested programs (handle, scope rows, domain count) and exit",
    )
    run.add_argument(
        "-p", "--pipeline", action="append", dest="pipelines",
        help="pipeline to run (repeatable; default: all discovered)",
    )
    run.add_argument(
        "-s", "--stage", action="append", dest="stages",
        help="stage to run (repeatable; default: every declared stage)",
    )
    run.add_argument(
        "--set", action="append", default=[], dest="options",
        help="forward key=value to pipelines (repeatable)",
    )
    run.add_argument("--output-root", default=None, help="runs/ root (default: repo output/)")
    run.add_argument(
        "--until-converged", "--converge", action="store_true", dest="converge",
        help=(
            "loop rounds until the discovery frontier stops growing (or a budget "
            "says stop); later rounds re-run only pipelines' declared repeat stages"
        ),
    )
    run.add_argument(
        "--max-rounds", type=int, default=None,
        help="round ceiling for --until-converged (default 4)",
    )
    run.add_argument(
        "--time-budget", type=float, default=None,
        help="seconds allowed for the whole converged run (default 2700; 0 = no limit)",
    )
    run.add_argument(
        "--max-active-actions", type=int, default=None,
        help="cumulative active actions across all rounds (0 = unlimited)",
    )

    history = sub.add_parser("history", help="show recent runs")
    history.add_argument("-n", "--limit", type=int, default=10)
    history.add_argument("-t", "--target", default=None, help="filter to one target")

    sub.add_parser("dlq", help="inspect the dead-letter queue")
    sub.add_parser("replay", help="report journaled graph writes awaiting the future schema")
    return parser


def _default_target() -> str | None:
    try:
        from .platform.common.config import TARGET

        return TARGET
    except Exception:
        return None


def _load_program_scope(handle: str):
    """Load a program's declared scope — or fail the run before anything runs.

    Scope is the safety input: an unknown handle, an empty scope or a database
    that will not answer is exit code 2 with the reason, never a silent
    fallback to whatever ``TARGET`` happens to name in ``.env``.
    """
    from .platform.programs import ProgramScopeError, ProgramScopeLoader

    try:
        return ProgramScopeLoader().load(handle)
    except ProgramScopeError as exc:
        colorlog.log.failed(f"program scope: {exc}")
        return None


def _cmd_list_programs() -> int:
    from .platform.programs import ProgramScopeError, list_programs

    try:
        rows = list_programs()
    except ProgramScopeError as exc:
        colorlog.log.failed(str(exc))
        return 2
    if not rows:
        print("no programs ingested — run the scraper's ingestion job first")
        return 0
    print(f"{'handle':<28} {'scopes':<8} {'domains':<8}")
    print("-" * 48)
    for row in rows:
        print(f"{row['handle']:<28} {row['scope_count']:<8} {row['domains']:<8}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    import logging

    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(name)s: %(message)s")

    if args.command in (None, "list"):
        return _cmd_list()

    if args.command == "run":
        if getattr(args, "domain", None) and not getattr(args, "program", None):
            parser.error("--domain belongs to --program (it selects one engagement of a program's scope)")
        return _cmd_run(args)
    if args.command == "history":
        return _cmd_history(args)
    if args.command == "dlq":
        return _cmd_dlq()
    if args.command == "replay":
        return _cmd_replay()
    parser.error(f"unknown command {args.command!r}")
    return 2


def _cmd_list() -> int:
    from .platform.registry import Registry

    registry = Registry.discover()
    rows = registry.describe()
    if not rows:
        colorlog.log.warn("no pipelines discovered under service/recon_pipeline/pipelines/")
        return 1
    print(f"{'name':<28} {'stages':<38} passive  asset types")
    print("-" * 110)
    for row in rows:
        print(
            f"{row['name']:<28} {row['stages']:<38} "
            f"{'yes' if row['passive_only'] else 'no':<7}  {row['asset_types']}"
        )
    return 0


def _cmd_run(args) -> int:
    if getattr(args, "list_programs", False):
        return _cmd_list_programs()

    if getattr(args, "program", None):
        if getattr(args, "scope_files", None) or getattr(args, "assets", None):
            colorlog.log.failed(
                "--program builds its scope from the database; "
                "use --scope-file/--asset instead"
            )
            return 2
        return _cmd_run_program(args)
    if getattr(args, "scope_files", None) or getattr(args, "assets", None):
        return _cmd_run_operator(args)
    if getattr(args, "domain", None):
        colorlog.log.failed("--domain belongs to --program (it selects one engagement of a program's scope)")
        return 2

    from .platform.runner import Runner

    target = args.target or _default_target()
    if not target:
        colorlog.log.failed("no target: pass -t or set TARGET in .env")
        return 2

    options = dict(option.split("=", 1) for option in args.options if "=" in option)
    runner = Runner(output_root=args.output_root)
    result = runner.run(
        target,
        pipelines=args.pipelines,
        stages=args.stages,
        options=options,
        convergence=_stop_policy(args) if args.converge else None,
    )

    _print_run_summary(result)
    return 0 if result.ok else 1


def _cmd_run_operator(args) -> int:
    """Engage operator-authored scope: ``-t`` + ``--scope-file`` + ``--asset``.

    Three spellings of one declared scope, classified by the same rules the
    program path obeys; the engagement resolution is fail-fast (an ambiguous
    file must be named with ``-t`` or ``--domain``-by-declaration, never
    resolved by accident).
    """
    from .platform.programs import (
        ProgramScopeError,
        engagement_domain_conflicts,
        operator_engagements,
        resolve_operator_scope,
    )
    from .platform.runner import Runner

    if args.domain:
        colorlog.log.failed("--domain belongs to --program (it selects one engagement of a program's scope)")
        return 2

    try:
        scope, refused = resolve_operator_scope(
            scope_files=args.scope_files, assets=args.assets, target=args.target
        )
        engagements = operator_engagements(scope, target=args.target)
    except ProgramScopeError as exc:
        colorlog.log.failed(f"operator scope: {exc}")
        return 2

    if refused:
        colorlog.log.warn(f"{len(refused)} scope line(s) refused: {'; '.join(refused)}")
    if scope.unsupported:
        colorlog.log.warn(
            f"{len(scope.unsupported)} declared asset(s) are not recon-actable "
            "and are recorded as unsupported in the run's summary"
        )

    apex, engagement = engagements[0]
    conflicts = engagement_domain_conflicts(engagement, apex)
    if conflicts:
        colorlog.log.warn(
            f"{len(conflicts)} declared domain(s) outside {apex} remain declared "
            f"in this engagement: {', '.join(conflicts)}"
        )

    colorlog.log.info(
        f"operator scope: {len(engagement.apexes)} domain(s), "
        f"{len(engagement.networks)} network(s), {len(engagement.addresses)} address(es)"
    )
    options = dict(option.split("=", 1) for option in args.options if "=" in option)
    runner = Runner(output_root=args.output_root)
    result = runner.run(
        apex,
        pipelines=args.pipelines,
        stages=args.stages,
        options=options,
        convergence=_stop_policy(args) if args.converge else None,
        program_scope=engagement,
    )
    _print_run_summary(result)
    return 0 if result.ok else 1


def _cmd_run_program(args) -> int:
    """Engage an ingested program: one run per declared domain, its scope applied.
    """
    from .platform.programs import choose_apexes, scope_for_apex
    from .platform.runner import Runner

    if args.target:
        colorlog.log.failed(
            "--program picks its own targets from the declared scope; "
            "use --domain to limit one engagement"
        )
        return 2

    scope = _load_program_scope(args.program)
    if scope is None:
        return 2
    try:
        apexes = choose_apexes(scope, args.domain)
    except Exception as exc:  # ProgramScopeError — fail fast, nothing runs
        colorlog.log.failed(f"program scope: {exc}")
        return 2

    colorlog.log.info(
        f"program {scope.handle}: {len(apexes)} engagement(s) — {', '.join(apexes)}"
    )
    if scope.unsupported:
        colorlog.log.warn(
            f"{len(scope.unsupported)} declared asset(s) are not recon-actable "
            "and are recorded as unsupported in each run's summary"
        )

    options = dict(option.split("=", 1) for option in args.options if "=" in option)
    stop_policy = _stop_policy(args) if args.converge else None
    worst = 0
    for apex in apexes:
        colorlog.log.info(f"— engagement: {apex} —")
        runner = Runner(output_root=args.output_root)
        result = runner.run(
            apex,
            pipelines=args.pipelines,
            stages=args.stages,
            options=options,
            convergence=stop_policy,
            program_scope=scope_for_apex(scope, apex),
        )
        _print_run_summary(result)
        worst = max(worst, 0 if result.ok else 1)
    return worst


def _print_run_summary(result) -> None:
    print(json.dumps(result.summary, indent=2, sort_keys=True))
    if result.convergence:
        verdict = result.convergence.get("verdict") or {}
        message = (
            f"converged after {result.convergence.get('rounds_run')} round(s): "
            f"{verdict.get('reason')} — {verdict.get('detail')}"
        )
        if result.convergence.get("exhausted"):
            colorlog.log.success(message)
        else:
            colorlog.log.warn(message)


def _stop_policy(args):
    """Build the loop's limits from the CLI, keeping the conservative defaults."""
    from .platform.convergence import StopPolicy

    policy = StopPolicy()
    if args.max_rounds is not None:
        policy.max_rounds = max(1, args.max_rounds)
    if args.time_budget is not None:
        policy.time_budget_seconds = max(0.0, args.time_budget)
    if args.max_active_actions is not None:
        policy.max_active_actions = max(0, args.max_active_actions)
    return policy


def _cmd_history(args) -> int:
    from .platform.observability import RunRegistry

    registry = RunRegistry(_runs_root())
    rows = registry.history(limit=args.limit)
    if args.target:
        rows = [row for row in rows if row.get("target") == args.target]
    if not rows:
        print("no runs recorded yet")
        return 0
    for row in rows:
        ok = "ok " if row.get("ok") else "FAIL"
        stages = row.get("stages") or []
        print(
            f"{row.get('finished_at', '?'):<21} {ok} {row.get('target', '?'):<20} "
            f"{len(stages)} stage(s) in {row.get('seconds', 0):.1f}s"
        )
    return 0


def _cmd_dlq() -> int:
    from .platform.observability import dlq_summary

    try:
        import redis

        url = __import__("os").getenv("REDIS_URL", "redis://localhost:6379/0")
        from urllib.parse import urlsplit

        parts = urlsplit(url)
        client = redis.Redis(
            host=parts.hostname or "localhost",
            port=parts.port or 6379,
            db=int((parts.path or "/0").lstrip("/")) or 0,
            socket_connect_timeout=2,
        )
        client.ping()
    except Exception:
        client = None
    rows = dlq_summary(client)
    if not rows:
        print("DLQ is empty")
        return 0
    for row in rows:
        print(json.dumps(row))
    return 0


def _cmd_replay() -> int:
    from .platform.graph.ingest import GraphSink

    sink = GraphSink(journal_path=_runs_root() / "graph_journal.jsonl")
    pending = sink.replay_journal()
    colorlog.log.failed(
        f"no graph schema is defined yet — {pending} write(s) replayed; "
        f"the journal at {sink.journal_path} is preserved for the migration"
    )
    return 1


def _runs_root() -> Path:
    """The runs/ directory: an existing one if present, else the default.

    Must match :attr:`platform.runner.Runner`'s choice, or ``history`` reads a
    different timeline than ``run`` writes.
    """
    for candidate in (Path.cwd() / "output" / "runs", Path.cwd() / "runs"):
        if candidate.is_dir():
            return candidate
    return Path.cwd() / "output" / "runs"


if __name__ == "__main__":
    sys.exit(main())
