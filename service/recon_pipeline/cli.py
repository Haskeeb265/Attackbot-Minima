"""``python -m service.recon_pipeline`` — the canonical operator CLI.

Subcommands:

- ``list``                 — every discovered pipeline (name, asset types, stages)
- ``run``                  — run pipelines against a target (the default action)
- ``history``              — the run registry (last N runs)
- ``dlq``                  — inspect the dead-letter queue
- ``replay``               — replay a graph journal into Neo4j

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
    run.add_argument("-t", "--target", help="apex domain (default: TARGET from .env)")
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

    history = sub.add_parser("history", help="show recent runs")
    history.add_argument("-n", "--limit", type=int, default=10)
    history.add_argument("-t", "--target", default=None, help="filter to one target")

    sub.add_parser("dlq", help="inspect the dead-letter queue")
    sub.add_parser("replay", help="replay the graph journal into Neo4j")
    return parser


def _default_target() -> str | None:
    try:
        from .platform.common.config import TARGET

        return TARGET
    except Exception:
        return None


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    import logging

    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(name)s: %(message)s")

    if args.command in (None, "list"):
        return _cmd_list()

    if args.command == "run":
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
    )

    print(json.dumps(result.summary, indent=2, sort_keys=True))
    return 0 if result.ok else 1


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
    from .platform.graph.ingest import GraphSink, connect_repository

    repository = connect_repository()
    sink = GraphSink(repository=repository, journal_path=_runs_root() / "graph_journal.jsonl")
    if not sink.available:
        colorlog.log.failed(f"graph unavailable: {sink.health.reason}")
        return 1
    replayed = sink.replay_journal()
    colorlog.log.success(f"replayed {replayed} journaled write(s) into Neo4j")
    return 0


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
