"""``url_endpoint`` — the pipeline orchestrator.

Runs the pipeline's stages in order and reduces them to the artifacts a consumer
actually wants::

    passive   archived/historical harvest (Wayback, Common Crawl, urlscan, gau)
              -> canonical, in-scope, deduplicated URLs
    extract   URLs -> endpoints, parameters, JS bundles, source maps, findings

Each stage is independently runnable and owns its own ``output/`` directory; this
module adds only what belongs to the *whole* pipeline:

* **ordering** — extract consumes the passive union;
* **the derived asset artifacts** — ``endpoints.txt``, ``parameters.txt``,
  ``javascript.txt``, ``source_maps.txt``, ``interesting.txt``, ``hosts.txt`` and
  ``urls.jsonl``, each one sorted and deterministic;
* **a combined report** — ``output/summary.json`` with per-stage status, counts
  and timings, so a partial run is legible without reading two reports.

Design notes (identical to the sibling names pipeline, deliberately):

* **One stage failing does not stop the pipeline.**  A failed stage is recorded
  and skipped; the remaining stages still run.
* **Stages are selected by name.**  ``--stages extract`` re-derives assets from an
  existing passive union, which is the common case while iterating on extraction.
* **No stage is re-implemented here.**  Flags are forwarded to the stage that owns
  them, so behaviour is identical to running that stage directly.
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import shared.colorlog as colorlog

from service.recon_pipeline.platform.common.config import TARGET
from service.recon_pipeline.platform.common.io import write_jsonl, write_lines
from service.recon_pipeline.platform.common.normalize import canonicalize_host
from .extract import extract
from .passive import pipeline as passive_mod
from .passive.pipeline import URLS_FILE, run_passive_stage
from .settings import DEFAULT_SOURCE_TIMEOUT, OUTPUT_DIR, PASSIVE_OUTPUT_DIR

log = logging.getLogger("url_endpoint.main")

#: The whole-pipeline artifacts (per-stage artifacts live in each stage's output/).
ENDPOINTS_FILE = "endpoints.txt"
PARAMETERS_FILE = "parameters.txt"
JAVASCRIPT_FILE = "javascript.txt"
SOURCE_MAPS_FILE = "source_maps.txt"
INTERESTING_FILE = "interesting.txt"
HOSTS_FILE = "hosts.txt"
URLS_JSONL_FILE = "urls.jsonl"
REPORT_FILE = "report.json"
SUMMARY_FILE = "summary.json"

ALL_STAGES: tuple[str, ...] = ("passive", "extract")


@dataclass
class UrlPipelineSummary:
    """Combined report for one orchestrator run."""

    target: str
    started_at: str
    stages_run: list[str] = field(default_factory=list)
    finished_at: str = ""
    seconds: float = 0.0
    ok: bool = True
    stages: list[dict[str, object]] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    outputs: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(self.__dict__, indent=2, sort_keys=False)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _write_json(path: Path, payload: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=False), encoding="utf-8", newline="\n")
    tmp.replace(path)
    return path


def _read_union(path: Path | str) -> list[str]:
    """Read the passive stage's URL union, tolerating a missing file."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return [line.strip() for line in text.splitlines() if line.strip()]


def run_extract_stage(
    urls: Iterable[str],
    apex: str,
    *,
    output_dir: Path | str = OUTPUT_DIR,
) -> dict[str, object]:
    """Derive every asset class from *urls* and write the derived artifacts.

    Returns the stage's count block.  Split out from :func:`run_pipeline` so it is
    testable without a passive run, and so ``--stages extract`` is a first-class
    path rather than a special case.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    result = extract(list(urls), apex)

    write_lines(output_dir / ENDPOINTS_FILE, result.endpoints)
    write_lines(output_dir / PARAMETERS_FILE, result.parameters)
    write_lines(output_dir / JAVASCRIPT_FILE, result.javascript)
    write_lines(output_dir / SOURCE_MAPS_FILE, result.source_maps)
    write_lines(output_dir / INTERESTING_FILE, result.interesting)
    write_lines(output_dir / HOSTS_FILE, result.hosts)
    write_jsonl(output_dir / URLS_JSONL_FILE, _parsed_records(result))
    _write_json(output_dir / REPORT_FILE, result.to_dict())

    return dict(result.counts)


def _parsed_records(result: object) -> list[dict[str, object]]:
    """Per-URL JSON records for ``urls.jsonl``, in canonical (sorted) order."""
    from .normalize import parse_url

    records: list[dict[str, object]] = []
    for url in result.urls:  # type: ignore[attr-defined]
        parsed = parse_url(url)
        if parsed is not None:
            records.append(parsed.to_dict())
    return records


def run_pipeline(
    target: str = TARGET,
    *,
    stages: Sequence[str] = ALL_STAGES,
    output_dir: Path | str = OUTPUT_DIR,
    passive_output_dir: Path | str = PASSIVE_OUTPUT_DIR,
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
    **stage_options: Any,
) -> UrlPipelineSummary:
    """Run the requested *stages* in order and write the combined artifacts.

    Parameters
    ----------
    stages:
        Any of :data:`ALL_STAGES`; run in the order given.
    output_dir:
        Where the derived assets and ``summary.json`` are written.
    passive_output_dir:
        Where the passive stage writes (and ``uris.txt`` is read from).
    timeout:
        Forwarded to the passive stage's per-source budget.
    stage_options:
        Extra keyword arguments forwarded verbatim to the passive stage (used by
        tests to inject a fake source runner).

    Returns
    -------
    UrlPipelineSummary
        Per-stage status plus the derived counts.  Also written to
        ``output/summary.json``.
    """
    unknown = [name for name in stages if name not in ALL_STAGES]
    if unknown:
        raise ValueError(
            f"unknown stage(s) {', '.join(unknown)}; known: {', '.join(ALL_STAGES)}"
        )

    apex = canonicalize_host(target)
    if apex is None:
        raise ValueError(
            f"target {target!r} is not a valid domain (expected e.g. 'example.com')"
        )

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    started = time.monotonic()
    summary = UrlPipelineSummary(target=apex, started_at=_utc_now(), stages_run=list(stages))

    union_path = Path(passive_output_dir) / URLS_FILE

    for stage in stages:
        log.info("=== %s stage ===", stage)
        stage_started = time.monotonic()
        try:
            if stage == "passive":
                report = run_passive_stage(
                    apex,
                    timeout=timeout,
                    output_dir=passive_output_dir,
                    **stage_options,
                )
                entry: dict[str, object] = {
                    "stage": stage,
                    "ok": bool(report.ok),
                    "seconds": round(report.seconds, 2),
                    "counts": dict(report.counts),
                    "outputs": dict(report.outputs),
                }
                if report.truncated:
                    entry["truncated"] = True
                union_path = Path(report.outputs.get(URLS_FILE, union_path))
                if not report.ok:
                    summary.ok = False
            else:
                counts = run_extract_stage(_read_union(union_path), apex, output_dir=output_dir)
                entry = {
                    "stage": stage,
                    "ok": True,
                    "seconds": round(time.monotonic() - stage_started, 2),
                    "counts": counts,
                    "outputs": {
                        name: (output_dir / name).as_posix()
                        for name in (
                            ENDPOINTS_FILE,
                            PARAMETERS_FILE,
                            JAVASCRIPT_FILE,
                            SOURCE_MAPS_FILE,
                            INTERESTING_FILE,
                            HOSTS_FILE,
                            URLS_JSONL_FILE,
                            REPORT_FILE,
                        )
                    },
                }
        except Exception as exc:  # one stage must not take the pipeline down
            log.error("%s stage failed: %s: %s", stage, type(exc).__name__, exc)
            summary.ok = False
            summary.stages.append(
                {
                    "stage": stage,
                    "ok": False,
                    "seconds": round(time.monotonic() - stage_started, 2),
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            continue

        summary.stages.append(entry)

    # Combined counts: the union size plus whichever stage produced assets.
    # Values are read defensively because ``counts`` is only populated on a stage
    # that ran to completion; a failed stage contributes nothing rather than
    # poisoning the totals with a placeholder.
    derived: dict[str, int] = {}
    for stage_entry in summary.stages:
        stage_counts = stage_entry.get("counts")
        if isinstance(stage_counts, dict):
            for key, value in stage_counts.items():
                if isinstance(value, int) and not isinstance(value, bool):
                    derived[str(key)] = value
    summary.counts = derived

    summary.outputs = {
        "url_union": union_path.as_posix(),
        "summary": (output_dir / SUMMARY_FILE).as_posix(),
    }
    summary.finished_at = _utc_now()
    summary.seconds = time.monotonic() - started
    _write_json(output_dir / SUMMARY_FILE, summary.__dict__)

    _log_summary(summary)
    return summary


def _log_summary(summary: UrlPipelineSummary) -> None:
    colorlog.log.info(
        f"{len(summary.stages)} stage(s) for {summary.target} in {summary.seconds:.1f}s -> "
        f"{summary.counts.get('urls', 0)} URL(s), "
        f"{summary.counts.get('endpoints', 0)} endpoint(s), "
        f"{summary.counts.get('parameters', 0)} parameter(s), "
        f"{summary.counts.get('javascript', 0)} JS bundle(s), "
        f"{summary.counts.get('interesting', 0)} interesting file(s)"
    )
    for entry in summary.stages:
        status = "ok" if entry["ok"] else "FAILED"
        detail = entry.get("error") or ""
        colorlog.log.info(
            f"  {entry['stage']:<10} {status:<7} {entry['seconds']:>7.1f}s  {detail}"
        )
    if summary.ok:
        colorlog.log.success("all requested stages completed")
    else:
        colorlog.log.warn(
            "some stages did not complete cleanly - see the per-stage reports and "
            f"{summary.outputs['summary']}"
        )


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m service.recon_pipeline.pipelines.url_endpoint.main",
        description=(
            "Harvest historical URLs and derive endpoints, parameters, JS bundles "
            "and interesting files."
        ),
    )
    parser.add_argument("-t", "--target", default=TARGET, help=f"apex domain (default: {TARGET})")
    parser.add_argument(
        "--stages",
        default=",".join(ALL_STAGES),
        help=f"comma-separated stages to run (default: {','.join(ALL_STAGES)})",
    )
    parser.add_argument("--only", default=None, help="comma-separated passive sources to run")
    parser.add_argument("--skip", default="", help="comma-separated passive sources to skip")
    parser.add_argument("--max-urls", type=int, default=0, help="cap on the URL union (0 = no cap)")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_SOURCE_TIMEOUT,
        help=f"per-source timeout in seconds (default: {DEFAULT_SOURCE_TIMEOUT})",
    )
    parser.add_argument("--output-dir", default=str(OUTPUT_DIR), help="derived-artifact directory")
    parser.add_argument(
        "--passive-output-dir",
        default=str(PASSIVE_OUTPUT_DIR),
        help="passive-stage output directory",
    )
    parser.add_argument("--list", action="store_true", help="list the stages and exit")
    parser.add_argument("-v", "--verbose", action="store_true", help="show debug logging")
    return parser


def _split(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.  Returns a process exit code."""
    args = _build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-7s %(name)s: %(message)s",
    )

    if args.list:
        print("stages, in run order:")
        print("  passive  Wayback / Common Crawl / urlscan / gau -> canonical URLs")
        print("  extract  URLs -> endpoints, parameters, JS, source maps, findings")
        return 0

    try:
        summary = run_pipeline(
            args.target,
            stages=_split(args.stages),
            output_dir=args.output_dir,
            passive_output_dir=args.passive_output_dir,
            timeout=args.timeout,
            only=_split(args.only) if args.only else None,
            skip=_split(args.skip),
            cap=args.max_urls,
        )
    except (ValueError, KeyError) as exc:
        colorlog.log.failed(str(exc))
        return 2

    return 0 if summary.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
