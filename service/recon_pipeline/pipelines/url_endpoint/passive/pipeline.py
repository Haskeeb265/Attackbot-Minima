"""End-to-end runner for the passive URL harvest stage.

This is the module that actually *produces* the stage's output.  The individual
sources are libraries; nothing downstream should have to know which of them ran,
where they wrote, or how their disagreements were reconciled.  This runner owns
that contract::

    run sources -> read only the sources that succeeded -> canonicalize + scope
                -> union -> write output/urls.txt + report.json

Output contract (everything lands in ``passive/output/``)
---------------------------------------------------------
=========================== ===================================================
``<source>.urls.txt``       raw per-source URLs (as the source emitted them)
``<source>.log``            per-tool stderr (Docker sources only)
``urls.txt``                canonical, in-scope, deduplicated union — **the
                            artifact the extract stage consumes**
``foreign.txt``             out-of-scope URLs found in a source's output
``report.json``             machine-readable run report (counts, timings,
                            per-source status, foreign/invalid accounting)
=========================== ===================================================

Two safety properties worth stating explicitly, both inherited from the sibling
names stage because they are properties of *any* multi-source merge:

* **Only sources that succeeded in this run are merged.**  A raw file left behind
  by a previous run can therefore never contaminate the output — the same class of
  bug the top-level ``run_recon.py`` guards against with its mtime snapshot.
* **Foreign and invalid input is counted, never silently dropped.**  A URL whose
  host is outside the apex is written to ``foreign.txt`` (public archives
  legitimately contain unrelated hosts, so this is normal rather than alarming);
  a token that is not a URL at all is counted in ``invalid``.  Either number being
  large is a diagnosable signal, not a hidden loss.
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import shared.colorlog as colorlog

from service.recon_pipeline.platform.common.config import TARGET
from service.recon_pipeline.platform.common.normalize import canonicalize_host, is_subdomain_of
from ..normalize import parse_url
from ..settings import (
    DEFAULT_SOURCE_TIMEOUT,
    MAX_URLS,
    PASSIVE_OUTPUT_DIR,
)
from . import sources as registry

log = logging.getLogger("url.passive.pipeline")

URLS_FILE = "urls.txt"
FOREIGN_FILE = "foreign.txt"
REPORT_FILE = "report.json"

#: Injected by tests: ``(name, apex, output_dir, timeout) -> SourceResult``.
SourceRunner = Callable[..., "registry.SourceResult"]


# --------------------------------------------------------------------------- #
# Scanning one source's raw output
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ScanResult:
    """What one raw source file contributed, and what it cost."""

    urls: list[str]
    foreign: list[str]
    invalid: int
    #: URLs that parsed but are debris (template placeholders, shell fragments).
    #: Counted separately from ``invalid`` because the cause and the fix differ:
    #: invalid means "not a URL", junk means "a URL-shaped string that is not an
    #: address" — see :func:`..normalize._is_junk`.
    junk: int = 0


def scan_url_file(path: Path | str, apex: str) -> ScanResult:
    """Canonicalize one raw source file, separating foreign and invalid input.

    A missing file is "the source produced nothing" (empty result), not an error:
    several sources legitimately return nothing for a target, and a skipped
    source has no file at all.
    """
    path = Path(path)
    apex = apex.lower().rstrip(".")
    if not path.is_file():
        return ScanResult(urls=[], foreign=[], invalid=0, junk=0)

    urls: set[str] = set()
    foreign: set[str] = set()
    invalid = 0
    junk = 0

    text = path.read_text(encoding="utf-8", errors="replace")
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parsed = parse_url(line)
        if parsed is None:
            invalid += 1
            continue
        if parsed.junk:
            junk += 1
            continue
        if parsed.host == apex or is_subdomain_of(parsed.host, apex):
            urls.add(parsed.url)
        else:
            foreign.add(parsed.url)

    return ScanResult(urls=sorted(urls), foreign=sorted(foreign), invalid=invalid, junk=junk)


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #


@dataclass
class UrlPassiveReport:
    """Machine-readable summary of one passive URL run."""

    target: str
    started_at: str
    finished_at: str = ""
    seconds: float = 0.0
    ok: bool = True
    sources: list[dict[str, object]] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    foreign: dict[str, list[str]] = field(default_factory=dict)
    truncated: bool = False
    outputs: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(self.__dict__, indent=2, sort_keys=False)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _write_report(path: Path, report: UrlPassiveReport) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(report.to_json(), encoding="utf-8", newline="\n")
    tmp.replace(path)
    return path


# --------------------------------------------------------------------------- #
# Stage
# --------------------------------------------------------------------------- #


def run_passive_stage(
    target: str = TARGET,
    *,
    only: Iterable[str] | None = None,
    skip: Iterable[str] = (),
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
    output_dir: Path | str = PASSIVE_OUTPUT_DIR,
    runner: SourceRunner | None = None,
    cap: int = MAX_URLS,
) -> UrlPassiveReport:
    """Run every selected passive URL source and write the stage's outputs.

    Parameters
    ----------
    target:
        Apex domain to harvest.
    only / skip:
        Source-name selectors (see :data:`..sources.ALL_SOURCES`).
    timeout:
        Per-source wall-clock budget in seconds.
    output_dir:
        Where raw and derived files are written.
    runner:
        Injected source runner for tests; production uses the registry.
    cap:
        Ceiling on the URL union after dedup (``0`` = no cap).  When it bites, the
        report records ``truncated`` rather than pretending the union was whole.

    Raises
    ------
    ValueError
        If *target* is not a plausible registrable domain.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    apex = canonicalize_host(target)
    if apex is None:
        raise ValueError(
            f"target {target!r} is not a valid domain (expected e.g. 'example.com')"
        )

    started = time.monotonic()
    report = UrlPassiveReport(target=apex, started_at=_utc_now())

    # 1. Run the selected sources.
    names = registry.select_sources(only=only, skip=skip)
    if runner is None:
        results = registry.run_all(apex, only=names, skip=(), output_dir=output_dir, timeout=timeout)
    else:
        results = [runner(name, apex, output_dir, timeout) for name in names]

    ran = [result for result in results if result.ok]
    if not ran:
        log.error("every passive URL source failed for %s - nothing to merge", apex)
        report.ok = False

    # 2. Merge, but only from sources that succeeded in this run.
    merged: set[str] = set()
    foreign: dict[str, list[str]] = {}
    invalid_total = 0
    junk_total = 0
    for result in ran:
        scanned = scan_url_file(result.output_path, apex)
        merged.update(scanned.urls)
        invalid_total += scanned.invalid
        junk_total += scanned.junk
        if scanned.foreign:
            foreign[Path(result.output_path).name] = scanned.foreign
        result.urls = len(scanned.urls)

    report.sources = [result.to_dict() for result in results]

    # 3. Deterministic union, with the cap applied to a sorted list so a capped
    #    run is reproducible rather than dependent on source ordering.
    ordered = sorted(merged)
    truncated = bool(cap) and len(ordered) > cap
    if truncated:
        log.warning(
            "URL union for %s has %d URLs, above the %d cap - keeping the first %d "
            "(raise URL_MAX_URLS to keep more)",
            apex,
            len(ordered),
            cap,
            cap,
        )
        ordered = ordered[:cap]
    report.truncated = truncated

    # 4. Write the derived outputs.
    urls_path = output_dir / URLS_FILE
    tmp = urls_path.with_name(urls_path.name + ".tmp")
    tmp.write_text("".join(f"{url}\n" for url in ordered), encoding="utf-8", newline="\n")
    tmp.replace(urls_path)
    report.outputs[URLS_FILE] = urls_path.as_posix()

    if foreign:
        flat = sorted({url for urls in foreign.values() for url in urls})
        foreign_path = output_dir / FOREIGN_FILE
        tmp = foreign_path.with_name(foreign_path.name + ".tmp")
        tmp.write_text("".join(f"{url}\n" for url in flat), encoding="utf-8", newline="\n")
        tmp.replace(foreign_path)
        report.foreign = foreign
        report.outputs[FOREIGN_FILE] = foreign_path.as_posix()

    report.counts = {
        "sources_selected": len(results),
        "sources_succeeded": len(ran),
        "sources_failed": sum(1 for r in results if not r.ok and r.skipped is None),
        "sources_skipped": sum(1 for r in results if r.skipped is not None),
        "urls_raw": sum(int(r.urls) for r in results),
        "urls": len(ordered),
        "foreign": sum(len(urls) for urls in foreign.values()),
        "invalid": invalid_total,
        "junk": junk_total,
    }
    report.finished_at = _utc_now()
    report.seconds = time.monotonic() - started
    report.outputs[REPORT_FILE] = _write_report(output_dir / REPORT_FILE, report).as_posix()

    _log_summary(report)
    return report


def _log_summary(report: UrlPassiveReport) -> None:
    counts = report.counts
    colorlog.log.info(
        f"passive URL stage for {report.target}: {counts.get('urls', 0)} URL(s), "
        f"{counts.get('sources_succeeded', 0)}/{counts.get('sources_selected', 0)} "
        f"source(s) succeeded in {report.seconds:.1f}s"
    )
    if counts.get("sources_failed"):
        colorlog.log.warn(
            f"{counts['sources_failed']} source(s) failed - see "
            f"{report.outputs.get(REPORT_FILE, REPORT_FILE)} for details"
        )
    if counts.get("foreign"):
        colorlog.log.info(
            f"{counts['foreign']} out-of-scope URL(s) recorded in "
            f"{report.outputs.get(FOREIGN_FILE, FOREIGN_FILE)} (normal for public archives)"
        )
    if counts.get("invalid"):
        colorlog.log.info(f"{counts['invalid']} line(s) were not URLs at all")
    if counts.get("junk"):
        colorlog.log.info(
            f"{counts['junk']} URL-shaped line(s) were template/shell debris and "
            "were dropped"
        )
    if report.truncated:
        colorlog.log.warn("the URL union was truncated by URL_MAX_URLS - see report.json")
    if report.ok:
        colorlog.log.success(f"canonical URLs written to {report.outputs.get(URLS_FILE)}")
    else:
        colorlog.log.failed(
            f"passive URL stage for {report.target} did not complete cleanly - "
            f"see {report.outputs.get(REPORT_FILE, REPORT_FILE)}"
        )


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m service.recon_pipeline.pipelines.url_endpoint.passive.pipeline",
        description=(
            "Harvest historical URLs from the keyless archives (plus gau), "
            "normalize and scope-filter them, and write passive/output/."
        ),
    )
    parser.add_argument("-t", "--target", default=TARGET, help=f"apex domain (default: {TARGET})")
    parser.add_argument("--only", default=None, help="comma-separated sources to run (default: all)")
    parser.add_argument("--skip", default="", help="comma-separated sources to skip")
    parser.add_argument(
        "--max-urls",
        type=int,
        default=MAX_URLS,
        help=f"cap on the URL union, 0 = no cap (default: {MAX_URLS})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_SOURCE_TIMEOUT,
        help=f"per-source timeout in seconds (default: {DEFAULT_SOURCE_TIMEOUT})",
    )
    parser.add_argument(
        "--output-dir", default=str(PASSIVE_OUTPUT_DIR), help="output directory"
    )
    parser.add_argument("--list", action="store_true", help="list available sources and exit")
    parser.add_argument("-v", "--verbose", action="store_true", help="show debug logging")
    return parser


def _split(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.  Returns a process exit code."""
    args = _build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-7s %(name)s: %(message)s",
    )

    if args.list:
        print(f"{'source':<14} {'flavour':<16} description")
        print("-" * 78)
        for row in registry.describe_sources():
            print(f"{row['name']:<14} {row['flavour']:<16} {row['description']}")
        return 0

    try:
        report = run_passive_stage(
            args.target,
            only=_split(args.only),
            skip=_split(args.skip) or (),
            timeout=args.timeout,
            output_dir=args.output_dir,
            cap=args.max_urls,
        )
    except (ValueError, KeyError) as exc:
        colorlog.log.failed(str(exc))
        return 2

    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
