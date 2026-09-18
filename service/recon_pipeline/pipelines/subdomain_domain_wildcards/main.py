"""
``subdomain_domain_wildcards`` — the stage orchestrator.

Runs the three stages of this asset pipeline in order and reduces them to one
answer::

    passive      OSINT / certificate transparency      -> known names
    active       DNS resolution + bruteforce + AXFR     -> live hosts
    permutation  names derived from the live hosts      -> live hosts, again

Each stage is independently runnable and owns its own ``output/`` directory; this
module adds only what belongs to the *whole* pipeline:

* **ordering** — active consumes the passive list, permutation consumes both;
* **the union artifact** — ``output/live_hosts.txt``, the deduplicated union of
  every live host the stages found, which is what a downstream consumer wants
  instead of three files;
* **a combined report** — ``output/summary.json`` with per-stage status, counts
  and timings, so a partial run is legible without reading three reports.

Design notes
------------
* **One stage failing does not stop the pipeline.**  A stage that fails is
  recorded and skipped; the remaining stages still run, because a partial union
  is still useful and re-running everything to recover one failed stage is
  wasteful.  The exit code reflects whether anything failed.
* **Stages are selected by name.**  ``--stages active,permutation`` skips the
  passive stage (useful when its output already exists and is current).
* **No stage is re-implemented here.**  Every flag is forwarded to the stage that
  owns it, so behaviour and output stay identical to running a stage directly.
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

import shared.colorlog as colorlog

from service.recon_pipeline.platform.common.config import TARGET

from .active import resolvers as resolver_mod
from .active.pipeline import RESOLVED_FILE as ACTIVE_RESOLVED_KEY
from .active.pipeline import run_active_stage
from .active.resolve import DEFAULT_ENGINE
from .active.settings import DEFAULT_SOURCE_TIMEOUT, PASSIVE_ONLY
from .passive.normalize import canonicalize_host
from .passive.pipeline import run_passive_stage
from .permutation.pipeline import RESOLVED_FILE as PERMUTATION_RESOLVED_KEY
from .permutation.pipeline import run_permutation_stage

log = logging.getLogger("subdomain_domain_wildcards.main")

STAGE_DIR = Path(__file__).resolve().parent

#: The whole-pipeline artifacts (per-stage artifacts live in each stage's output/).
OUTPUT_DIR = STAGE_DIR / "output"
LIVE_HOSTS_FILE = "live_hosts.txt"
SUMMARY_FILE = "summary.json"

#: Stage names, in run order.
ALL_STAGES: tuple[str, ...] = ("passive", "active", "permutation")


@dataclass
class PipelineSummary:
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


def _write_json(path: Path, summary: PipelineSummary) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(summary.to_json(), encoding="utf-8", newline="\n")
    tmp.replace(path)
    return path


def _read_hosts(path: Path | str | None, apex: str) -> set[str]:
    """Read a stage's resolved-host list, filtered to *apex*'s scope."""
    if not path:
        return set()
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    hosts: set[str] = set()
    for line in text.splitlines():
        host = canonicalize_host(line)
        if host and (host == apex or host.endswith("." + apex)):
            hosts.add(host)
    return hosts


def run_pipeline(
    target: str = TARGET,
    *,
    stages: Sequence[str] = ALL_STAGES,
    output_dir: Path | str = OUTPUT_DIR,
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
    engine: str = DEFAULT_ENGINE,
    wordlist_files: Iterable[Path | str] = (),
    bruteforce: bool = True,
    recursion: bool = True,
    axfr: bool = True,
    http: bool = False,
    resolvers: Iterable[str] | None = None,
    trusted_resolvers: Iterable[str] | None = None,
    max_candidates: int | None = None,
    **stage_options: object,
) -> PipelineSummary:
    """Run the requested *stages* in order and write the combined artifacts.

    Parameters
    ----------
    stages:
        Any of :data:`ALL_STAGES`; run in the order given.
    output_dir:
        Where ``live_hosts.txt`` and ``summary.json`` are written.
    bruteforce / recursion / axfr / http / wordlist_files / engine / resolvers:
        Forwarded to the stages that own them.
    stage_options:
        Extra keyword arguments forwarded verbatim to every stage that accepts
        them (used by tests to inject fakes).

    Returns
    -------
    PipelineSummary
        Per-stage status plus the union of live hosts.  Also written to
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
    summary = PipelineSummary(
        target=apex, started_at=_utc_now(), stages_run=list(stages)
    )

    live: set[str] = set()

    for stage in stages:
        log.info("=== %s stage ===", stage)
        # The passive stage is always allowed.  Active technique is refused when
        # the operator forces passive-only: the stages enforce this themselves
        # (they can also trip on a quarantine they discover mid-run), but saying
        # so here keeps the stage list honest instead of reporting a stage that
        # ran and instantly aborted.
        if stage != "passive" and PASSIVE_ONLY:
            log.warning("skipping %s stage: PASSIVE_ONLY is set", stage)
            summary.stages.append(
                {
                    "stage": stage,
                    "ok": True,
                    "skipped": "PASSIVE_ONLY",
                    "seconds": 0.0,
                    "counts": {},
                }
            )
            continue
        stage_started = time.monotonic()
        try:
            if stage == "passive":
                report = run_passive_stage(apex, timeout=timeout, **stage_options)
            elif stage == "active":
                report = run_active_stage(
                    apex,
                    engine=engine,
                    timeout=timeout,
                    bruteforce=bruteforce,
                    recursion=recursion,
                    axfr=axfr,
                    http=http,
                    wordlist_files=wordlist_files,
                    resolvers=resolvers,
                    trusted_resolvers=trusted_resolvers,
                    **stage_options,
                )
            else:
                report = run_permutation_stage(
                    apex,
                    engine=engine,
                    timeout=timeout,
                    resolvers=resolvers,
                    trusted_resolvers=trusted_resolvers,
                    **({"max_candidates": max_candidates} if max_candidates else {}),
                    **stage_options,
                )
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

        entry: dict[str, object] = {
            "stage": stage,
            "ok": bool(report.ok),
            "seconds": round(report.seconds, 2),
            "counts": dict(report.counts),
            "outputs": dict(report.outputs),
        }
        # A stage's stealth state belongs in the run summary: it is the record of
        # how we presented ourselves and what the target did about it.
        stealth = getattr(report, "stealth", None)
        if isinstance(stealth, dict) and stealth:
            entry["stealth"] = {
                "transport": (stealth.get("transport") or {}).get("name"),
                "passive_only": stealth.get("passive_only"),
                "verdicts": stealth.get("verdicts") or {},
                "blocked_hosts": stealth.get("blocked_hosts") or [],
                "dns_plan": stealth.get("dns_plan") or {},
            }
        if not report.ok:
            summary.ok = False
        if getattr(report, "fatal", None):
            entry["fatal"] = report.fatal
        summary.stages.append(entry)

        if stage in ("active", "permutation"):
            # Each stage keys its artifacts by filename, so the stage's own
            # RESOLVED_FILE constant is the lookup key.
            key = ACTIVE_RESOLVED_KEY if stage == "active" else PERMUTATION_RESOLVED_KEY
            resolved_path = report.outputs.get(key)
            found = _read_hosts(resolved_path, apex)
            expected = int((entry["counts"] or {}).get("resolved") or 0)
            if expected and not found:
                # A stage that resolved hosts but whose artifact we cannot read
                # would leave the union quietly incomplete -- say so loudly.
                log.warning(
                    "%s stage reported %d resolved host(s) but none were readable "
                    "from %s - the union artifact is incomplete",
                    stage,
                    expected,
                    resolved_path,
                )
            live |= found

    # The union artifact: what downstream consumers should read.
    live_path = output_dir / LIVE_HOSTS_FILE
    tmp = live_path.with_name(live_path.name + ".tmp")
    tmp.write_text(
        "".join(f"{host}\n" for host in sorted(live)), encoding="utf-8", newline="\n"
    )
    tmp.replace(live_path)

    summary.counts = {
        "live_hosts": len(live),
        **{
            f"{entry['stage']}_live": int(
                (entry.get("counts") or {}).get("subdomains")
                or (entry.get("counts") or {}).get("resolved")
                or 0
            )
            for entry in summary.stages
        },
    }
    summary.outputs = {
        "live_hosts": live_path.as_posix(),
        "summary": (output_dir / SUMMARY_FILE).as_posix(),
    }
    summary.finished_at = _utc_now()
    summary.seconds = time.monotonic() - started
    _write_json(output_dir / SUMMARY_FILE, summary)

    _log_summary(summary)
    return summary


def _log_summary(summary: PipelineSummary) -> None:
    colorlog.log.info(
        f"{len(summary.stages)} stage(s) for {summary.target} in "
        f"{summary.seconds:.1f}s -> {summary.counts.get('live_hosts', 0)} unique "
        f"live host(s) in {summary.outputs['live_hosts']}"
    )
    for entry in summary.stages:
        status = "ok" if entry["ok"] else "FAILED"
        detail = entry.get("error") or entry.get("fatal") or ""
        colorlog.log.info(
            f"  {entry['stage']:<12} {status:<7} {entry['seconds']:>7.1f}s  {detail}"
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
        prog="python -m "
        "service.recon_pipeline.pipelines.subdomain_domain_wildcards.main",
        description=(
            "Run the passive, active and permutation stages in order and write "
            "the union of live hosts to output/live_hosts.txt."
        ),
    )
    parser.add_argument(
        "-t", "--target", default=TARGET, help=f"apex domain (default: {TARGET})"
    )
    parser.add_argument(
        "--stages", default=",".join(ALL_STAGES),
        help=f"comma-separated stages to run (default: {','.join(ALL_STAGES)})",
    )
    parser.add_argument(
        "--engine", default=DEFAULT_ENGINE,
        help=f"resolution engine for the active/permutation stages (default: {DEFAULT_ENGINE})",
    )
    parser.add_argument(
        "--wordlist", action="append", default=[],
        help="extra wordlist for bruteforce (repeatable)",
    )
    parser.add_argument("--no-bruteforce", action="store_true", help="skip bruteforce")
    parser.add_argument("--no-recursion", action="store_true", help="skip recursion")
    parser.add_argument("--no-axfr", action="store_true", help="skip zone transfers")
    parser.add_argument(
        "--http", action="store_true",
        help="enable the HTTP probe (sends application traffic to the target)",
    )
    parser.add_argument(
        "--max-candidates", type=int, default=None,
        help="cap on generated permutation candidates",
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
        "--timeout", type=float, default=DEFAULT_SOURCE_TIMEOUT,
        help=f"per-tool timeout in seconds (default: {DEFAULT_SOURCE_TIMEOUT})",
    )
    parser.add_argument(
        "--output-dir", default=str(OUTPUT_DIR),
        help=f"output directory for the combined artifacts (default: {OUTPUT_DIR})",
    )
    parser.add_argument(
        "--list", action="store_true", help="list the stages and exit"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="show debug logging")
    return parser


def _read_resolver_args(paths: Iterable[str]) -> list[str] | None:
    paths = list(paths)
    if not paths:
        return None
    addresses: list[str] = []
    for path in paths:
        addresses += resolver_mod.load_resolvers_file(path)
    return addresses


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
        print("  passive      OSINT / certificate transparency -> known names")
        print("  active       DNS resolution, bruteforce, recursion, AXFR -> live hosts")
        print("  permutation  names derived from known hosts    -> more live hosts")
        return 0

    try:
        summary = run_pipeline(
            args.target,
            stages=_split(args.stages),
            output_dir=args.output_dir,
            timeout=args.timeout,
            engine=args.engine,
            wordlist_files=args.wordlist,
            bruteforce=not args.no_bruteforce,
            recursion=not args.no_recursion,
            axfr=not args.no_axfr,
            http=args.http,
            resolvers=_read_resolver_args(args.resolvers),
            trusted_resolvers=_read_resolver_args(args.trusted_resolvers),
            max_candidates=args.max_candidates,
        )
    except (ValueError, KeyError) as exc:
        colorlog.log.failed(str(exc))
        return 2

    return 0 if summary.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
