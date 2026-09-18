"""
End-to-end runner for the passive subdomain enumeration stage.

This is the module that actually *produces* the stage's output.  The individual
tool wrappers and the normalizer are libraries; nothing downstream should have
to know the order in which they must be called, which files to read, or how to
reconcile their disagreements.  This runner owns that contract:

    run sources -> normalize + merge (with provenance) -> detect wildcards
                -> suppress wildcard noise -> write output/ + report.json

Output contract (everything lands in ``passive/output/``)
--------------------------------------------------------
============================ ==================================================
``<source>.txt``             raw per-source output (as the tool printed it)
``<source>.log``             per-tool stderr (Docker sources)
``domains.txt``              the in-scope apex itself — the "domain" layer
``subdomains.txt``           normalized, deduplicated subdomains; **the artifact
                             the active/ and permutation/ stages consume**
``wildcards.txt``            confirmed wildcard records (``*.parent``)
``wildcard_suppressed.txt``  names dropped as wildcard noise (auditable)
``foreign.txt``              out-of-scope hosts found in a source's output
``report.json``              machine-readable run report (counts, timings,
                             per-source status, wildcards, suppression)
============================ ==================================================

Two safety properties worth stating explicitly:

* **Only sources that succeeded in this run are merged.**  A stale file left by
  a previous run can therefore never contaminate the output.
* **Foreign-domain leakage is always reported, and aborts only when it is
  systemic.**  Out-of-scope hosts never reach ``subdomains.txt``; they are
  written to ``foreign.txt`` and logged.  The stage aborts when they make up the
  majority of what the sources returned — the signature of a stale ``TARGET``
  enumerating an entirely different domain.  Isolated strays (a lookalike such
  as ``one-tesla.com``, a third-party name a tool matched loosely) are recorded
  without discarding the whole run.  See *foreign policy* below.

Selecting the foreign policy
----------------------------
============= ==================================================
``threshold`` default: abort only if out-of-scope hosts are >= 50% of all hosts
``strict``    abort on a single out-of-scope host (CI / paranoia)
``lenient``   never abort; just record and warn
============= ==================================================
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import shared.colorlog as colorlog

from service.recon_pipeline.platform.common.config import TARGET

from . import sources as registry
from .normalize import (
    ForeignDomainError,
    canonicalize_host,
    find_foreign,
    merge_observations,
    normalize_amass_relations,
    relation_subdomains,
    scan_subdomain_file,
    write_host_list,
)
from .settings import DEFAULT_SOURCE_TIMEOUT, OUTPUT_DIR, WILDCARD_ENABLED
from .wildcard import Resolver, detect_wildcards, filter_wildcard_noise

#: Stable logger name — ``__name__`` would become ``__main__`` under ``-m``.
log = logging.getLogger("passive.pipeline")

# Derived output file names (see the module docstring's output contract).
DOMAINS_FILE = "domains.txt"
SUBDOMAINS_FILE = "subdomains.txt"
WILDCARDS_FILE = "wildcards.txt"
SUPPRESSED_FILE = "wildcard_suppressed.txt"
FOREIGN_FILE = "foreign.txt"
REPORT_FILE = "report.json"

# Foreign-domain policies (see the module docstring).
FOREIGN_POLICY_THRESHOLD = "threshold"
FOREIGN_POLICY_STRICT = "strict"
FOREIGN_POLICY_LENIENT = "lenient"

#: Under the default policy, out-of-scope hosts abort the run once they account
#: for at least this share of every host the sources returned.  A stale TARGET
#: pushes this towards 1.0; a single lookalike pushes it towards 0.0.
FOREIGN_ABORT_SHARE = 0.5


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #


@dataclass
class PassiveReport:
    """Machine-readable summary of one passive stage run."""

    target: str
    started_at: str
    finished_at: str = ""
    seconds: float = 0.0
    ok: bool = True
    wildcard_probe: bool = True
    sources: list[dict[str, object]] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    domains: list[str] = field(default_factory=list)
    wildcards: list[str] = field(default_factory=list)
    suppressed: dict[str, str] = field(default_factory=dict)
    foreign: dict[str, list[str]] = field(default_factory=dict)
    amass_relations: int = 0
    #: True when out-of-scope hosts were severe enough to abort the stage.
    foreign_abort: bool = False
    outputs: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(self.__dict__, indent=2, sort_keys=False)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# Stage
# --------------------------------------------------------------------------- #


def run_passive_stage(
    target: str = TARGET,
    *,
    only: Iterable[str] | None = None,
    skip: Iterable[str] = (),
    wildcards: bool = WILDCARD_ENABLED,
    foreign_policy: str = FOREIGN_POLICY_THRESHOLD,
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
    output_dir: Path | str = OUTPUT_DIR,
    resolver: Resolver | None = None,
) -> PassiveReport:
    """Run the full passive stage for *target* and write its outputs.

    Parameters
    ----------
    target:
        Apex domain to enumerate.
    only / skip:
        Source-name selectors (see :data:`..sources.ALL_SOURCES`).
    wildcards:
        Run DNS wildcard detection and suppress wildcard-explained noise.
    foreign_policy:
        One of :data:`FOREIGN_POLICY_THRESHOLD` (default),
        :data:`FOREIGN_POLICY_STRICT`, :data:`FOREIGN_POLICY_LENIENT` — see the
        module docstring.
    timeout:
        Per-source wall-clock budget in seconds.
    output_dir:
        Where raw and derived files are written.
    resolver:
        Injected DNS resolver for tests; production uses dnspython.

    Raises
    ------
    ValueError
        If *target* is not a plausible registrable domain, or *foreign_policy*
        is not one of the supported values.
    ForeignDomainError
        If the selected *foreign_policy* says the leakage is disqualifying.
    """
    if foreign_policy not in (
        FOREIGN_POLICY_THRESHOLD,
        FOREIGN_POLICY_STRICT,
        FOREIGN_POLICY_LENIENT,
    ):
        raise ValueError(
            f"unknown foreign_policy {foreign_policy!r}; expected one of "
            f"{FOREIGN_POLICY_THRESHOLD!r}, {FOREIGN_POLICY_STRICT!r}, "
            f"{FOREIGN_POLICY_LENIENT!r}"
        )
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    apex = canonicalize_host(target)
    if apex is None:
        raise ValueError(
            f"target {target!r} is not a valid domain (expected e.g. 'example.com')"
        )

    started = time.monotonic()
    report = PassiveReport(
        target=apex, started_at=_utc_now(), wildcard_probe=wildcards
    )

    # 1. Run the sources.  Individual failures are tolerated.
    results = registry.run_all(
        apex, only=only, skip=skip, output_dir=output_dir, timeout=timeout
    )
    report.sources = [result.to_dict() for result in results]

    ran = [result for result in results if result.ok]
    if not ran:
        log.error("every passive source failed for %s - nothing to merge", apex)
        report.ok = False

    # 2. Normalize + merge, but only from sources that succeeded in this run so
    #    a leftover file from an earlier run cannot contaminate the output.
    list_sources = [
        result.name
        for result in ran
        if result.name in registry.SUBDOMAIN_SOURCES
    ]
    observations = merge_observations(
        apex, output_dir, sources=list_sources, reject_foreign=False
    )

    # 3. amass contributes names through its relation stream, not as a list.
    amass_result = next((r for r in results if r.name == "amass"), None)
    amass_hosts: set[str] = set()
    if amass_result is not None and amass_result.ok:
        relations = normalize_amass_relations(amass_result.output_path)
        report.amass_relations = len(relations)
        amass_hosts = relation_subdomains(relations, apex)
        for host in amass_hosts:
            observations.setdefault(host, set()).add("amass")

    # Per-source contribution counts for the report.
    for result in ran:
        if result.name == "amass":
            result.hosts = len(amass_hosts)
        else:
            result.hosts = len(
                scan_subdomain_file(output_dir / f"{result.name}.txt", apex).hosts
            )
    report.sources = [result.to_dict() for result in results]

    # 4. Leakage check — out-of-scope hosts never reach the derived output.
    foreign = find_foreign(apex, output_dir, sources=list_sources)
    report.foreign = foreign
    if foreign:
        flat = sorted({host for hosts in foreign.values() for host in hosts})
        write_host_list(output_dir / FOREIGN_FILE, flat)
        report.outputs["foreign"] = (output_dir / FOREIGN_FILE).as_posix()

        in_scope_count = len(observations)
        share = len(flat) / max(1, len(flat) + in_scope_count)
        disqualifying = _foreign_is_disqualifying(
            foreign_policy, foreign_count=len(flat), share=share
        )
        log.warning(
            "%d out-of-scope host(s) in source output (%.1f%% of all hosts) - %s",
            len(flat),
            share * 100,
            "DISQUALIFYING" if disqualifying else f"recorded in {FOREIGN_FILE}",
        )
        for name, hosts in foreign.items():
            log.warning("  %s: %s%s", name, ", ".join(hosts[:5]), " ..." if len(hosts) > 5 else "")

        if disqualifying:
            report.foreign_abort = True
            report.ok = False
            # Populate the report before bailing out, so the abort itself is
            # diagnosable from report.json without re-reading the raw files.
            report.counts = _build_counts(
                results, ran, report, foreign, raw_count=in_scope_count, kept_count=0
            )
            report.finished_at = _utc_now()
            report.seconds = time.monotonic() - started
            _write_report(output_dir / REPORT_FILE, report)
            raise ForeignDomainError(
                f"{len(flat)} host(s) outside {apex!r} found in source output "
                f"({share:.0%} of all hosts - possible stale TARGET / wrong "
                f"domain): "
                + ", ".join(flat[:5])
                + (" ..." if len(flat) > 5 else "")
                + f". See {output_dir / FOREIGN_FILE}.",
                offenders={k: v for k, v in foreign.items()},
            )

    # 5. Wildcard detection + suppression.
    raw_count = len(observations)
    verdicts = []
    filtered = None
    if wildcards and observations:
        verdicts = detect_wildcards(apex, observations, resolver=resolver)
        filtered = filter_wildcard_noise(observations, verdicts, resolver=resolver)
        kept = filtered.kept
        suppressed = filtered.suppressed
    else:
        kept = observations
        suppressed = {}

    # 6. Write the derived outputs.
    report.domains = [apex]
    report.wildcards = sorted({v.pattern for v in verdicts if v.is_wildcard})
    report.suppressed = suppressed

    outputs = {
        DOMAINS_FILE: write_host_list(output_dir / DOMAINS_FILE, report.domains),
        SUBDOMAINS_FILE: write_host_list(output_dir / SUBDOMAINS_FILE, kept),
        WILDCARDS_FILE: write_host_list(output_dir / WILDCARDS_FILE, report.wildcards),
        SUPPRESSED_FILE: write_host_list(output_dir / SUPPRESSED_FILE, suppressed),
    }
    report.outputs.update({key: Path(path).as_posix() for key, path in outputs.items()})

    report.counts = _build_counts(
        results, ran, report, foreign, raw_count=raw_count, kept_count=len(kept)
    )

    report.finished_at = _utc_now()
    report.seconds = time.monotonic() - started
    report.outputs["report"] = _write_report(output_dir / REPORT_FILE, report).as_posix()

    _log_summary(report)
    return report


def _foreign_is_disqualifying(policy: str, *, foreign_count: int, share: float) -> bool:
    """Decide whether out-of-scope hosts should abort the stage."""
    if policy == FOREIGN_POLICY_LENIENT:
        return False
    if policy == FOREIGN_POLICY_STRICT:
        return foreign_count > 0
    return share >= FOREIGN_ABORT_SHARE


def _build_counts(
    results: list[registry.SourceResult],
    ran: list[registry.SourceResult],
    report: PassiveReport,
    foreign: dict[str, list[str]],
    *,
    raw_count: int,
    kept_count: int,
) -> dict[str, int]:
    """Assemble the report's count block.

    Called on the normal path and again on the strict-foreign abort path, so
    ``report.json`` is complete either way.
    """
    return {
        "sources_selected": len(results),
        "sources_succeeded": len(ran),
        "sources_failed": sum(1 for r in results if not r.ok and r.skipped is None),
        "sources_skipped": sum(1 for r in results if r.skipped is not None),
        "amass_relations": report.amass_relations,
        "subdomains_raw": raw_count,
        "subdomains": kept_count,
        "wildcards": len(report.wildcards),
        "wildcard_suppressed": len(report.suppressed),
        "foreign": sum(len(hosts) for hosts in foreign.values()),
    }


def _write_report(path: Path, report: PassiveReport) -> Path:
    """Persist the run report as JSON (atomic replace)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(report.to_json(), encoding="utf-8", newline="\n")
    tmp.replace(path)
    return path


def _log_summary(report: PassiveReport) -> None:
    counts = report.counts
    colorlog.log.info(
        f"passive stage for {report.target}: "
        f"{counts.get('subdomains', 0)} subdomain(s), "
        f"{counts.get('wildcards', 0)} wildcard(s), "
        f"{counts.get('wildcard_suppressed', 0)} suppressed, "
        f"{counts.get('sources_succeeded', 0)}/{counts.get('sources_selected', 0)} "
        f"source(s) succeeded in {report.seconds:.1f}s"
    )
    if counts.get("sources_failed"):
        colorlog.log.warn(
            f"{counts['sources_failed']} source(s) failed - see "
            f"{report.outputs.get('report', 'report.json')} for details"
        )
    if counts.get("foreign"):
        colorlog.log.warn(
            f"{counts['foreign']} out-of-scope host(s) excluded from the output - "
            f"see {report.outputs.get('foreign', FOREIGN_FILE)}"
        )
    if report.wildcards:
        colorlog.log.warn(
            "wildcard DNS present; names only explained by it were dropped "
            f"({', '.join(report.wildcards)})"
        )
    if report.ok:
        colorlog.log.success(
            f"normalized subdomains written to {report.outputs.get(SUBDOMAINS_FILE)}"
        )
    else:
        colorlog.log.failed(
            f"passive stage for {report.target} did not complete cleanly - "
            f"see {report.outputs.get('report', 'report.json')}"
        )


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m "
        "service.recon_pipeline.pipelines.subdomain_domain_wildcards.passive.pipeline",
        description=(
            "Run every passive subdomain source, normalize + merge the results, "
            "detect wildcard DNS, and write passive/output/."
        ),
    )
    parser.add_argument(
        "-t", "--target", default=TARGET, help=f"apex domain (default: {TARGET})"
    )
    parser.add_argument(
        "--only", default=None,
        help="comma-separated sources to run (default: all)",
    )
    parser.add_argument(
        "--skip", default="", help="comma-separated sources to skip"
    )
    parser.add_argument(
        "--no-wildcards", action="store_true",
        help="skip DNS wildcard detection and wildcard-flood suppression",
    )
    foreign_group = parser.add_mutually_exclusive_group()
    foreign_group.add_argument(
        "--strict-foreign", action="store_true",
        help="abort on a single out-of-scope host (overrides the default)",
    )
    foreign_group.add_argument(
        "--lenient-foreign", action="store_true",
        help="never abort on out-of-scope hosts; only record and warn",
    )
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_SOURCE_TIMEOUT,
        help=f"per-source timeout in seconds (default: {DEFAULT_SOURCE_TIMEOUT})",
    )
    parser.add_argument(
        "--output-dir", default=str(OUTPUT_DIR),
        help=f"output directory (default: {OUTPUT_DIR})",
    )
    parser.add_argument(
        "--list", action="store_true", help="list available sources and exit"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="show debug logging"
    )
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
        print(f"{'source':<12} {'flavour':<20} description")
        print("-" * 78)
        for row in registry.describe_sources():
            print(f"{row['name']:<12} {row['flavour']:<20} {row['description']}")
        return 0

    try:
        report = run_passive_stage(
            args.target,
            only=_split(args.only),
            skip=_split(args.skip) or (),
            wildcards=not args.no_wildcards,
            foreign_policy=(
                FOREIGN_POLICY_STRICT
                if args.strict_foreign
                else FOREIGN_POLICY_LENIENT
                if args.lenient_foreign
                else FOREIGN_POLICY_THRESHOLD
            ),
            timeout=args.timeout,
            output_dir=args.output_dir,
        )
    except ForeignDomainError as exc:
        colorlog.log.failed(str(exc))
        return 2
    except (ValueError, KeyError) as exc:
        colorlog.log.failed(str(exc))
        return 2

    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
