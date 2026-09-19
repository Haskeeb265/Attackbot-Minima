"""``cloud_resource`` — pipeline orchestrator: sibling artifacts → verdicts.

Run order (each step is independently runnable through ``--stages``):::

    harvest   read sibling artifacts, derive candidate bucket names (no network)
    probe     one GET per candidate against its provider, classified by matrix
    emit      verdicts.jsonl, buckets.jsonl, dangling.jsonl, report.json

What this module adds over the per-source functions:

* **Stage selection with dependency honesty.**  ``--stages probe`` runs the
  harvest first when no candidate artifact exists — probing needs candidates —
  and says so in the summary's ``note``, the same convention
  ``graph_normalize`` uses for its later stages.
* **Provenance discipline.**  Every candidate and every verdict keeps where it
  came from (origin, artifact, evidence string), so a downstream consumer —
  the S25 takeover detector above all — can weigh the claim without re-deriving it.
* **Honest caps.**  The derived-name cap and the probe cap are recorded in the
  reports when they bite, so a truncated artifact set is never mistaken for a
  whole one.
* **"No answer" is not "absent".**  Unavailable probes lower ``ok`` and are
  counted, never folded into a false negative.
"""

from __future__ import annotations

import argparse
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

import shared.colorlog as colorlog

from service.recon_pipeline.platform.common.config import TARGET
from service.recon_pipeline.platform.common.normalize import canonicalize_host
from . import emit, settings, verify
from .normalize import Candidate
from .seeds import harvest

log = logging.getLogger("cloud_resource.main")

ALL_STAGES: tuple[str, ...] = ("harvest", "probe", "takeover")

CANDIDATES_JSONL = "candidates.jsonl"


@dataclass
class CloudReport:
    """Machine-readable summary of one pipeline run."""

    target: str
    started_at: str
    finished_at: str = ""
    seconds: float = 0.0
    ok: bool = True
    stages_run: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    outputs: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "seconds": round(self.seconds, 2),
            "ok": self.ok,
            "stages_run": list(self.stages_run),
            "counts": self.counts,
            "outputs": self.outputs,
            "notes": self.notes,
        }


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run_pipeline(
    target: str = TARGET,
    *,
    stages: list[str] | tuple[str, ...] = ALL_STAGES,
    output_dir: Path | str = settings.OUTPUT_DIR,
    passive_output_dir: Path | str = settings.PASSIVE_OUTPUT_DIR,
    names_dir: Path | str | None = None,
    urls_dir: Path | str | None = None,
    explicit_names: list[str] | None = None,
    use_siblings: bool = True,
    max_derived: int | None = None,
    max_probes: int | None = None,
    fetcher: verify.Fetcher | None = None,
    timeout: float | None = None,
) -> CloudReport:
    """Run the requested *stages* in order and write the artifacts.

    Parameters
    ----------
    stages:
        Any of :data:`ALL_STAGES`, run in the order given.  ``probe`` runs the
        harvest first (noting it) when the candidate artifact is absent.
    output_dir / passive_output_dir:
        Where the probe / harvest artifacts are written.
    names_dir / urls_dir:
        Overrides for the sibling artifact roots (tests, alternate checkouts).
    explicit_names:
        Operator-supplied candidate names (``--name``, repeatable).
    use_siblings:
        False when the operator said ``--no-sibling-input``: no sibling artifact
        is read, candidates come from *explicit_names* only.
    max_derived / max_probes:
        Cap overrides (defaults from :mod:`settings`).
    fetcher:
        Injected HTTP callable for tests; production uses :func:`verify.http_get`.
    timeout:
        Per-probe budget override.
    """
    unknown = [name for name in stages if name not in ALL_STAGES]
    if unknown:
        raise ValueError(f"unknown stage(s) {', '.join(unknown)}; known: {', '.join(ALL_STAGES)}")

    apex = canonicalize_host(target)
    if apex is None:
        raise ValueError(f"target {target!r} is not a valid domain (expected e.g. 'example.com')")

    output_dir = Path(output_dir)
    passive_output_dir = Path(passive_output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    started = time.monotonic()
    report = CloudReport(target=apex, started_at=_utc_now(), stages_run=list(stages))
    notes: list[str] = []
    candidates: list[Candidate] = []
    harvest_counts: dict[str, int] = {}

    candidates_path = passive_output_dir / CANDIDATES_JSONL

    for stage in stages:
        stage_started = time.monotonic()
        if stage == "harvest":
            candidates, harvest_counts, _ = harvest(
                apex,
                output_dir=passive_output_dir,
                names_dir=names_dir,
                urls_dir=urls_dir,
                explicit_names=explicit_names or (),
                use_siblings=use_siblings,
                max_derived=max_derived,
            )
            report.counts.update(harvest_counts)
        elif stage == "probe":
            if not candidates and candidates_path.is_file():
                candidates = _read_candidates(candidates_path)
                notes.append("probe re-used the existing candidate artifact (harvest not in this run)")
            if not candidates and not candidates_path.is_file():
                candidates, harvest_counts, _ = harvest(
                    apex,
                    output_dir=passive_output_dir,
                    names_dir=names_dir,
                    urls_dir=urls_dir,
                    explicit_names=explicit_names or (),
                    use_siblings=use_siblings,
                    max_derived=max_derived,
                )
                report.counts.update(harvest_counts)
                notes.append("probe ran the harvest first (no candidate artifact existed)")
            verdicts, probe_counts = verify.probe_candidates(
                candidates, fetcher=fetcher, timeout=timeout, max_probes=max_probes
            )
            report.counts.update(probe_counts)
            emit.write_jsonl(output_dir / "verdicts.jsonl", (v.to_dict() for v in verdicts))
            emit.write_jsonl(output_dir / "buckets.jsonl", emit.bucket_rows(verdicts))
            emit.write_jsonl(output_dir / "dangling.jsonl", emit.dangling_rows(verdicts))
            probe_seconds = time.monotonic() - stage_started
            probe_summary = emit.probe_report(apex, verdicts, probe_counts, probe_seconds)
            emit.write_json(output_dir / "report.json", probe_summary)
            report.outputs.update(
                {
                    "verdicts": (output_dir / "verdicts.jsonl").as_posix(),
                    "buckets": (output_dir / "buckets.jsonl").as_posix(),
                    "dangling": (output_dir / "dangling.jsonl").as_posix(),
                    "report": (output_dir / "report.json").as_posix(),
                }
            )
            if probe_counts.get("truncated"):
                notes.append(
                    f"probe cap reached ({max_probes or settings.MAX_PROBES}); "
                    f"{probe_counts['truncated']} candidate(s) not probed"
                )

        else:  # takeover (S25): detector, one GET per fingerprint-matched claim
            from . import takeover as takeover_mod

            records_rows = _read_records(names_dir)
            findings, takeover_counts = takeover_mod.run_takeover(
                records_rows,
                fetcher=fetcher or takeover_mod.http_get,
                output_dir=output_dir,
            )
            report.counts.update(takeover_counts)
            report.outputs["takeover"] = (output_dir / "takeover.jsonl").as_posix()
            if takeover_counts.get("claims") and not takeover_counts.get("fingerprint_matched"):
                notes.append("takeover: claims existed but none matched a fingerprint")
            notes.append(
                f"takeover: policy gate set to '{settings.TAKEOVER_POLICY}' — "
                f"{takeover_counts.get('scored', 0)} scored, "
                f"{takeover_counts.get('informational', 0)} informational"
            )

    # The harvest artifacts are outputs too, whenever the stage ran in-process.
    if candidates:
        report.outputs.update(
            {
                "candidates": candidates_path.as_posix(),
                "candidates_txt": (passive_output_dir / "candidates.txt").as_posix(),
                "harvest_report": (passive_output_dir / "report.json").as_posix(),
            }
        )

    # The sibling rule for ok: a probe that could not obtain an answer is a
    # failure; everything else (missing artifacts, zero candidates, an Azure
    # NXDOMAIN absence fact) is a state, not a failure.
    report.ok = report.counts.get("unavailable", 0) == 0
    report.notes = notes
    report.finished_at = _utc_now()
    report.seconds = time.monotonic() - started

    combined = output_dir / "summary.json"
    emit.write_json(combined, report.to_dict())
    report.outputs["summary"] = combined.as_posix()

    _log_summary(report)
    return report


def _read_candidates(path: Path) -> list[Candidate]:
    """Read back a candidate artifact (rows the harvest stage wrote)."""
    from service.recon_pipeline.platform.common.io import read_jsonl

    rows: list[Candidate] = []
    for row in read_jsonl(path):
        name = row.get("name")
        provider = row.get("provider")
        if isinstance(name, str) and isinstance(provider, str):
            rows.append(
                Candidate(
                    name=name,
                    provider=provider,
                    origins=set(row.get("origins") or ()),
                    sources=set(row.get("sources") or ()),
                    evidence=[str(item) for item in row.get("evidence") or ()],
                    claimants=[str(item) for item in row.get("claimants") or ()],
                    distinctive=bool(row.get("distinctive", True)),
                )
            )
    return rows


def _read_records(names_dir: Path | str | None) -> list[dict]:
    """The names stage's records stream — the takeover detector's raw material.

    Same sibling-discipline as the harvest: the artifact is read, not the
    sibling's code, and absence is a state the report shows (an empty records
    list means no claims were ever seen, which the counts make visible).
    """
    from service.recon_pipeline.platform.common.io import read_jsonl

    root = Path(names_dir) if names_dir else settings.NAMES_DIR
    records_path = root / "active" / "output" / "records.jsonl"
    if not records_path.is_file():
        return []
    return read_jsonl(records_path)


def _log_summary(report: CloudReport) -> None:
    colorlog.log.info(
        f"cloud_resource for {report.target}: {report.counts.get('probed', 0)} probe(s), "
        f"{report.counts.get('open', 0)} open, {report.counts.get('auth_required', 0)} auth-required, "
        f"{report.counts.get('dangling', 0)} dangling, {report.counts.get('exists_other_region', 0)} "
        f"other-region, {report.counts.get('unavailable', 0)} unavailable — "
        f"{report.seconds:.1f}s"
    )
    for note in report.notes:
        colorlog.log.info(f"note: {note}")
    if report.ok:
        colorlog.log.success(f"artifacts written to {report.outputs.get('summary', 'output/')}")
    else:
        colorlog.log.warn(
            "some probes could not obtain an answer - see output/report.json"
        )


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m service.recon_pipeline.pipelines.cloud_resource.main",
        description=(
            "Discover cloud-storage resources (S3 / Azure / GCS): harvest candidate "
            "names from sibling artifacts, then probe the providers for existence. "
            "Probes touch the providers, never the target."
        ),
    )
    parser.add_argument("-t", "--target", default=TARGET, help=f"apex domain (default: {TARGET})")
    parser.add_argument(
        "--stages",
        default=",".join(ALL_STAGES),
        help=f"comma-separated stages to run (default: {','.join(ALL_STAGES)})",
    )
    parser.add_argument(
        "--name",
        action="append",
        default=None,
        dest="names",
        help="explicit candidate name (repeatable), probed against every enabled provider",
    )
    parser.add_argument(
        "--no-sibling-input",
        action="store_true",
        help="do not read sibling-stage artifacts (explicit --name seeds only)",
    )
    parser.add_argument("--output-dir", default=str(settings.OUTPUT_DIR), help="probe output directory")
    parser.add_argument(
        "--passive-output-dir", default=str(settings.PASSIVE_OUTPUT_DIR), help="harvest output directory"
    )
    parser.add_argument("--max-derived", type=int, default=None, help="cap on derived names")
    parser.add_argument("--max-probes", type=int, default=None, help="cap on existence probes")
    parser.add_argument("--timeout", type=float, default=None, help="per-probe seconds")
    parser.add_argument("--list", action="store_true", help="list the stages and exit")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.  Returns a process exit code."""
    args = _build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-7s %(name)s: %(message)s",
    )

    if args.list:
        print("stages, in run order:")
        for stage in ALL_STAGES:
            print(f"  {stage}")
        return 0

    stages = [stage.strip() for stage in args.stages.split(",") if stage.strip()]
    try:
        report = run_pipeline(
            args.target,
            stages=stages,
            output_dir=Path(args.output_dir),
            passive_output_dir=Path(args.passive_output_dir),
            explicit_names=list(args.names or []),
            use_siblings=not args.no_sibling_input,
            max_derived=args.max_derived,
            max_probes=args.max_probes,
            timeout=args.timeout,
        )
    except (ValueError, KeyError) as exc:
        colorlog.log.failed(str(exc))
        return 2

    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
