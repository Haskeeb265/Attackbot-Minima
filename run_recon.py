#!/usr/bin/env python3
"""Run the names, ports/services, URL/endpoint, ASN/CIDR and cloud-resource
pipelines against one target and write one combined report at the project root.

What it does, in order:

1. runs ``subdomain_domain_wildcards`` (passive -> active -> permutation), whose
   ``active/output/records.jsonl`` is the address source for the port stage;
2. runs ``port_service_host`` against the same target;
3. runs ``url_endpoint`` (historical URL harvest -> endpoints/parameters/JS);
4. runs ``asn_cidr`` (network ownership discovery; never scans, emits the ports
   stage's discovered-scope files) — best *after* pipeline 2 so sibling
   addresses exist for annotation;
5. runs ``cloud_resource`` (storage-bucket harvest + provider probes) — last
   deliberately, since the names/URL artifacts are its seed material;
6. assembles ``RECON_<target>_OUTPUT.md`` at the project root: a data-driven
   summary (read from the stages' machine reports, never hand-written) followed
   by every curated artifact verbatim, then the console logs.

With ``--until-converged`` step 1–5 become a **loop**: round 1 is the run above,
and every later round re-runs only the stages whose answer a grown frontier can
change — the names stage's ``active``/``permutation`` (its generators), ports
(new addresses), ASN/CIDR (new addresses) and cloud buckets (new names and
URLs).  The passive names sources, the URL archives and ASN's registry lookups
are asked the same question once and answered in full (see
``service/recon_pipeline/platform/convergence.py``), so re-running them buys
nothing.  The loop stops on a measured fixed point *or* a limit
(``--max-rounds``, ``--time-budget``, a quarantine), and the report always names
which of the two it was — ``frontier_exhausted`` is the only verdict that claims
the surface ran out.

Two properties it exists to guarantee:

* **Only this run's artifacts are embedded.**  Every output directory is
  mtimeshot before the run; a file that was not written during the run (an
  ``nmap-1.xml`` left over from yesterday, a stale ``records.jsonl``) is excluded
  from the report and listed as stale instead of passing for fresh evidence.
* **The summary is computed, not authored.**  The tables come from
  ``summary.json``/``report.json``, so the report cannot claim something the
  machine reports do not.

Usage::

    python run_recon.py -t qbsco.net
    python run_recon.py -t example.com --stages active,permutation   # skip passive
    python run_recon.py -t example.com --skip-subdomain              # ports + URLs
    python run_recon.py -t example.com --skip-ports                  # names + URLs
    python run_recon.py -t example.com --skip-url                    # names + ports
    python run_recon.py -t example.com --skip-asn                    # names + ports + URLs
    python run_recon.py -t example.com --skip-cloud                  # all but buckets

Per-stage knobs keep working through their environment variables (``PSH_*``,
``ACTIVE_*``) — this script forwards nothing it does not understand, so a run is
reproducible from the documented settings alone.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent

SDW_MODULE = "service.recon_pipeline.pipelines.subdomain_domain_wildcards.main"
PSH_MODULE = "service.recon_pipeline.pipelines.port_service_host.pipeline"
URL_MODULE = "service.recon_pipeline.pipelines.url_endpoint.main"
ASN_MODULE = "service.recon_pipeline.pipelines.asn_cidr.main"
CLOUD_MODULE = "service.recon_pipeline.pipelines.cloud_resource.main"

SDW_DIR = ROOT / "service/recon_pipeline/pipelines/subdomain_domain_wildcards"
PSH_DIR = ROOT / "service/recon_pipeline/pipelines/port_service_host"
URL_DIR = ROOT / "service/recon_pipeline/pipelines/url_endpoint"
ASN_DIR = ROOT / "service/recon_pipeline/pipelines/asn_cidr"
CLOUD_DIR = ROOT / "service/recon_pipeline/pipelines/cloud_resource"

#: The artifacts worth embedding, relative to each stage directory.  Anything
#: absent or stale is skipped and reported.  The permutation stage's 26
#: ``candidates-batch-*.txt`` files are deliberately not here: 300 KB of
#: candidate names that resolved to nothing is noise, and the stage report
#: already counts them.
SDW_ARTIFACTS: tuple[str, ...] = (
    "output/live_hosts.txt",
    "output/summary.json",
    "passive/output/subdomains.txt",
    "passive/output/domains.txt",
    "passive/output/subfinder.txt",
    "passive/output/crtsh.txt",
    "passive/output/chaos.txt",
    "passive/output/assetfinder.txt",
    "passive/output/findomain.txt",
    "passive/output/wayback.txt",
    "passive/output/amass.txt",
    "active/output/resolved.txt",
    "active/output/records.txt",
    "active/output/records.jsonl",
    "permutation/output/resolved.txt",
    "passive/output/report.json",
    "active/output/report.json",
    "permutation/output/report.json",
)

PSH_ARTIFACTS: tuple[str, ...] = (
    "output/ips_raw.txt",
    "output/hosts.txt",
    "output/openports.jsonl",
    "output/naabu.jsonl",
    "output/httpx.jsonl",
    "output/services.jsonl",
    "output/escalated-naabu.jsonl",
    "output/ptr.jsonl",
    "output/passive_intel.jsonl",
    "output/ownership.jsonl",
    "output/cdn_classified.jsonl",
    "output/quarantine.json",
    "output/report.json",
)

URL_ARTIFACTS: tuple[str, ...] = (
    "passive/output/urls.txt",
    "passive/output/report.json",
    "output/endpoints.txt",
    "output/parameters.txt",
    # The provenance-bearing forms: which URL exposes which parameter, and what
    # the live validation stage actually measured.  ``url_validation.jsonl`` is
    # the difference between "the archive mentioned it" and "it answered today".
    "output/parameters.jsonl",
    "output/url_validation.jsonl",
    "output/validation.json",
    "output/javascript.txt",
    "output/source_maps.txt",
    "output/interesting.txt",
    "output/hosts.txt",
    "output/report.json",
    "output/summary.json",
)

ASN_ARTIFACTS: tuple[str, ...] = (
    "output/networks.jsonl",
    "output/asns.jsonl",
    "output/scope/discovered.txt",
    "output/scope/discovered.annotated.txt",
    "output/report.json",
)

#: What each pipeline puts *on the table*, mirrored from its manifest's
#: ``frontier_artifacts``.  ``test_convergence.py`` pins the two against each
#: other, so this cannot drift into a loop that measures a file nobody writes.
FRONTIER_ARTIFACTS: dict[str, tuple[Path, tuple[str, ...]]] = {
    "names": (
        SDW_DIR,
        (
            "output/live_hosts.txt",
            "active/output/resolved.txt",
            "permutation/output/resolved.txt",
        ),
    ),
    "ports": (PSH_DIR, ("output/ips_raw.txt", "output/hosts.txt")),
    "url": (
        URL_DIR,
        (
            "passive/output/urls.txt",
            "output/endpoints.txt",
            "output/javascript.txt",
            "output/hosts.txt",
        ),
    ),
    "asn": (ASN_DIR, ("output/scope/discovered.txt",)),
    "cloud": (CLOUD_DIR, ("passive/output/candidates.txt",)),
}

#: Stages a grown frontier can genuinely change the answer for.  ``url`` is
#: absent on purpose: all four of its sources are per-domain archives, so a
#: second pass asks the same question of the same archive (measured at 94–393 s).
#: ``names`` repeats only ``active,permutation`` — ``passive``'s sources are
#: subtree queries, so one call already returns every depth.
REPEAT_STAGES: dict[str, str] = {"names": "active,permutation"}

#: Which frontier kinds make each repeat job worth its requests, mirrored from the
#: manifests' ``repeat_on`` (the convergence tests pin the two together).  A round
#: that added only URLs, say, owes the ports stage no packets at all.
REPEAT_ON: dict[str, tuple[str, ...]] = {
    "names": ("host",),
    "ports": ("ip",),
    "asn": ("ip",),
    "cloud": ("host", "url"),
}

CLOUD_ARTIFACTS: tuple[str, ...] = (
    "passive/output/candidates.jsonl",
    "passive/output/candidates.txt",
    "passive/output/report.json",
    "output/verdicts.jsonl",
    "output/buckets.jsonl",
    "output/dangling.jsonl",
    "output/report.json",
    "output/summary.json",
)


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _mtimes(directory: Path) -> dict[str, float]:
    """``relative path -> mtime`` for every file under *directory*."""
    snapshot: dict[str, float] = {}
    if not directory.is_dir():
        return snapshot
    for path in directory.rglob("*"):
        if path.is_file():
            snapshot[path.relative_to(directory).as_posix()] = path.stat().st_mtime
    return snapshot


def _console_write(line: str) -> None:
    """Write *line* to stdout, losing a glyph rather than the engagement.

    A child that emits bytes in its own locale encoding (every Python child of this
    script defaults to the ANSI code page on Windows, not UTF-8) decodes here into
    U+FFFD, and a cp1252 console cannot encode that character at all: the write
    raises ``UnicodeEncodeError`` and took down a live converged run mid-probe.  The
    log file — the record that matters — is written separately as UTF-8; the console
    is only a window, and a window may drop a character.
    """
    try:
        sys.stdout.write(line)
    except UnicodeEncodeError:
        encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
        sys.stdout.write(line.encode(encoding, "replace").decode(encoding, "replace"))


def _child_env(env: dict[str, str] | None = None) -> dict[str, str]:
    """The child's environment, with UTF-8 pinned for its own stdout.

    Fixing the *parent* side of the pipe alone would still be guessing: telling the
    child to speak UTF-8 is what makes the round trip lossless, so a stage that
    prints a non-ASCII hostname or a box-drawing character arrives intact.
    """
    merged = dict(os.environ if env is None else env)
    merged.setdefault("PYTHONIOENCODING", "utf-8")
    merged.setdefault("PYTHONUTF8", "1")
    return merged


def _run_streamed(
    command: list[str], log_path: Path, env: dict[str, str] | None = None
) -> int:
    """Run *command*, teeing stdout+stderr to the console and *log_path*.

    The child is invoked with ``-u`` (unbuffered).  Without it Python block-buffers
    stdout when it is a pipe, so a long stage's log stays empty for minutes and an
    interrupted run leaves a zero-byte log — measured here: a full three-pipeline
    run killed after 10 minutes had written nothing to the subdomain log even
    though that stage had been running the whole time.
    """
    _console_write(f"[run_recon] $ {' '.join(command)}\n")
    sys.stdout.flush()
    env = _child_env(env)
    started = time.monotonic()
    with log_path.open("w", encoding="utf-8", newline="\n") as log:
        process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=ROOT,
            env=env,
        )
        assert process.stdout is not None
        for line in process.stdout:
            log.write(line)
            _console_write(line)
            sys.stdout.flush()
        code = process.wait()
    log_path.write_text(
        log_path.read_text(encoding="utf-8", errors="replace")
        + f"\nEXIT_CODE={code} ({time.monotonic() - started:.1f}s)\n",
        encoding="utf-8",
        newline="\n",
    )
    return code


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}


def _fence(path: Path, relative: str, stale: bool) -> str:
    if stale:
        return f"\n#### `{relative}`\n\n(stale — not written by this run, not embedded)\n"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return f"\n#### `{relative}`\n\n(absent — this run produced no such artifact)\n"
    lines = text.count("\n")
    return (
        f"\n#### `{relative}` (verbatim, {lines} lines)\n\n```text\n"
        + (text if text.endswith("\n") or not text else text + "\n")
        + "```\n"
    )


def _mail_records(sdw_dir: Path, apex: str) -> list[str]:
    """The apex's mail policy, from this run's ``records.jsonl``.

    The answer to "where does mail actually flow" — MX, SPF and DMARC — lives on
    the apex, which is why the active stage now enriches it.  Surfacing it in the
    summary keeps the report from burying its one direct answer to a question the
    previous run could not answer at all.
    """
    rows: list[str] = []
    records_path = sdw_dir / "active/output/records.jsonl"
    try:
        text = records_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return rows
    wanted = {apex, f"_dmarc.{apex}", f"_domainkey.{apex}"}
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = str(payload.get("host") or "").rstrip(".").lower()
        if host not in wanted:
            continue
        for rtype in ("mx", "txt", "cname"):
            values = payload.get(rtype) or []
            for value in values:
                rows.append(f"{host}  {rtype.upper()}  {value}")
    return rows


def _summary_section(sdw_report: dict, psh_report: dict, url_report: dict,
                     asn_report: dict, cloud_report: dict, apex: str,
                     warnings: list[str] | None = None) -> str:
    """The data-driven header of the report: what happened, from the machine reports."""
    out: list[str] = [f"# Recon output — {apex}", ""]
    out.append(f"**Assembled:** {_utc()}  ·  generated by `run_recon.py` "
               "(summary values are read from the stages' machine reports)")
    for warning in warnings or []:
        out.append("")
        out.append(f"> **WARNING:** {warning}")
    out.append("")

    if sdw_report:
        stages = sdw_report.get("stages") or []
        out.append("## Pipeline 1 — subdomain_domain_wildcards")
        out.append("")
        out.append("| Stage | Seconds | OK | Key counts |")
        out.append("|---|---|---|---|")
        for entry in stages:
            counts = entry.get("counts") or {}
            key = ", ".join(f"{k} {v}" for k, v in counts.items() if v)
            out.append(
                f"| {entry.get('stage')} | {entry.get('seconds', 0):.1f} "
                f"| {entry.get('ok')} | {key or '-'} |"
            )
        out.append("")
        out.append(
            f"**Union:** {sdw_report.get('counts', {}).get('live_hosts', 0)} live host(s) "
            f"in {sdw_report.get('seconds', 0):.1f}s · ok={sdw_report.get('ok')}"
        )
        mail = _mail_records(SDW_DIR, apex)
        if mail:
            out.append("")
            out.append("**Apex mail policy (MX/SPF/DMARC, from this run's enrichment):**")
            out.append("")
            out.append("```text")
            out.extend(mail)
            out.append("```")
        else:
            out.append("")
            out.append("**Apex mail policy:** no MX/TXT/DMARC rows in this run's enrichment "
                       "(check `active/output/records.jsonl` below before calling it \"none\").")
        out.append("")

    if psh_report:
        counts = psh_report.get("counts") or {}
        ladder_block = psh_report.get("ladder") or {}
        out.append("## Pipeline 2 — port_service_host")
        out.append("")
        out.append(
            f"{counts.get('addresses', 0)} address(es) → {counts.get('open_ports', 0)} "
            f"open port(s) on {counts.get('hosts', 0)} host(s), "
            f"{counts.get('services', 0)} service(s), in {psh_report.get('seconds', 0):.1f}s "
            f"· ok={psh_report.get('ok')}"
        )
        out.append("")
        out.append(f"Classification: {psh_report.get('classification', {}).get('by_verdict', {})}")
        out.append(f"Ladder: {ladder_block.get('by_level', {})}")
        if ladder_block.get("escalated"):
            out.append(f"Escalated to full-range: {ladder_block['escalated']}")
        if ladder_block.get("escalation_refused_hosted"):
            out.append(
                "Escalation refused (hosted): "
                + ", ".join(ladder_block["escalation_refused_hosted"])
            )
        out.append("")
        out.append(f"Counts: `{json.dumps(counts, sort_keys=True)}`")
        out.append("")

    if url_report:
        counts = url_report.get("counts") or {}
        out.append("## Pipeline 3 — url_endpoint")
        out.append("")
        out.append(
            f"{counts.get('urls', 0)} URL(s) → {counts.get('endpoints', 0)} endpoint(s), "
            f"{counts.get('parameters', 0)} parameter(s), "
            f"{counts.get('javascript', 0)} JS bundle(s), "
            f"{counts.get('interesting', 0)} interesting file(s), "
            f"in {url_report.get('seconds', 0):.1f}s · ok={url_report.get('ok')}"
        )
        out.append("")
        stages = url_report.get("stages") or []
        if stages:
            out.append("| Stage | Seconds | OK | Key counts |")
            out.append("|---|---|---|---|")
            for entry in stages:
                stage_counts = entry.get("counts") or {}
                key = ", ".join(f"{k} {v}" for k, v in stage_counts.items() if v)
                out.append(
                    f"| {entry.get('stage')} | {entry.get('seconds', 0):.1f} "
                    f"| {entry.get('ok')} | {key or '-'} |"
                )
            out.append("")
        out.append(f"Counts: `{json.dumps(counts, sort_keys=True)}`")
        out.append("")

    if asn_report:
        counts = asn_report.get("counts") or {}
        out.append("## Pipeline 4 — asn_cidr (network ownership; discovery only, never scans)")
        out.append("")
        out.append(
            f"{counts.get('networks', 0)} network(s) discovered "
            f"({counts.get('announced', 0)} announced, {counts.get('allocated', 0)} allocated, "
            f"{counts.get('both_origins', 0)} corroborated), "
            f"{counts.get('with_known_hosts', 0)} contain resolved address(es), in "
            f"{asn_report.get('seconds', 0):.1f}s · ok={asn_report.get('ok')}"
        )
        out.append("")
        out.append(
            "Discovered ≠ declared: `asn_cidr/output/scope/discovered.txt` feeds no "
            "scan without an operator moving it into declared scope (design §5.4)."
        )
        out.append("")
        out.append(f"Counts: `{json.dumps(counts, sort_keys=True)}`")
        out.append("")

    if cloud_report:
        counts = cloud_report.get("counts") or {}
        by_state = cloud_report.get("by_state") or {}
        out.append("## Pipeline 5 — cloud_resource (storage buckets; probes touch providers, never the target)")
        out.append("")
        out.append(
            f"{counts.get('probed', 0)} probe(s): {by_state.get('open', 0)} open, "
            f"{by_state.get('auth_required', 0)} auth-required, "
            f"{by_state.get('dangling', 0)} dangling, "
            f"{by_state.get('exists_other_region', 0)} other-region, "
            f"{by_state.get('unavailable', 0)} unavailable, in "
            f"{cloud_report.get('seconds', 0):.1f}s · ok={cloud_report.get('ok')}"
        )
        out.append("")
        out.append(
            "Dangling CNAME-claimed names are the takeover detector's (S25) raw "
            "material — a bucket the target's DNS claims but the provider says is absent."
        )
        out.append("")
        out.append(f"Counts: `{json.dumps(counts, sort_keys=True)}`")
        out.append("")

    if not sdw_report and not psh_report and not url_report and not asn_report and not cloud_report:
        out.append("_No pipeline produced a readable report — see the logs below._")
        out.append("")
    return "\n".join(out) + "\n"


def _frontier_paths() -> list[Path]:
    """Every declared frontier artifact, as an absolute path."""
    return [
        directory / relative
        for directory, relatives in FRONTIER_ARTIFACTS.values()
        for relative in relatives
    ]


def _blocked_state() -> tuple[bool, str]:
    """Has the stealth layer quarantined us?  Best-effort, never raises.

    Every active stage keeps its own quarantine store under its ``output/``
    directory unless ``STEALTH_QUARANTINE_FILE`` points them all at one file, so
    all of them are consulted — checking only the shared setting would report
    "never blocked" on the default configuration.
    """
    try:
        sys.path.insert(0, str(ROOT))
        from service.recon_pipeline.platform.stealth import settings as stealth_settings
        from service.recon_pipeline.platform.stealth.quarantine import blocked_state
    except Exception:  # the loop must survive a missing stealth layer
        return False, ""
    paths: list[Path] = []
    if stealth_settings.QUARANTINE_FILE:
        paths.append(Path(stealth_settings.QUARANTINE_FILE))
    for directory in (SDW_DIR, PSH_DIR, URL_DIR):
        paths.extend(sorted(directory.glob("**/output/quarantine.json")))
    return blocked_state(paths)


def _repeat_jobs(
    apex: str,
    known: set[str],
    kinds: set[str],
    stamp: str,
    index: int,
    verbose: bool,
) -> tuple[list[tuple[str, list[str], Path]], list[str]]:
    """Rounds 2+: only what a grown frontier can change the answer for.

    Returns the jobs to run and the labels skipped for want of a relevant new
    asset — the second list is what makes a quiet round *visible* instead of
    looking like a loop that decided to do nothing.
    """
    jobs: list[tuple[str, list[str], Path]] = []
    # Sorted, not set order: Python randomises string hashing per process, so an
    # unsorted set walk makes the same round report a different skip list in every
    # run (the same defect the scope engine's "first containing network" had).
    skipped: list[str] = sorted(
        label
        for label in known
        if label in REPEAT_ON and not kinds.intersection(REPEAT_ON[label])
    )
    if "names" in known and "names" not in skipped:
        command = [sys.executable, "-u", "-m", SDW_MODULE, "-t", apex,
                   "--stages", REPEAT_STAGES["names"]]
        jobs.append(("names", command, ROOT / f"recon_{apex}_names_r{index}_{stamp}.log"))
    if "ports" in known and "ports" not in skipped:
        jobs.append((
            "ports",
            [sys.executable, "-u", "-m", PSH_MODULE, "-t", apex],
            ROOT / f"recon_{apex}_ports_r{index}_{stamp}.log",
        ))
    if "asn" in known and "asn" not in skipped:
        jobs.append((
            "asn",
            [sys.executable, "-u", "-m", ASN_MODULE, "-t", apex],
            ROOT / f"recon_{apex}_asn_r{index}_{stamp}.log",
        ))
    if "cloud" in known and "cloud" not in skipped:
        jobs.append((
            "cloud",
            [sys.executable, "-u", "-m", CLOUD_MODULE, "-t", apex],
            ROOT / f"recon_{apex}_cloud_r{index}_{stamp}.log",
        ))
    if verbose:
        for _label, command, _log in jobs:
            command.append("-v")
    return jobs, skipped


def _run_converged(
    apex: str,
    first_round_jobs: list[tuple[str, list[str], Path]],
    *,
    stamp: str,
    verbose: bool,
    policy,
) -> tuple[dict, list[int]]:
    """Loop rounds until the frontier stops growing, or a limit says stop."""
    sys.path.insert(0, str(ROOT))
    from service.recon_pipeline.platform.convergence import (
        ConvergenceDriver,
        Ledger,
        Round,
        token_kind,
    )

    exit_codes: list[int] = []
    known = {label for label, _command, _log in first_round_jobs}
    report_path = ROOT / f"recon_{apex}_convergence_{stamp}.json"
    ledger_path = ROOT / f"recon_{apex}_ledger_{stamp}.jsonl"
    # The scan receipt for *this* run.  Pointed at the run's own file so a fresh
    # engagement cannot inherit the last one's scan history and skip work it never
    # did — while the rounds inside the run share it, which is the point.
    receipt_path = ROOT / f"recon_{apex}_attempts_{stamp}.jsonl"
    child_env = {**os.environ, "PSH_ATTEMPT_RECEIPT": str(receipt_path)}

    def round_fn(index: int, found: frozenset[str]) -> Round:
        labels: list[str]
        skipped: list[str] = []
        if index == 1:
            jobs = first_round_jobs
        else:
            kinds = {token_kind(token) for token in found}
            jobs, skipped = _repeat_jobs(apex, known, kinds, stamp, index, verbose)
        started = time.monotonic()
        failed = 0
        for _label, command, log_path in jobs:
            code = _run_streamed(command, log_path, child_env)
            exit_codes.append(code)
            if code != 0:
                failed += 1
        blocked, why = _blocked_state()
        labels = [label for label, _command, _log in jobs]
        notes = [why] if why else []
        if skipped:
            found_kinds = sorted({token_kind(token) for token in found})
            notes.append(
                f"skipped {'/'.join(skipped)}: nothing new of kind "
                f"{'/'.join(found_kinds) if found_kinds else 'any'} to spend on"
            )
        return Round(
            index=index,
            seconds=time.monotonic() - started,
            stages_run=len(jobs),
            stages_failed=failed,
            blocked=blocked,
            gated=bool(skipped),
            stages=labels,
            notes=notes,
        )

    driver = ConvergenceDriver(
        policy=policy,
        ledger=Ledger(ledger_path),
        frontier_paths=_frontier_paths(),
        log_round=lambda message: print(f"[run_recon] {message}", flush=True),
    )
    payload = driver.run(round_fn, target=apex).to_dict()
    payload["report"] = report_path.as_posix()
    payload["receipt"] = receipt_path.as_posix()
    report_path.write_text(
        json.dumps(payload, indent=2, sort_keys=False), encoding="utf-8", newline="\n"
    )
    print(f"[run_recon] convergence: {payload['verdict']['reason']} "
          f"({payload['verdict']['detail']})", flush=True)
    return payload, exit_codes


def _convergence_section(payload: dict | None) -> str:
    """The report's account of the loop: how many rounds, and why it stopped."""
    if not payload:
        return ""
    verdict = payload.get("verdict") or {}
    out: list[str] = ["## Convergence — how the loop stopped", ""]
    out.append(f"**Verdict:** `{verdict.get('reason')}` — {verdict.get('detail')}")
    out.append("")
    if payload.get("exhausted"):
        out.append(
            "The frontier stopped growing: every declared discovery artifact was "
            "re-read after the last round and nothing new appeared in any of them. "
            "This is the only verdict that claims the surface ran out."
        )
    else:
        out.append(
            "**This run did not reach exhaustion.** It stopped on a limit, not "
            "because the surface ran out — read the round numbers below as \"how "
            "far this budget got\", not as \"all there is\"."
        )
    out.append("")
    out.append("| Round | New assets | Known | Pipelines | Failed | Seconds |")
    out.append("|---|---|---|---|---|---|")
    for entry in payload.get("rounds") or []:
        out.append(
            f"| {entry.get('round')} | {entry.get('new_assets')} | "
            f"{entry.get('frontier_assets')} | "
            f"{', '.join(entry.get('stages') or []) or '-'} | "
            f"{entry.get('stages_failed')} | {entry.get('seconds')} |"
        )
    out.append("")
    ledger = payload.get("ledger") or {}
    out.append(
        f"Ledger: `{ledger.get('path')}` — {ledger.get('assets_seen', 0)} asset(s) "
        "seen this engagement. A token seen in any round is never counted as new "
        "again, which is what makes an oscillating frontier stop instead of spin."
    )
    out.append("")
    if payload.get("receipt"):
        out.append(
            f"Scan receipt: `{payload['receipt']}` — every address the port stage "
            "actually attempted, with the outcome. An address in it is not scanned "
            "again in this engagement, which is why the rounds after the first get "
            "cheaper; a *failed* attempt is deliberately not a skip."
        )
        out.append("")
    rounds_with_notes = [
        (entry.get("round"), entry.get("notes")) 
        for entry in payload.get("rounds") or []
        if entry.get("notes")
    ]
    if rounds_with_notes:
        for number, notes in rounds_with_notes:
            out.append(f"- round {number}: {'; '.join(notes)}")
        out.append("")
    return "\n".join(out) + "\n"


def assemble(apex: str, *, ran_subdomain: bool, ran_ports: bool, ran_url: bool,
             ran_asn: bool, ran_cloud: bool,
             sub_log: Path, port_log: Path, url_log: Path, asn_log: Path,
             cloud_log: Path,
             convergence: dict | None = None,
             sdw_before: dict[str, float] | None = None,
             psh_before: dict[str, float] | None = None,
             url_before: dict[str, float] | None = None,
             asn_before: dict[str, float] | None = None,
             cloud_before: dict[str, float] | None = None) -> Path:
    """Write the combined report: computed summary + this-run artifacts + logs.

    ``*_before`` are the mtime snapshots taken *before* the stages ran; a file
    whose mtime did not move was not written by this run and is embedded only as
    a named stale marker, never as evidence.
    """
    sdw_before = sdw_before if sdw_before is not None else _mtimes(SDW_DIR)
    psh_before = psh_before if psh_before is not None else _mtimes(PSH_DIR)
    url_before = url_before if url_before is not None else _mtimes(URL_DIR)
    asn_before = asn_before if asn_before is not None else _mtimes(ASN_DIR)
    cloud_before = cloud_before if cloud_before is not None else _mtimes(CLOUD_DIR)

    def fresh(directory: Path, before: dict[str, float], relative: str) -> bool:
        """True when the artifact is new or was rewritten after the snapshot."""
        path = directory / relative
        if not path.is_file():
            return False
        mtime = path.stat().st_mtime
        baseline = before.get(relative)
        return baseline is None or mtime > baseline

    sdw_report = _read_json(SDW_DIR / "output/summary.json") if ran_subdomain else {}
    psh_report = _read_json(PSH_DIR / "output/report.json") if ran_ports else {}
    url_report = _read_json(URL_DIR / "output/summary.json") if ran_url else {}
    asn_report = _read_json(ASN_DIR / "output/report.json") if ran_asn else {}
    cloud_report = _read_json(CLOUD_DIR / "output/summary.json") if ran_cloud else {}

    # The summary is only as fresh as the machine report it was read from.  When
    # a stage was asked to run but did not rewrite its report (a crash before the
    # write, a preflight abort), the summary below would otherwise describe a
    # PREVIOUS run without saying so — the same failure the artifact guard
    # exists to prevent, one level up.  Stale reports are shown, but labelled.
    warnings: list[str] = []
    if ran_subdomain and sdw_report and not fresh(
        SDW_DIR, sdw_before or {}, "output/summary.json"
    ):
        warnings.append(
            "pipeline 1 did not rewrite its summary this run - "
            "the figures below describe a previous run"
        )
    if ran_ports and psh_report and not fresh(
        PSH_DIR, psh_before or {}, "output/report.json"
    ):
        warnings.append(
            "pipeline 2 did not rewrite its report this run - "
            "the figures below describe a previous run"
        )
    if ran_url and url_report and not fresh(
        URL_DIR, url_before or {}, "output/summary.json"
    ):
        warnings.append(
            "pipeline 3 did not rewrite its summary this run - "
            "the figures below describe a previous run"
        )
    if ran_asn and asn_report and not fresh(
        ASN_DIR, asn_before or {}, "output/report.json"
    ):
        warnings.append(
            "pipeline 4 did not rewrite its report this run - "
            "the figures below describe a previous run"
        )
    if ran_cloud and cloud_report and not fresh(
        CLOUD_DIR, cloud_before or {}, "output/summary.json"
    ):
        warnings.append(
            "pipeline 5 did not rewrite its summary this run - "
            "the figures below describe a previous run"
        )

    parts: list[str] = [
        _summary_section(sdw_report, psh_report, url_report, asn_report, cloud_report, apex, warnings),
        _convergence_section(convergence),
    ]

    if ran_subdomain:
        parts.append("---\n\n## Verbatim artifacts — subdomain_domain_wildcards\n")
        stale_sdw: list[str] = []
        for relative in SDW_ARTIFACTS:
            path = SDW_DIR / relative
            if path.is_file() and not fresh(SDW_DIR, sdw_before, relative):
                stale_sdw.append(relative)
                parts.append(_fence(path, relative, stale=True))
            else:
                parts.append(_fence(path, relative, stale=False))
        if stale_sdw:
            parts.append(f"\n_Stale artifacts excluded from embedding: {', '.join(stale_sdw)}_\n")

    if ran_ports:
        parts.append("---\n\n## Verbatim artifacts — port_service_host\n")
        stale_psh: list[str] = []
        psh_items = list(PSH_ARTIFACTS) + sorted(
            p.relative_to(PSH_DIR).as_posix()
            for p in (PSH_DIR / "output").glob("nmap-*.xml")
        )
        seen: set[str] = set()
        for relative in psh_items:
            if relative in seen:
                continue
            seen.add(relative)
            path = PSH_DIR / relative
            if path.is_file() and not fresh(PSH_DIR, psh_before, relative):
                stale_psh.append(relative)
                parts.append(_fence(path, relative, stale=True))
            else:
                parts.append(_fence(path, relative, stale=False))
        if stale_psh:
            parts.append(f"\n_Stale artifacts excluded from embedding: {', '.join(stale_psh)}_\n")

    if ran_url:
        parts.append("---\n\n## Verbatim artifacts — url_endpoint\n")
        stale_url: list[str] = []
        for relative in URL_ARTIFACTS:
            path = URL_DIR / relative
            if path.is_file() and not fresh(URL_DIR, url_before, relative):
                stale_url.append(relative)
                parts.append(_fence(path, relative, stale=True))
            else:
                parts.append(_fence(path, relative, stale=False))
        if stale_url:
            parts.append(f"\n_Stale artifacts excluded from embedding: {', '.join(stale_url)}_\n")

    if ran_asn:
        parts.append("---\n\n## Verbatim artifacts — asn_cidr\n")
        stale_asn: list[str] = []
        for relative in ASN_ARTIFACTS:
            path = ASN_DIR / relative
            if path.is_file() and not fresh(ASN_DIR, asn_before, relative):
                stale_asn.append(relative)
                parts.append(_fence(path, relative, stale=True))
            else:
                parts.append(_fence(path, relative, stale=False))
        if stale_asn:
            parts.append(f"\n_Stale artifacts excluded from embedding: {', '.join(stale_asn)}_\n")

    if ran_cloud:
        parts.append("---\n\n## Verbatim artifacts — cloud_resource\n")
        stale_cloud: list[str] = []
        for relative in CLOUD_ARTIFACTS:
            path = CLOUD_DIR / relative
            if path.is_file() and not fresh(CLOUD_DIR, cloud_before, relative):
                stale_cloud.append(relative)
                parts.append(_fence(path, relative, stale=True))
            else:
                parts.append(_fence(path, relative, stale=False))
        if stale_cloud:
            parts.append(f"\n_Stale artifacts excluded from embedding: {', '.join(stale_cloud)}_\n")

    parts.append("---\n\n## Console logs\n")
    if ran_subdomain:
        parts.append(_fence(sub_log, sub_log.name, stale=False))
    if ran_ports:
        parts.append(_fence(port_log, port_log.name, stale=False))
    if ran_url:
        parts.append(_fence(url_log, url_log.name, stale=False))
    if ran_asn:
        parts.append(_fence(asn_log, asn_log.name, stale=False))
    if ran_cloud:
        parts.append(_fence(cloud_log, cloud_log.name, stale=False))

    report_path = ROOT / f"RECON_{apex}_OUTPUT.md"
    report_path.write_text("".join(parts), encoding="utf-8", newline="\n")
    return report_path


def _configure_console() -> None:
    """Make this process's own stdout UTF-8, so redirected logs are too.

    A tool that prints an em dash is decoded correctly as UTF-8 and then re-encoded
    for the console; on Windows the locale code page decides that re-encoding, which
    left the engagement log a cp1252 file that every tool downstream treats as
    binary (``grep`` calls it out, and a reader on another machine gets mojibake).
    Anything the console genuinely cannot show is still degraded rather than fatal.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue  # a test double or a closed pipe, not a text stream
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass


def main(argv: list[str] | None = None) -> int:
    _configure_console()
    parser = argparse.ArgumentParser(
        prog="run_recon.py",
        description="Run every recon pipeline and write a combined report to the project root.",
    )
    parser.add_argument("-t", "--target", help="apex domain (default: TARGET from .env)")
    parser.add_argument("--stages", default="passive,active,permutation",
                        help="subdomain stages to run (forwarded to the orchestrator)")
    parser.add_argument("--skip-subdomain", action="store_true", help="skip pipeline 1")
    parser.add_argument("--skip-ports", action="store_true", help="skip pipeline 2")
    parser.add_argument("--skip-url", action="store_true", help="skip pipeline 3")
    parser.add_argument("--skip-asn", action="store_true", help="skip pipeline 4 (ASN/CIDR discovery)")
    parser.add_argument("--skip-cloud", action="store_true", help="skip pipeline 5 (cloud buckets)")
    parser.add_argument(
        "--until-converged", action="store_true",
        help=(
            "keep running rounds until the discovery frontier stops growing (or a "
            "budget says stop); later rounds re-run only the stages a new asset can "
            "change the answer for"
        ),
    )
    parser.add_argument("--max-rounds", type=int, default=None,
                        help="round ceiling for --until-converged (default 4)")
    parser.add_argument("--time-budget", type=float, default=None,
                        help="seconds allowed for the whole converged run "
                             "(default 2700; 0 = no limit)")
    parser.add_argument("--max-active-actions", type=int, default=None,
                        help="cumulative active actions across all rounds (0 = unlimited)")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging in every stage")
    args = parser.parse_args(argv)

    if args.target:
        apex = args.target.strip().lower().rstrip(".")
    else:
        try:
            sys.path.insert(0, str(ROOT))
            from service.recon_pipeline.platform.common.config import TARGET
        except Exception as exc:  # pragma: no cover - only without .env
            parser.error(f"-t/--target is required when TARGET is unset ({exc})")
        apex = str(TARGET).strip().lower().rstrip(".")
    if not apex:
        parser.error("no target: pass -t or set TARGET in .env")

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    sub_log = ROOT / f"recon_{apex}_subdomain_{stamp}.log"
    port_log = ROOT / f"recon_{apex}_ports_{stamp}.log"
    url_log = ROOT / f"recon_{apex}_url_{stamp}.log"
    asn_log = ROOT / f"recon_{apex}_asn_{stamp}.log"
    cloud_log = ROOT / f"recon_{apex}_cloud_{stamp}.log"

    exit_codes: list[int] = []
    ran_subdomain = not args.skip_subdomain
    ran_ports = not args.skip_ports
    ran_url = not args.skip_url
    ran_asn = not args.skip_asn
    ran_cloud = not args.skip_cloud

    # Snapshot the output trees BEFORE the stages run: the stale-artifact guard
    # is "did this file's mtime move during the run", which needs a baseline.
    sdw_before = _mtimes(SDW_DIR) if ran_subdomain else None
    psh_before = _mtimes(PSH_DIR) if ran_ports else None
    url_before = _mtimes(URL_DIR) if ran_url else None
    asn_before = _mtimes(ASN_DIR) if ran_asn else None
    cloud_before = _mtimes(CLOUD_DIR) if ran_cloud else None

    # Round 1's jobs, in the order the docstring argues for: names, then ports
    # (its address source), then URLs, then ASN/CIDR (seeded *by* the ports stage),
    # then buckets (seeded by the names and URL artifacts).
    first_round_jobs: list[tuple[str, list[str], Path]] = []
    if ran_subdomain:
        command = [sys.executable, "-u", "-m", SDW_MODULE, "-t", apex,
                   "--stages", args.stages]
        if args.verbose:
            command.append("-v")
        first_round_jobs.append(("names", command, sub_log))
    if ran_ports:
        command = [sys.executable, "-u", "-m", PSH_MODULE, "-t", apex]
        if args.verbose:
            command.append("-v")
        first_round_jobs.append(("ports", command, port_log))
    if ran_url:
        command = [sys.executable, "-u", "-m", URL_MODULE, "-t", apex]
        if args.verbose:
            command.append("-v")
        first_round_jobs.append(("url", command, url_log))
    if ran_asn:
        command = [sys.executable, "-u", "-m", ASN_MODULE, "-t", apex]
        if args.verbose:
            command.append("-v")
        first_round_jobs.append(("asn", command, asn_log))
    if ran_cloud:
        command = [sys.executable, "-u", "-m", CLOUD_MODULE, "-t", apex]
        if args.verbose:
            command.append("-v")
        first_round_jobs.append(("cloud", command, cloud_log))

    convergence: dict = {}
    if args.until_converged:
        from service.recon_pipeline.platform.convergence import StopPolicy

        policy = StopPolicy()
        if args.max_rounds is not None:
            policy.max_rounds = max(1, args.max_rounds)
        if args.time_budget is not None:
            policy.time_budget_seconds = max(0.0, args.time_budget)
        if args.max_active_actions is not None:
            policy.max_active_actions = max(0, args.max_active_actions)
        convergence, round_codes = _run_converged(
            apex, first_round_jobs, stamp=stamp, verbose=args.verbose, policy=policy
        )
        exit_codes.extend(round_codes)
    else:
        for _label, command, log_path in first_round_jobs:
            exit_codes.append(_run_streamed(command, log_path))

    report_path = assemble(
        apex, ran_subdomain=ran_subdomain, ran_ports=ran_ports, ran_url=ran_url,
        ran_asn=ran_asn, ran_cloud=ran_cloud,
        sub_log=sub_log, port_log=port_log, url_log=url_log, asn_log=asn_log,
        cloud_log=cloud_log,
        convergence=convergence,
        sdw_before=sdw_before, psh_before=psh_before, url_before=url_before,
        asn_before=asn_before, cloud_before=cloud_before,
    )
    print(f"\n[run_recon] combined report: {report_path}")
    return 0 if all(code == 0 for code in exit_codes) else 1


if __name__ == "__main__":
    raise SystemExit(main())
