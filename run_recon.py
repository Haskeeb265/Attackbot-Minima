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


def _run_streamed(command: list[str], log_path: Path) -> int:
    """Run *command*, teeing stdout+stderr to the console and *log_path*.

    The child is invoked with ``-u`` (unbuffered).  Without it Python block-buffers
    stdout when it is a pipe, so a long stage's log stays empty for minutes and an
    interrupted run leaves a zero-byte log — measured here: a full three-pipeline
    run killed after 10 minutes had written nothing to the subdomain log even
    though that stage had been running the whole time.
    """
    print(f"[run_recon] $ {' '.join(command)}", flush=True)
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
        )
        assert process.stdout is not None
        for line in process.stdout:
            log.write(line)
            sys.stdout.write(line)
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


def assemble(apex: str, *, ran_subdomain: bool, ran_ports: bool, ran_url: bool,
             ran_asn: bool, ran_cloud: bool,
             sub_log: Path, port_log: Path, url_log: Path, asn_log: Path,
             cloud_log: Path,
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
        _summary_section(sdw_report, psh_report, url_report, asn_report, cloud_report, apex, warnings)
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


def main(argv: list[str] | None = None) -> int:
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

    if ran_subdomain:
        command = [sys.executable, "-u", "-m", SDW_MODULE, "-t", apex,
                   "--stages", args.stages]
        if args.verbose:
            command.append("-v")
        exit_codes.append(_run_streamed(command, sub_log))
    if ran_ports:
        command = [sys.executable, "-u", "-m", PSH_MODULE, "-t", apex]
        if args.verbose:
            command.append("-v")
        exit_codes.append(_run_streamed(command, port_log))
    if ran_url:
        command = [sys.executable, "-u", "-m", URL_MODULE, "-t", apex]
        if args.verbose:
            command.append("-v")
        exit_codes.append(_run_streamed(command, url_log))
    if ran_asn:
        # After pipeline 2 deliberately: sibling addresses are this pipeline's
        # seeds and annotation input.
        command = [sys.executable, "-u", "-m", ASN_MODULE, "-t", apex]
        if args.verbose:
            command.append("-v")
        exit_codes.append(_run_streamed(command, asn_log))
    if ran_cloud:
        # Last deliberately: the URL and names artifacts are this pipeline's
        # seed material (CNAMEs, JS hosts, brand tokens).
        command = [sys.executable, "-u", "-m", CLOUD_MODULE, "-t", apex]
        if args.verbose:
            command.append("-v")
        exit_codes.append(_run_streamed(command, cloud_log))

    report_path = assemble(
        apex, ran_subdomain=ran_subdomain, ran_ports=ran_ports, ran_url=ran_url,
        ran_asn=ran_asn, ran_cloud=ran_cloud,
        sub_log=sub_log, port_log=port_log, url_log=url_log, asn_log=asn_log,
        cloud_log=cloud_log,
        sdw_before=sdw_before, psh_before=psh_before, url_before=url_before,
        asn_before=asn_before, cloud_before=cloud_before,
    )
    print(f"\n[run_recon] combined report: {report_path}")
    return 0 if all(code == 0 for code in exit_codes) else 1


if __name__ == "__main__":
    raise SystemExit(main())
