#!/usr/bin/env python3
"""Run the subdomain and ports/services pipelines against one target and write
one combined report at the project root.

What it does, in order:

1. runs ``subdomain_domain_wildcards`` (passive -> active -> permutation), whose
   ``active/output/records.jsonl`` is the address source for the port stage;
2. runs ``port_service_host`` against the same target;
3. assembles ``RECON_<target>_OUTPUT.md`` at the project root: a data-driven
   summary (read from the stages' machine reports, never hand-written) followed
   by every curated artifact verbatim, then both console logs.

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
    python run_recon.py -t example.com --skip-subdomain              # ports only
    python run_recon.py -t example.com --skip-ports                  # subdomains only

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

SDW_MODULE = "service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.main"
PSH_MODULE = "service.recon_pipeline.asset_pipelines.port_service_host.pipeline"

SDW_DIR = ROOT / "service/recon_pipeline/asset_pipelines/subdomain_domain_wildcards"
PSH_DIR = ROOT / "service/recon_pipeline/asset_pipelines/port_service_host"

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
    """Run *command*, teeing stdout+stderr to the console and *log_path*."""
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


def _summary_section(sdw_report: dict, psh_report: dict, apex: str,
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

    if not sdw_report and not psh_report:
        out.append("_Neither stage produced a readable report — see the logs below._")
        out.append("")
    return "\n".join(out) + "\n"


def assemble(apex: str, *, ran_subdomain: bool, ran_ports: bool,
             sub_log: Path, port_log: Path,
             sdw_before: dict[str, float] | None = None,
             psh_before: dict[str, float] | None = None) -> Path:
    """Write the combined report: computed summary + this-run artifacts + logs.

    ``*_before`` are the mtime snapshots taken *before* the stages ran; a file
    whose mtime did not move was not written by this run and is embedded only as
    a named stale marker, never as evidence.
    """
    sdw_before = sdw_before if sdw_before is not None else _mtimes(SDW_DIR)
    psh_before = psh_before if psh_before is not None else _mtimes(PSH_DIR)

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

    parts: list[str] = [_summary_section(sdw_report, psh_report, apex, warnings)]

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

    parts.append("---\n\n## Console logs\n")
    if ran_subdomain:
        parts.append(_fence(sub_log, sub_log.name, stale=False))
    if ran_ports:
        parts.append(_fence(port_log, port_log.name, stale=False))

    report_path = ROOT / f"RECON_{apex}_OUTPUT.md"
    report_path.write_text("".join(parts), encoding="utf-8", newline="\n")
    return report_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="run_recon.py",
        description="Run both recon pipelines and write a combined report to the project root.",
    )
    parser.add_argument("-t", "--target", help="apex domain (default: TARGET from .env)")
    parser.add_argument("--stages", default="passive,active,permutation",
                        help="subdomain stages to run (forwarded to the orchestrator)")
    parser.add_argument("--skip-subdomain", action="store_true", help="skip pipeline 1")
    parser.add_argument("--skip-ports", action="store_true", help="skip pipeline 2")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging in both stages")
    args = parser.parse_args(argv)

    if args.target:
        apex = args.target.strip().lower().rstrip(".")
    else:
        try:
            sys.path.insert(0, str(ROOT))
            from service.recon_pipeline.asset_pipelines.config import TARGET
        except Exception as exc:  # pragma: no cover - only without .env
            parser.error(f"-t/--target is required when TARGET is unset ({exc})")
        apex = str(TARGET).strip().lower().rstrip(".")
    if not apex:
        parser.error("no target: pass -t or set TARGET in .env")

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    sub_log = ROOT / f"recon_{apex}_subdomain_{stamp}.log"
    port_log = ROOT / f"recon_{apex}_ports_{stamp}.log"

    exit_codes: list[int] = []
    ran_subdomain = not args.skip_subdomain
    ran_ports = not args.skip_ports

    # Snapshot the output trees BEFORE the stages run: the stale-artifact guard
    # is "did this file's mtime move during the run", which needs a baseline.
    sdw_before = _mtimes(SDW_DIR) if ran_subdomain else None
    psh_before = _mtimes(PSH_DIR) if ran_ports else None

    if ran_subdomain:
        command = [sys.executable, "-m", SDW_MODULE, "-t", apex,
                   "--stages", args.stages]
        if args.verbose:
            command.append("-v")
        exit_codes.append(_run_streamed(command, sub_log))
    if ran_ports:
        command = [sys.executable, "-m", PSH_MODULE, "-t", apex]
        if args.verbose:
            command.append("-v")
        exit_codes.append(_run_streamed(command, port_log))

    report_path = assemble(
        apex, ran_subdomain=ran_subdomain, ran_ports=ran_ports,
        sub_log=sub_log, port_log=port_log,
        sdw_before=sdw_before, psh_before=psh_before,
    )
    print(f"\n[run_recon] combined report: {report_path}")
    return 0 if all(code == 0 for code in exit_codes) else 1


if __name__ == "__main__":
    raise SystemExit(main())
