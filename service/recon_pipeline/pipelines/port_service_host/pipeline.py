"""
End-to-end runner for the ports / services / hosts stage.

The stage answers one question — *what is listening, on which address, speaking
what protocol* — and this module owns the order in which that happens::

    build seeds (DNS records + declared scope)
      -> passive intel (InternetDB) + ownership (RDAP/Cymru) + reverse DNS
      -> classify (cdn / dedicated / unknown)
      -> scan ladder (L1 skip | L2 top-N | L2b CDN web probe | L3 full)
      -> service identification on open non-HTTP ports
      -> write output/

Output contract (everything lands in ``port_service_host/output/``)
------------------------------------------------------------------
============================ ================================================
``ips_raw.txt``              the scan set: canonical, deduplicated, scoped
``passive_intel.jsonl``      per-address passive ports/hostnames/tags/vulns,
                             each with its source and its age
``ownership.jsonl``          per-address ASN, prefix, org, registry, country
``cdn_classified.jsonl``     per-address verdict + the evidence for it
``openports.jsonl``          one line per open socket, with scan mode and source
``services.jsonl``           what is listening there, with TLS when present
``hosts.txt``                unique addresses that produced anything (v4 then v6)
``report.json``              counts, ladder decisions, budgets, aborts, failures
``<tool>.log`` / ``.jsonl``  raw tool output, when something looks wrong
============================ ================================================

Design properties worth stating, because they are enforced in code rather than
documented and hoped for:

* **Nothing is scanned that has not earned it.**  The ladder decides per address,
  CDN/WAF addresses are never port-scanned, and the report records every rung
  including the ones that sent no packet — so "found nothing" and "never looked"
  can never be confused (the design's D3 and D6).
* **Passive intel always runs first, and survives failure.**  The intel and
  ownership sources are keyless HTTP and need no Docker, so a missing image or a
  refused SYN scan degrades the run instead of losing the passive result (D1).
* **Passive-only is a real mode, not an error.**  A quarantine carried over from
  a previous run, or ``PSH_SCAN_LEVEL=passive``, drops every address to the
  passive rung; the artifacts are still produced and the report says why.
* **A failing step degrades; a failed seed does not.**  Every tool failure is
  recorded per step and the run continues, because a partially scanned estate is
  still useful.  But no seed at all is a clean, explained empty run rather than a
  crash.
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import shared.colorlog as colorlog

from service.recon_pipeline.platform.common.config import TARGET

from ...platform.stealth.session import StealthConfig, StealthSession
from service.recon_pipeline.platform import escalation
from service.recon_pipeline.platform.common.normalize import canonicalize_host
from service.recon_pipeline.platform.receipt import (
    OUTCOME_FAILED,
    OUTCOME_FOUND,
    OUTCOME_NONE,
    Receipt,
    asset_token,
)
from . import seed_builder
from .active import ladder, naabu, nmap, tools, webprobe
from .classify import cdn
from .normalize import (
    MergedPorts,
    PortObservation,
    ServiceObservation,
    dedupe_addresses,
    write_jsonl,
    write_lines,
)
from .passive import internetdb, rdap
from .passive import ptr as ptr_mod
from .settings import (
    attempt_receipt_path,
    CDN_PROBE,
    DEFAULT_SOURCE_TIMEOUT,
    ESCALATE,
    ESCALATE_MAX,
    HTTP_RATE_LIMIT,
    HTTP_THREADS,
    INTEL_ENABLED,
    INTEL_MAX_AGE_DAYS,
    INTEL_TIMEOUT,
    INTERNETDB_REFRESH_DAYS,
    MAX_IPS,
    MAX_RATE,
    NMAP_ENABLED,
    NMAP_MAX_RATE,
    NMAP_VERSION_LIGHT,
    OUTPUT_DIR,
    PASSIVE_ONLY,
    PTR_ENABLED,
    QUARANTINE_FILE,
    RDAP_ENABLED,
    RESOLVE_UNCOVERED,
    RETRIES,
    SCAN_LEVEL,
    SCAN_LEVEL_PASSIVE,
    SCAN_TYPE,
    SCOPE_FILES,
    STEALTH_ENABLED,
    TLS_CERTS,
    TOP_PORTS,
)

log = logging.getLogger("psh.pipeline")

# Derived output file names (see the module docstring's output contract).
REPORT_FILE = "report.json"
HOSTS_FILE = "hosts.txt"
OPENPORTS_FILE = "openports.jsonl"
SERVICES_FILE = "services.jsonl"
CDN_FILE = "cdn_classified.jsonl"
INTEL_FILE = "passive_intel.jsonl"
OWNERSHIP_FILE = "ownership.jsonl"


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #


@dataclass
class PshReport:
    """Machine-readable summary of one ports/services/hosts run."""

    target: str
    started_at: str
    run_mode: str = "active"
    finished_at: str = ""
    seconds: float = 0.0
    ok: bool = True
    fatal: str | None = None
    #: Set when the stage image could not be used.  Scanning is then unavailable
    #: but the passive layer still ran, which is a degradation, not an abort.
    docker_error: str | None = None
    seeds: dict[str, object] = field(default_factory=dict)
    intel: dict[str, object] = field(default_factory=dict)
    ownership: dict[str, object] = field(default_factory=dict)
    reverse_dns: dict[str, object] = field(default_factory=dict)
    classification: dict[str, object] = field(default_factory=dict)
    ladder: dict[str, object] = field(default_factory=dict)
    scans: list[dict[str, object]] = field(default_factory=list)
    services: dict[str, object] = field(default_factory=dict)
    stealth: dict[str, object] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)
    outputs: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(self.__dict__, indent=2, sort_keys=False)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _write_json(path: Path, report: PshReport) -> Path:
    """Persist the run report as JSON (atomic replace)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(report.to_json(), encoding="utf-8", newline="\n")
    tmp.replace(path)
    return path


# --------------------------------------------------------------------------- #
# Stage
# --------------------------------------------------------------------------- #


def run_port_service_host_stage(
    target: str = TARGET,
    *,
    # -- seeds ------------------------------------------------------------- #
    records_file: Path | str | None = seed_builder.ACTIVE_RECORDS_FILE,
    host_files: Sequence[Path | str] = (),
    scope_files: Iterable[Path | str] = (),
    addresses: Iterable[str] = (),
    max_ips: int = MAX_IPS,
    resolve_uncovered: bool = RESOLVE_UNCOVERED,
    # -- layers ------------------------------------------------------------ #
    intel: bool = INTEL_ENABLED,
    ownership: bool = RDAP_ENABLED,
    reverse_dns: bool = PTR_ENABLED,
    classify: bool = True,
    services: bool = NMAP_ENABLED,
    scan_level: str = SCAN_LEVEL,
    cdn_probe: bool = CDN_PROBE,
    escalate: bool = ESCALATE,
    escalate_max: int = ESCALATE_MAX,
    # -- knobs ------------------------------------------------------------- #
    rate: int = MAX_RATE,
    retries: int = RETRIES,
    scan_type: str = SCAN_TYPE,
    top_ports: str = TOP_PORTS,
    intel_max_age_days: int = INTEL_MAX_AGE_DAYS,
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
    output_dir: Path | str = OUTPUT_DIR,
    resolvers: Path | str | None = seed_builder.ACTIVE_RESOLVERS_FILE,
    # -- injected seams (tests) -------------------------------------------- #
    session: StealthSession | None = None,
    stealth: bool = STEALTH_ENABLED,
    intel_fetcher: Callable[..., internetdb.IpIntel] = internetdb.fetch_ip,
    ownership_fetcher: Callable[..., rdap.IpOwnership] = rdap.fetch_ip,
    ptr_lookup: Callable[..., ptr_mod.PtrResult] = ptr_mod.lookup,
    port_scanner: Callable[..., naabu.ScanOutcome] = naabu.scan,
    service_scanner: Callable[..., nmap.ServiceOutcome] = nmap.scan,
    web_prober: Callable[..., webprobe.ProbeOutcome] = webprobe.probe,
    image_check: Callable[..., None] = tools.ensure_image,
    tool_runner: Callable[..., object] | None = None,
) -> PshReport:
    """Run the stage for *target* and write its outputs.

    Parameters
    ----------
    target:
        Apex domain.  Used for scope labelling and the report only — the addresses
        come from the DNS stage's records and from the declared scope.
    records_file / host_files / scope_files / addresses:
        Seed sources.  ``records_file`` is the sibling active stage's
        ``records.jsonl`` (the real source of addresses); ``scope_files`` is the
        only input that grants network reach beyond our own resolved hosts.
    intel / ownership / reverse_dns / classify / services:
        Which layers run.  Each is independently switchable so a partial run is
        possible without patching code.
    scan_level:
        ``passive`` | ``l2`` | ``full``.  A quarantine, ``PASSIVE_ONLY`` or the
        stealth layer's own degradation can force ``passive`` regardless.
    escalate / escalate_max:
        Whether (and how many) L2 addresses that showed an open port are promoted
        to a full-range scan.
    session / stealth:
        An explicit :class:`StealthSession`, or whether to build one.

    The remaining keyword arguments are injection points: every tool wrapper and
    every network-backed lookup can be replaced, which is how the whole stage is
    tested without Docker, DNS or HTTP.

    Returns
    -------
    PshReport
        Also written to ``output/report.json``.
    """
    apex = canonicalize_host(target)
    if apex is None:
        raise ValueError(
            f"target {target!r} is not a valid domain (expected e.g. 'example.com')"
        )

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    report = PshReport(target=apex, started_at=_utc_now())

    def finish() -> PshReport:
        report.finished_at = _utc_now()
        report.seconds = time.monotonic() - started
        if session is not None:
            # Persist quarantine state and record how the run presented itself
            # before the report is serialised, so the report describes the run's
            # final stealth state rather than a stale snapshot.
            report.stealth = session.to_dict()
            session.save()
        report.outputs["report"] = _write_json(output_dir / REPORT_FILE, report).as_posix()
        _log_summary(report)
        return report

    # 1. Stealth layer.  Built first so a quarantine — including one carried over
    #    from a previous run — can downgrade the plan *before* a tool is touched.
    #    This stage never refuses to run in passive-only mode: the passive layer
    #    is genuinely useful on its own, so the correct response is to drop to the
    #    passive rung and say why (design §10.4).
    if session is None and stealth:
        session = StealthSession(
            StealthConfig.from_settings(
                quarantine_path=QUARANTINE_FILE,
                passive_only=PASSIVE_ONLY,
            )
        )

    passive_reason: str | None = None
    if session is not None and session.passive_only:
        passive_reason = (
            "passive-only mode is active (PASSIVE_ONLY, or a WAF quarantine carried "
            "over from a previous run): the active layer will not run"
        )
        log.warning("stealth: %s", passive_reason)
    elif scan_level == SCAN_LEVEL_PASSIVE:
        passive_reason = "scan level 'passive' was requested"

    # 2. The stage's tools live in a locally built image, so the check happens
    #    before any work.  A missing image costs the *active* layers only: the
    #    passive layer needs no Docker and still runs.
    docker_error: str | None = None
    if not passive_reason or reverse_dns or resolve_uncovered:
        try:
            image_check()
        except Exception as exc:  # ToolImageMissingError, DockerUnavailableError, ...
            docker_error = str(exc)
            report.docker_error = docker_error
            report.ok = False
            log.error("%s", docker_error)

    if docker_error is not None:
        passive_reason = passive_reason or (
            "the stage's tool image is unavailable, so no tool can run: "
            "scanning, probing and service identification are skipped"
        )
        # Reverse DNS and the address-gap fill are Docker steps too.
        reverse_dns = False
        resolve_uncovered = False
        services = False

    effective_level = SCAN_LEVEL_PASSIVE if passive_reason else scan_level
    report.run_mode = "passive" if passive_reason else "active"

    # 3. Seeds.
    seeds = seed_builder.build(
        target=apex,
        records_file=records_file,
        host_files=tuple(host_files)
        or (seed_builder.ACTIVE_RESOLVED_FILE, seed_builder.LIVE_HOSTS_FILE),
        scope_files=tuple(scope_files) or tuple(SCOPE_FILES),
        extra_addresses=addresses,
        max_ips=max_ips,
        output_dir=output_dir,
        resolve_uncovered=resolve_uncovered,
        resolve_timeout=timeout,
        resolvers=resolvers,
        run=tool_runner,
    )
    report.seeds = dict(seeds.to_dict(), refused_reasons=seed_builder.refused_report(seeds))
    report.outputs["ips_raw"] = seed_builder.write_seeds(output_dir, seeds).as_posix()

    if not seeds.addresses:
        report.fatal = (
            "no scan-eligible address: the DNS records and the declared scope "
            "produced nothing (run the subdomain stage first, or pass --scope)"
        )
        report.counts = _counts(report, seeds, (), (), ())
        return finish()

    # ---- 4. Passive layer: no packet is sent at any address in this section ---
    intel_records: dict[str, internetdb.IpIntel] = {}
    if intel:
        records = [
            intel_fetcher(address, timeout=INTEL_TIMEOUT, refresh_days=INTERNETDB_REFRESH_DAYS)
            for address in seeds.addresses
        ]
        intel_records = {record.ip: record for record in records}
        report.intel = internetdb.summarise(records)
        stale = sorted(record.ip for record in records if record.is_stale(intel_max_age_days))
        report.intel["stale"] = stale
        if stale:
            log.warning(
                "%d passive intel record(s) are past the %d-day freshness limit; they "
                "may seed the ladder but are not reported as current state",
                len(stale),
                intel_max_age_days,
            )
        report.outputs["passive_intel"] = write_jsonl(
            output_dir / INTEL_FILE, (record.to_dict() for record in records)
        ).as_posix()

    ownership_records: dict[str, rdap.IpOwnership] = {}
    if ownership:
        owned = [ownership_fetcher(address, timeout=INTEL_TIMEOUT) for address in seeds.addresses]
        ownership_records = {record.ip: record for record in owned}
        report.ownership = rdap.summarise(owned)
        report.outputs["ownership"] = write_jsonl(
            output_dir / OWNERSHIP_FILE, (record.to_dict() for record in owned)
        ).as_posix()

    ptr_names: dict[str, list[str]] = {}
    if reverse_dns:
        ptr_result = ptr_lookup(
            seeds.addresses,
            output_dir=output_dir,
            timeout=timeout,
            resolvers=resolvers,
            run=tool_runner,
        )
        report.reverse_dns = ptr_mod.summarise(ptr_result)
        ptr_names = dict(ptr_result.names)
        if not ptr_result.ok:
            report.ok = False
            report.reverse_dns["error"] = ptr_result.error

    # ---- 5. Classification ---------------------------------------------------
    # "In scope" means one of the target's own names resolves here, which is the
    # evidence that separates ``dedicated`` from ``unknown``.  Declared scope is a
    # legal claim, not a technical one, and is handled separately by the ladder.
    in_scope = {address for address, names in seeds.names_by_ip.items() if names}
    verdicts: dict[str, cdn.CdnVerdict] = {}
    if classify:
        classified = cdn.classify_all(
            seeds.addresses,
            intel_by_ip=intel_records,
            ownership_by_ip=ownership_records,
            ptr_by_ip=ptr_names,
            cname_by_ip=seeds.cname_targets,
            in_scope=in_scope,
        )
        verdicts = {verdict.ip: verdict for verdict in classified}
        report.classification = cdn.summarise(classified)
        report.outputs["cdn_classified"] = write_jsonl(
            output_dir / CDN_FILE, (verdict.to_dict() for verdict in classified)
        ).as_posix()

    # ---- 5b. The attempt receipt ---------------------------------------------
    # An address scanned with nothing open leaves no trace in any artifact, so a
    # second pass over the same address is indistinguishable from the first —
    # which is the whole reason this stage used to pay for it twice.  The receipt
    # is the trace: ``port_scan`` on an address that answered, or errored, or had
    # nothing open.  Failed scans are deliberately *not* a skip (see
    # ``platform.receipt``): an outage is not knowledge.
    receipt = Receipt(attempt_receipt_path(output_dir))
    already_attempted = receipt.attempted_assets(escalation.OPERATION_PORT_SCAN)
    planned_addresses = [
        address
        for address in seeds.addresses
        if (asset_token(address, "ip") or address) not in already_attempted
    ]
    skipped_attempted = len(seeds.addresses) - len(planned_addresses)
    if skipped_attempted:
        log.info(
            "attempt receipt: %d of %d address(es) already scanned in this "
            "engagement, not queued again (%s)",
            skipped_attempted,
            len(seeds.addresses),
            attempt_receipt_path(output_dir),
        )

    # ---- 6. The ladder -------------------------------------------------------
    rungs = ladder.plan(
        planned_addresses,
        verdicts=verdicts,
        intel=intel_records,
        in_scope=in_scope,
        scope_declared=seeds.scope_declared,
        scan_level=effective_level,
        cdn_probe=cdn_probe,
        passive_only=bool(passive_reason),
    )
    report.ladder = ladder.summarise(rungs)
    if passive_reason:
        report.ladder["passive_reason"] = passive_reason
    log.info(
        "ladder: %s",
        {level: len(ips) for level, ips in ladder.by_level(rungs).items()},
    )

    # ---- 7. Active layer -----------------------------------------------------
    merged = MergedPorts()

    def scan_rung(
        level: str,
        ips: Sequence[str],
        *,
        ports: Sequence[int] | None = None,
        top: str | None = None,
        suffix: str = "",
    ) -> None:
        if not ips:
            return
        outcome = port_scanner(
            ips,
            ports=ports,
            top_ports=top,
            rate=rate,
            retries=retries,
            scan_type=scan_type,
            exclude_cdn=True,
            output_dir=output_dir,
            timeout=timeout,
            resolvers=resolvers,
            run=tool_runner,
            suffix=suffix,
        )
        report.scans.append(
            dict(outcome.to_dict(), level=level, addresses_requested=len(ips))
        )
        if not outcome.ok:
            report.ok = False
        merged.extend(outcome.observations)
        # Record the attempt *here*, where packets actually left, rather than from
        # the ladder: a rung is a plan, and this is the only place that knows the
        # scan really ran.  The outcome decides whether a later pass may skip it —
        # and a failed scan is recorded as such precisely so it never becomes a
        # permanent gap (see ``platform.receipt``).
        answered = {observation.ip for observation in outcome.observations}
        for address in ips:
            if not outcome.ok:
                result = OUTCOME_FAILED
            else:
                result = OUTCOME_FOUND if address in answered else OUTCOME_NONE
            receipt.record(
                asset_token(address, "ip"),
                escalation.OPERATION_PORT_SCAN,
                outcome=result,
            )

    scan_rung(ladder.RUNG_TOP, ladder.ips_for(rungs, ladder.RUNG_TOP), top=top_ports)
    scan_rung(
        ladder.RUNG_FULL,
        ladder.ips_for(rungs, ladder.RUNG_FULL),
        top=tools.TOP_PORTS_FULL,
    )

    # The CDN rung: HTTP only, and its responses feed back into quarantine.
    cdn_ips = ladder.ips_for(rungs, ladder.RUNG_CDN)
    if cdn_ips:
        probe = web_prober(
            cdn_ips,
            output_dir=output_dir,
            timeout=timeout,
            rate_limit=HTTP_RATE_LIMIT,
            threads=HTTP_THREADS,
            session=session,
            run=tool_runner,
        )
        report.scans.append(
            dict(probe.to_dict(), level=ladder.RUNG_CDN, addresses_requested=len(cdn_ips))
        )
        if not probe.ok:
            report.ok = False
        merged.extend(probe.observations)
        if probe.responses:
            report.classification["cdn_responded"] = len(probe.responses)
            # A response is fresh evidence about an address we had already
            # classified, so the verdict is re-derived with it (see the design's
            # layered-evidence principle: pre-scan naming, post-probe headers).
            refined = cdn.classify_all(
                cdn_ips,
                intel_by_ip=intel_records,
                ownership_by_ip=ownership_records,
                ptr_by_ip=ptr_names,
                cname_by_ip=seeds.cname_targets,
                headers_by_ip={
                    address: entry["headers"]
                    for address, entry in probe.responses.items()
                    if isinstance(entry.get("headers"), dict)
                },
                in_scope=in_scope,
            )
            report.classification["refined"] = {
                verdict.ip: verdict.labelled for verdict in refined if verdict.is_cdn
            }

    # Escalation: an L2 address that showed an open port earns a full-range scan.
    # Bounded by ``escalate_max`` and reported either way, because "earned" is not
    # the same as "affordable".
    escalated: list[str] = []
    if escalate and passive_reason is None:
        already_full = set(ladder.ips_for(rungs, ladder.RUNG_FULL))
        on_top_rung = {rung.ip for rung in rungs if rung.level == ladder.RUNG_TOP}
        cdn_set = set(cdn_ips)
        hosted_set = {
            ip for ip, verdict in verdicts.items() if verdict.verdict == cdn.VERDICT_HOSTED
        }
        earned = {
            observation.ip
            for observation in merged.entries
            if observation.ip in on_top_rung and observation.ip not in cdn_set
        } - already_full
        # A hosted verdict permits the top-N rung but refuses the escalation: an
        # open port on tenant infrastructure means "the platform's edge answered",
        # and the target's own server is not on the other end of those 65,535
        # probes.  Refusals are reported, not silent.
        refused_hosted = sorted(earned & hosted_set)
        if refused_hosted:
            report.ladder["escalation_refused_hosted"] = refused_hosted
            log.info(
                "%d hosted address(es) earned escalation but were held at the "
                "top-N rung: %s",
                len(refused_hosted),
                ", ".join(refused_hosted[:5]),
            )
        candidates = sorted(earned - hosted_set)
        if len(candidates) > escalate_max:
            log.warning(
                "%d address(es) earned escalation but the cap is %d - escalating %d "
                "and reporting the rest as L2 findings",
                len(candidates),
                escalate_max,
                escalate_max,
            )
            candidates = candidates[:escalate_max]
        escalated = candidates
        scan_rung(ladder.RUNG_FULL, escalated, top=tools.TOP_PORTS_FULL, suffix="escalated-")
    report.ladder["escalated"] = escalated

    # ---- 8. Service identification on open non-HTTP ports --------------------
    service_observations: list[ServiceObservation] = []
    if services and len(merged):
        groups = nmap.group_by_ports(merged.entries)
        if groups:
            outcome = service_scanner(
                groups,
                output_dir=output_dir,
                timeout=timeout,
                version_light=NMAP_VERSION_LIGHT,
                tls_certs=TLS_CERTS,
                max_rate=NMAP_MAX_RATE,
                run=tool_runner,
            )
            service_observations = list(outcome.observations)
            report.services = dict(outcome.to_dict())
            if not getattr(outcome, "ok", True):
                report.ok = False
        else:
            report.services = {"skipped": "every open port is HTTP-ish"}
    elif not services:
        report.services = {"skipped": "service identification is disabled"}
    else:
        report.services = {"skipped": "no open port was found"}

    # ---- 9. Write the artifacts ---------------------------------------------
    port_rows = merged.entries
    host_addresses, host_refused = dedupe_addresses(merged.ips())
    if host_refused:
        log.debug("hosts.txt: %d address(es) refused by the scope gate", len(host_refused))

    outputs = {
        OPENPORTS_FILE: write_jsonl(
            output_dir / OPENPORTS_FILE, (row.to_dict() for row in port_rows)
        ),
        SERVICES_FILE: write_jsonl(
            output_dir / SERVICES_FILE, (row.to_dict() for row in service_observations)
        ),
        HOSTS_FILE: write_lines(output_dir / HOSTS_FILE, host_addresses),
    }
    report.outputs.update({key: Path(path).as_posix() for key, path in outputs.items()})

    report.counts = _counts(
        report, seeds, rungs, port_rows, service_observations, skipped_attempted
    )
    report.outputs["attempt_receipt"] = attempt_receipt_path(output_dir).as_posix()
    return finish()


def _counts(
    report: PshReport,
    seeds: seed_builder.SeedSet,
    rungs: Sequence[ladder.Rung],
    ports: Sequence[PortObservation],
    services: Sequence[ServiceObservation],
    skipped_attempted: int = 0,
) -> dict[str, int]:
    """Assemble the report's count block."""
    levels = ladder.by_level(rungs) if rungs else {}
    verdicts = report.classification.get("by_verdict") or {}
    escalated = report.ladder.get("escalated") or []
    return {
        "addresses": len(seeds.addresses),
        # Addresses the receipt had already paid for, and which therefore cost
        # nothing this pass.  Reported rather than hidden: a scan set that shrank
        # for a reason is a different fact from a scan set that was always small.
        "skipped_attempted": skipped_attempted,
        "planned": len(rungs),
        "scope_declared": len(seeds.scope_declared),
        "in_scope": sum(1 for address in seeds.addresses if seeds.names_by_ip.get(address)),
        "refused": len(seeds.refused),
        "unresolved_hosts": len(seeds.unresolved_hosts),
        "intel_indexed": int(report.intel.get("indexed", 0) or 0),
        "stale_intel": len(report.intel.get("stale", []) or []),
        "ptr_named": int(report.reverse_dns.get("answered", 0) or 0),
        "cdn": int(verdicts.get(cdn.VERDICT_CDN, 0) or 0),
        "hosted": int(verdicts.get(cdn.VERDICT_HOSTED, 0) or 0),
        "dedicated": int(verdicts.get(cdn.VERDICT_DEDICATED, 0) or 0),
        "unknown": int(verdicts.get(cdn.VERDICT_UNKNOWN, 0) or 0),
        "scanned_l2": len(levels.get(ladder.RUNG_TOP, [])),
        "scanned_l3": len(levels.get(ladder.RUNG_FULL, [])),
        "cdn_probed": len(levels.get(ladder.RUNG_CDN, [])),
        "escalated": len(escalated),
        "unscanned": sum(
            len(levels.get(level, [])) for level in (ladder.RUNG_SKIP, ladder.RUNG_PASSIVE)
        ),
        "open_ports": len(ports),
        "confirmed_ports": sum(1 for row in ports if "+" in str(row.scan_mode)),
        "services": len(services),
        "hosts": len({row.ip for row in ports}),
    }


def _log_summary(report: PshReport) -> None:
    """One-screen summary of the run, for a terminal."""
    if report.fatal:
        colorlog.log.failed(f"ports/services stage for {report.target}: {report.fatal}")
        return

    counts = report.counts
    colorlog.log.info(
        f"ports/services stage for {report.target}: {counts.get('addresses', 0)} "
        f"address(es) -> {counts.get('open_ports', 0)} open port(s), "
        f"{counts.get('services', 0)} service(s) in {report.seconds:.1f}s "
        f"[cdn {counts.get('cdn', 0)}, l2 {counts.get('scanned_l2', 0)}, "
        f"l3 {counts.get('scanned_l3', 0)}, unscanned {counts.get('unscanned', 0)}]"
    )
    if report.run_mode == "passive":
        reason = (report.ladder or {}).get("passive_reason") or "passive-only"
        colorlog.log.warn(f"passive rung only - {reason}")
    if counts.get("cdn"):
        colorlog.log.info(
            f"{counts['cdn']} CDN/WAF address(es) were not port-scanned "
            f"({counts.get('cdn_probed', 0)} probed over HTTP on 80/443)"
        )
    if counts.get("hosted"):
        colorlog.log.info(
            f"{counts['hosted']} address(es) classified hosted (the target's names "
            "resolve through a third-party platform's tenant naming) - scanned at "
            "the top-N rung only, never escalated"
        )
    if counts.get("escalated"):
        colorlog.log.info(
            f"{counts['escalated']} address(es) escalated from the top-N rung to a "
            "full-range scan because the top-N scan found an open port"
        )
    if counts.get("unresolved_hosts"):
        colorlog.log.warn(
            f"{counts['unresolved_hosts']} known host(s) had no address and were not "
            "scanned - see seeds.unresolved_hosts in the report"
        )
    for entry in report.scans:
        if not entry.get("ok", True):
            colorlog.log.warn(
                f"scan {entry.get('level')} failed: "
                f"{entry.get('error') or entry.get('skipped') or 'unknown error'}"
            )
    if report.docker_error:
        colorlog.log.warn("no Docker: only the passive layer ran")
    if report.ok:
        colorlog.log.success(f"open ports written to {report.outputs.get(OPENPORTS_FILE)}")
    else:
        colorlog.log.warn(
            f"ports/services stage for {report.target} completed with failures - see "
            f"{report.outputs.get('report', REPORT_FILE)}"
        )


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m service.recon_pipeline.pipelines.port_service_host.pipeline",
        description=(
            "Collect keyless passive intel for every address the DNS stage found, "
            "classify CDN/WAF addresses, scan the rest according to the ladder, "
            "identify services, and write port_service_host/output/."
        ),
    )
    parser.add_argument("-t", "--target", default=TARGET, help=f"apex domain (default: {TARGET})")
    parser.add_argument(
        "--records",
        default=str(seed_builder.ACTIVE_RECORDS_FILE),
        help="the subdomain stage's records.jsonl (the address source)",
    )
    parser.add_argument(
        "--host-file", action="append", default=[],
        help="host list used to fill address gaps (repeatable)",
    )
    parser.add_argument(
        "--scope", action="append", default=[],
        help="declared-scope file of CIDRs/IPs (repeatable; the only input that grants "
        "reach beyond our own resolved hosts)",
    )
    parser.add_argument(
        "--address", action="append", default=[],
        help="an address to include explicitly (repeatable)",
    )
    parser.add_argument(
        "--scan-level", default=SCAN_LEVEL, choices=("passive", "l2", "full"),
        help=f"how much of the network to touch (default: {SCAN_LEVEL})",
    )
    parser.add_argument("--no-intel", action="store_true", help="skip keyless passive intel")
    parser.add_argument("--no-ownership", action="store_true", help="skip RDAP/Cymru lookups")
    parser.add_argument("--no-ptr", action="store_true", help="skip reverse DNS")
    parser.add_argument(
        "--no-resolve-uncovered", action="store_true",
        help="do not resolve hosts that have no DNS record (skips the dnsx gap fill)",
    )
    parser.add_argument("--no-services", action="store_true", help="skip nmap service identification")
    parser.add_argument("--no-cdn-probe", action="store_true", help="do not probe CDN addresses at all")
    parser.add_argument("--no-escalate", action="store_true", help="never promote L2 findings to L3")
    parser.add_argument(
        "--max-ips", type=int, default=MAX_IPS, help="cap on the scan set size (default: no cap)"
    )
    parser.add_argument(
        "--rate", type=int, default=MAX_RATE,
        help=f"packets/second for the port scan (default: {MAX_RATE})",
    )
    parser.add_argument(
        "--scan-type", default=SCAN_TYPE, choices=("auto", "syn", "connect"),
        help=f"port-scan mode (default: {SCAN_TYPE})",
    )
    parser.add_argument(
        "--resolvers", default=str(seed_builder.ACTIVE_RESOLVERS_FILE),
        help="resolver list for reverse DNS",
    )
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_SOURCE_TIMEOUT,
        help=f"per-tool timeout in seconds (default: {DEFAULT_SOURCE_TIMEOUT})",
    )
    parser.add_argument(
        "--output-dir", default=str(OUTPUT_DIR),
        help=f"output directory (default: {OUTPUT_DIR})",
    )
    parser.add_argument("--list", action="store_true", help="list tools and CDN providers, then exit")
    parser.add_argument("-v", "--verbose", action="store_true", help="show debug logging")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.  Returns a process exit code."""
    args = _build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-7s %(name)s: %(message)s",
    )

    if args.list:
        print("tools")
        print("-" * 78)
        for row in tools.describe_tools():
            print(f"  {row['name']:<8} {row['description']}")
        print("\ncdn/waf providers")
        print("-" * 78)
        for provider in cdn.PROVIDERS:
            print(f"  {provider.key:<12} {provider.label}")
        table = cdn.load_ranges()
        print(f"\nrange snapshot: {len(table.networks)} network(s)")
        if table.unparsed:
            print(f"  {len(table.unparsed)} unparsed line(s): {'; '.join(table.unparsed[:3])}")
        return 0

    try:
        report = run_port_service_host_stage(
            args.target,
            records_file=args.records,
            host_files=tuple(args.host_file),
            scope_files=tuple(args.scope),
            addresses=tuple(args.address),
            max_ips=args.max_ips,
            intel=not args.no_intel,
            ownership=not args.no_ownership,
            reverse_dns=not args.no_ptr,
            resolve_uncovered=not args.no_resolve_uncovered,
            services=not args.no_services,
            cdn_probe=not args.no_cdn_probe,
            escalate=not args.no_escalate,
            scan_level=args.scan_level,
            rate=args.rate,
            scan_type=args.scan_type,
            timeout=args.timeout,
            output_dir=args.output_dir,
            resolvers=args.resolvers,
        )
    except (ValueError, KeyError) as exc:
        colorlog.log.failed(str(exc))
        return 2

    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
