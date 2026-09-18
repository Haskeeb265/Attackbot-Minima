"""``asn_cidr`` — pipeline orchestrator: seeds in, network claims out.

Run order (each step is independently runnable through ``--stages``):::

    seeds      an apex, an ASN seed, and whatever the siblings already know
    lookup     RIPEstat (announcements) + RDAP (allocations) for each seed
    merge      claims folded to one row per network, origins unioned
    annotate   sibling addresses matched against the discovered networks
    emit       networks.jsonl, asns.jsonl, scope/discovered files, report.json

What this module adds over the per-source functions:

* **Seed expansion.** One address or domain seeds a chain: address → origin
  ASN(s) (RIPEstat ``prefix-overview``) → every prefix that AS announces →
  the allocation range behind the seed address (RDAP).  A bare ``AS<n>`` seed
  skips straight to announcements.  This is the pipeline's whole value: the
  ports stage can only see addresses DNS already pointed at.
* **Provenance discipline.** Every claim keeps where it came from, and the
  two origin kinds (``announced`` vs ``allocated``) never blur — the design's
  §5.4 gate downstream depends on the distinction being real.
* **Honest caps.** The per-ASN and per-org caps are recorded in the report
  when they bite, so a truncated artifact set is never mistaken for a whole one.
* **One failing source does not stop the run.** RIPEstat and RDAP are
  independent; the report carries each one's status.
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
from . import emit, settings, sources
from .normalize import (
    ORIGIN_ALLOCATION,
    ORIGIN_ANNOUNCEMENT,
    NetworkClaim,
    annotate_known_hosts,
    canonicalize_network,
    merge_claims,
    parse_prefixes,
)
from .sources import STATUS_UNAVAILABLE

log = logging.getLogger("asn_cidr.main")

ALL_STAGES: tuple[str, ...] = ("lookup", "emit")


@dataclass
class AsnCidrReport:
    """Machine-readable summary of one pipeline run."""

    target: str
    started_at: str
    finished_at: str = ""
    seconds: float = 0.0
    ok: bool = True
    seeds: list[str] = field(default_factory=list)
    sources: list[dict[str, object]] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    outputs: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "seconds": round(self.seconds, 2),
            "ok": self.ok,
            "seeds": self.seeds,
            "sources": self.sources,
            "counts": self.counts,
            "outputs": self.outputs,
        }


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def expand_asn_seed(
    asn: str,
    *,
    fetcher: sources.Fetcher | None = None,
    timeout: float | None = None,
    max_prefixes: int | None = None,
    min_prefix_len: int | None = None,
    max_prefix_len: int | None = None,
) -> tuple[list[NetworkClaim], dict[str, object], list[tuple[str, str]]]:
    """Every prefix *asn* announces, as ``announced``-class claims."""
    max_prefixes = settings.MAX_PREFIXES_PER_ASN if max_prefixes is None else max_prefixes
    min_prefix_len = settings.MIN_PREFIX_LEN if min_prefix_len is None else min_prefix_len
    max_prefix_len = settings.MAX_PREFIX_LEN if max_prefix_len is None else max_prefix_len

    result = sources.fetch_announced_prefixes(asn, fetcher=fetcher, timeout=timeout)
    status_row: dict[str, object] = result.to_dict()
    if result.status != sources.STATUS_OK:
        return [], status_row, []

    prefixes, refused = parse_prefixes(
        result.prefixes, min_prefix_len=min_prefix_len, max_prefix_len=max_prefix_len
    )
    truncated = False
    if max_prefixes and len(prefixes) > max_prefixes:
        log.warning(
            "AS%s announces %d usable prefix(es), above the %d cap - keeping the first %d",
            asn,
            len(prefixes),
            max_prefixes,
            max_prefixes,
        )
        prefixes = prefixes[:max_prefixes]
        truncated = True
    claims = [
        NetworkClaim(
            network=prefix,
            origin=ORIGIN_ANNOUNCEMENT,
            asns={result.asn},
            sources={"ripestat"},
        )
        for prefix in prefixes
    ]
    if truncated:
        status_row["truncated"] = True
    return claims, status_row, refused


def expand_address_seed(
    address: str,
    *,
    fetcher: sources.Fetcher | None = None,
    timeout: float | None = None,
) -> tuple[list[NetworkClaim], list[dict[str, object]], list[str]]:
    """Origin ASN(s) + allocation range behind one address.

    Returns ``(claims, per-source status rows, next ASN seeds)``.  The RIPEstat
    lookup yields the *announced* claim plus the ASNs that announce it; the
    RDAP lookup yields the *allocated* claim.  Either can succeed alone — the
    merge step keeps the single-origin row rather than waiting for both.
    """
    claims: list[NetworkClaim] = []
    statuses: list[dict[str, object]] = []
    next_asn_seeds: list[str] = []

    if settings.RIPESTAT_ENABLED:
        overview = sources.fetch_prefix_overview(address, fetcher=fetcher, timeout=timeout)
        statuses.append(
            {"source": "ripestat:prefix-overview", "address": address, "status": overview.status}
        )
        if overview.asns:
            for asn in overview.asns:
                prefix_claims, asn_status, _ = expand_asn_seed(
                    asn, fetcher=fetcher, timeout=timeout
                )
                # The per-AS row is the source's own dict; make it carry the
                # same "source" key the per-address rows use so the report is
                # uniform and consumers filter on one field.
                statuses.append(
                    {
                        "source": "ripestat:announced-prefixes",
                        "asn": asn,
                        **asn_status,
                    }
                )
                if prefix_claims:
                    next_asn_seeds.append(asn)
                for claim in prefix_claims:
                    if claim.as_names:
                        continue
                    claim.as_names = {
                        asn: overview.as_holders.get(asn, "") for asn in claim.asns
                    }
                claims.extend(prefix_claims)
        if overview.block:
            canonical = canonicalize_network(overview.block)
            if canonical:
                from .normalize import is_globally_routable
                import ipaddress

                block = ipaddress.ip_network(canonical)
                wide_ok = not (
                    block.version == 4
                    and settings.MAX_PREFIX_LEN
                    and block.prefixlen < settings.MAX_PREFIX_LEN
                )
                if is_globally_routable(block) and wide_ok:
                    claims.append(
                        NetworkClaim(
                            network=canonical,
                            origin=ORIGIN_ANNOUNCEMENT,
                            asns=set(overview.asns),
                            as_names=dict(overview.as_holders),
                            sources={"ripestat"},
                        )
                    )

    if settings.RDAP_ENABLED:
        rdap_range = sources.fetch_rdap_network(address, fetcher=fetcher, timeout=timeout)
        statuses.append(
            {
                "source": "rdap",
                "address": address,
                "status": rdap_range.status,
                "org": rdap_range.org,
            }
        )
        if rdap_range.status == sources.STATUS_OK and rdap_range.network:
            claims.append(
                NetworkClaim(
                    network=rdap_range.network,
                    origin=ORIGIN_ALLOCATION,
                    org=rdap_range.org,
                    org_handle=rdap_range.org_handle,
                    country=rdap_range.country,
                    registry=rdap_range.registry,
                    sources={"rdap"},
                )
            )

    return claims, statuses, sorted(set(next_asn_seeds))


def run_pipeline(
    target: str = TARGET,
    *,
    asns: list[str] | None = None,
    addresses: list[str] | None = None,
    output_dir: Path | str = settings.OUTPUT_DIR,
    sibling_addresses: list[str] | None = None,
    fetcher: sources.Fetcher | None = None,
    timeout: float | None = None,
    max_prefixes: int | None = None,
    min_prefix_len: int | None = None,
) -> AsnCidrReport:
    """Run the pipeline: seeds → claims → annotated artifacts.

    Parameters
    ----------
    target:
        Apex domain; used as the report label and to seed the address lookup
        from the sibling stages' live-host artifacts when *addresses* is empty.
    asns:
        Extra ``AS<n>`` seeds (announcement side only).
    addresses:
        Address seeds.  Empty means "derive from the sibling stages' artifacts"
        (the ports stage's ``openports.jsonl``/``ownership.jsonl`` inputs).
    sibling_addresses:
        Addresses the sibling stages already know, used only for annotation
        (which networks are confirmed vs. untouched).
    fetcher:
        Injected HTTP callable for tests; production uses :func:`sources.http_get`.
    timeout:
        Per-request budget override.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    apex = canonicalize_host(target)
    if apex is None:
        raise ValueError(f"target {target!r} is not a valid domain (expected e.g. 'example.com')")

    started = time.monotonic()
    report = AsnCidrReport(target=apex, started_at=_utc_now())

    # The documented seed contract: no explicit addresses → derive from the
    # sibling stages' artifacts (ports' ownership.jsonl, names' records.jsonl).
    # Missing artifacts mean "no seeds known", a state, not an error.
    if addresses is None:
        addresses = _sibling_addresses()
        log.info("seeded %d address(es) from sibling-stage artifacts", len(addresses))
    if sibling_addresses is None:
        sibling_addresses = _sibling_addresses()

    report.seeds = [*(f"AS{a}" for a in (asns or [])), *list(addresses or [])]

    claims: list[NetworkClaim] = []
    source_statuses: list[dict[str, object]] = []
    refused: list[tuple[str, str]] = []

    # 1. Address seeds → origin ASNs + allocation ranges.
    for address in addresses or []:
        address_claims, statuses, next_asns = expand_address_seed(
            address, fetcher=fetcher, timeout=timeout
        )
        claims.extend(address_claims)
        source_statuses.extend(statuses)
        for asn in next_asns:
            asn_claims, asn_status, asn_refused = expand_asn_seed(
                asn, fetcher=fetcher, timeout=timeout, max_prefixes=max_prefixes,
                min_prefix_len=min_prefix_len,
            )
            claims.extend(asn_claims)
            source_statuses.append(asn_status)
            refused.extend(asn_refused)

    # 2. Direct ASN seeds → announcements only.
    for asn in asns or []:
        asn_claims, asn_status, asn_refused = expand_asn_seed(
            asn, fetcher=fetcher, timeout=timeout, max_prefixes=max_prefixes,
            min_prefix_len=min_prefix_len,
        )
        claims.extend(asn_claims)
        source_statuses.append(asn_status)
        refused.extend(asn_refused)

    # 3. Merge to one row per network, then annotate with what the siblings know.
    merged = merge_claims(claims)
    known = sibling_addresses or []
    matched = annotate_known_hosts(merged, known)

    report.sources = source_statuses
    report.counts = {
        "claims_raw": len(claims),
        "networks": len(merged),
        "announced": sum(1 for c in merged if c.announced),
        "allocated": sum(1 for c in merged if c.allocated),
        "both_origins": sum(1 for c in merged if c.announced and c.allocated),
        "with_known_hosts": sum(1 for c in merged if c.known_hosts),
        "known_host_matches": matched,
        "refused": len(refused),
        "source_failures": sum(
            1
            for row in source_statuses
            if row.get("status") in (STATUS_UNAVAILABLE, sources.STATUS_ERROR)
        ),
    }
    if refused:
        report.counts["refused_private"] = sum(
            1 for _, reason in refused if "routable" in reason
        )
        report.counts["refused_narrow"] = sum(
            1 for _, reason in refused if "narrower" in reason
        )
        report.counts["refused_wide"] = sum(
            1 for _, reason in refused if "wider than" in reason
        )

    # 4. Emit.  A run with zero claims still writes the artifacts, so a
    #    consumer never has to distinguish "empty" from "not run".
    networks_path = emit.write_jsonl(
        output_dir / emit.NETWORKS_FILE, (claim.to_dict() for claim in merged)
    )
    asns_path = emit.write_jsonl(output_dir / emit.ASNS_FILE, emit.asn_summary_rows(merged))
    scope_annotated = emit.write_lines(
        output_dir / emit.SCOPE_DIR / emit.SCOPE_ANNOTATED_FILE, emit.scope_lines(merged)
    )
    scope_plain = emit.write_lines(
        output_dir / emit.SCOPE_DIR / emit.SCOPE_DISCOVERED_FILE, emit.plain_scope_lines(merged)
    )
    report.outputs = {
        emit.NETWORKS_FILE: networks_path.as_posix(),
        emit.ASNS_FILE: asns_path.as_posix(),
        f"{emit.SCOPE_DIR}/{emit.SCOPE_DISCOVERED_FILE}": scope_plain.as_posix(),
        f"{emit.SCOPE_DIR}/{emit.SCOPE_ANNOTATED_FILE}": scope_annotated.as_posix(),
    }

    report.ok = not report.counts["source_failures"] or bool(merged)
    report.finished_at = _utc_now()
    report.seconds = time.monotonic() - started
    report_path = emit.write_json(output_dir / emit.REPORT_FILE, report.to_dict())
    report.outputs[emit.REPORT_FILE] = report_path.as_posix()

    _log_summary(report, merged, refused)
    return report


def _log_summary(
    report: AsnCidrReport, claims: list[NetworkClaim], refused: list[tuple[str, str]]
) -> None:
    colorlog.log.info(
        f"asn/cidr stage for {report.target}: {report.counts.get('networks', 0)} network(s) "
        f"({report.counts.get('announced', 0)} announced, {report.counts.get('allocated', 0)} "
        f"allocated, {report.counts.get('both_origins', 0)} corroborated) in "
        f"{report.seconds:.1f}s"
    )
    if report.counts.get("with_known_hosts"):
        colorlog.log.info(
            f"{report.counts['with_known_hosts']} network(s) contain address(es) the sibling "
            f"stages already resolved (confirmed territory)"
        )
    if refused:
        colorlog.log.info(
            f"{len(refused)} network(s) refused (private/reserved or below the prefix floor) "
            "- counted in report.json"
        )
    if report.counts.get("source_failures"):
        colorlog.log.warn(
            f"{report.counts['source_failures']} source lookup(s) failed - see "
            f"{report.outputs.get(emit.REPORT_FILE, emit.REPORT_FILE)}"
        )
    if report.ok:
        colorlog.log.success(
            f"discovered scope written to {report.outputs.get(emit.SCOPE_DIR + '/' + emit.SCOPE_DISCOVERED_FILE)}"
        )
    else:
        colorlog.log.failed(
            f"asn/cidr stage for {report.target} did not complete cleanly - see report.json"
        )


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m service.recon_pipeline.pipelines.asn_cidr.main",
        description=(
            "Discover the ASNs and CIDRs behind a target (RIPEstat + RDAP, keyless) "
            "and emit ports-stage-compatible scope files. Never scans."
        ),
    )
    parser.add_argument("-t", "--target", default=TARGET, help=f"apex domain (default: {TARGET})")
    parser.add_argument(
        "--asn", action="append", default=None, dest="asns",
        help="AS seed (repeatable), e.g. --asn 400771",
    )
    parser.add_argument(
        "--address", action="append", default=None, dest="addresses",
        help="address seed (repeatable); default: the ports stage's resolved addresses",
    )
    parser.add_argument(
        "--no-sibling-input", action="store_true",
        help="do not read sibling-stage artifacts for seeds/annotation",
    )
    parser.add_argument("--output-dir", default=str(settings.OUTPUT_DIR), help="output directory")
    parser.add_argument("--timeout", type=float, default=None, help="per-request seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.  Returns a process exit code."""
    args = _build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-7s %(name)s: %(message)s",
    )

    addresses = list(args.addresses) if args.addresses else None
    sibling_addresses: list[str] | None = None
    if args.no_sibling_input:
        # Explicit opt-out: never read (or annotate from) sibling artifacts.
        addresses = list(args.addresses or [])
        sibling_addresses = []

    try:
        report = run_pipeline(
            args.target,
            asns=list(args.asns or []),
            addresses=addresses,
            sibling_addresses=sibling_addresses,
            output_dir=args.output_dir,
            timeout=args.timeout,
        )
    except (ValueError, KeyError) as exc:
        colorlog.log.failed(str(exc))
        return 2

    return 0 if report.ok else 1


def _sibling_addresses() -> list[str]:
    """Addresses the sibling stages already know, best-effort.

    Reads the ports stage's ``ownership.jsonl`` (every address it looked at)
    and the names stage's ``active/output/records.jsonl`` A/AAAA answers.
    Missing files mean the siblings have not run — that is a state, not an
    error, and the pipeline still runs on explicit ``--address``/``--asn`` seeds.
    """
    import json

    addresses: list[str] = []

    psh_root = Path(__file__).resolve().parents[1] / "port_service_host" / "output"
    ownership = psh_root / "ownership.jsonl"
    if ownership.is_file():
        for line in ownership.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            address = row.get("ip")
            if isinstance(address, str) and address:
                addresses.append(address)

    records = (
        Path(__file__).resolve().parents[1]
        / "subdomain_domain_wildcards"
        / "active"
        / "output"
        / "records.jsonl"
    )
    if records.is_file():
        for line in records.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if not stripped.startswith("{"):
                continue
            try:
                row = json.loads(stripped)
            except (json.JSONDecodeError, ValueError):
                continue
            for key in ("a", "aaaa"):
                for value in row.get(key) or ():
                    if isinstance(value, str) and value:
                        addresses.append(value)

    return sorted(set(addresses))


if __name__ == "__main__":
    raise SystemExit(main())
