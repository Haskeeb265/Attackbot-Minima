"""Build the scan set: which addresses, from where, and with what claim on them.

The decisive inventory fact about this stage is that **the DNS-to-IP half is
already done**.  The sibling active stage's ``records.jsonl`` carries the A/AAAA
answers for every live host it found, so the addresses this stage scans are not
discovered here — they are *recovered*, deduplicated, and given provenance.

Three inputs, and the provenance each one carries is the reason they are kept
apart rather than unioned into one anonymous list:

``records.jsonl`` (sibling stage)
    An address reached from a name that our own pipeline resolved and
    wildcard-filtered.  This is the strongest claim in the set.

``resolved.txt`` / ``live_hosts.txt`` (sibling stage)
    The name list, used to expand an address back into the names that point at
    it — which is what makes the report readable ("203.0.113.7" is far less
    useful than "203.0.113.7 <- dev.example.com, staging.example.com").

``scope files`` (operator-declared)
    CIDRs and single addresses from a program's declared scope.  Per the design's
    §5.4 this is the **only** input that grants network reach beyond the hosts our
    own DNS data resolved, and it is what marks an address as eligible for the L3
    rung.  ASN-derived prefixes never land here; they are advisory and are reported
    as such.

The CNAME targets recorded alongside the addresses matter more than they look: a
name whose CNAME chain ends in ``*.edgekey.net`` or ``*.cloudflare.net`` is
evidence that the address is shared edge infrastructure, and it arrives *before*
any packet is sent — which is exactly when the classifier needs it.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from service.recon_pipeline.platform.common.normalize import canonicalize_host
from .normalize import (
    canonicalize_ip,
    dedupe_addresses,
    expand_networks,
    read_text,
    write_lines,
)
from .settings import (  # noqa: F401  (re-exported: callers key off these paths)
    ACTIVE_RECORDS_FILE,
    ACTIVE_RESOLVED_FILE,
    ACTIVE_RESOLVERS_FILE,
    LIVE_HOSTS_FILE,
    MAX_IPS,
    OUTPUT_DIR,
    SCOPE_FILES,
)

log = logging.getLogger("psh.seed_builder")

#: The artifact this module writes — the stage's primary seed list.
IPS_RAW_FILE = "ips_raw.txt"


@dataclass
class RecordsIndex:
    """What the sibling stage's DNS records tell us, indexed by address."""

    #: ``ip -> [names]`` (unioned across A and AAAA answers).
    names_by_ip: dict[str, list[str]] = field(default_factory=dict)
    #: ``ip -> [cname targets]`` — pre-scan evidence that an address is an edge.
    cname_targets: dict[str, list[str]] = field(default_factory=dict)
    #: Addresses seen, in first-seen order.
    addresses: list[str] = field(default_factory=list)
    #: Records whose ``host`` was not a usable name.
    skipped: int = 0

    def __len__(self) -> int:
        return len(self.addresses)


def parse_records(text: str) -> RecordsIndex:
    """Index ``dnsx -json`` records by the addresses they resolve to.

    The shape was taken from the sibling stage's real output rather than from
    documentation::

        {"host":"a.example.com","a":["1.2.3.4"],"aaaa":["2001:db8::1"],
         "cname":["a.example.com.edgekey.net","e1.dscx.akamaiedge.net"]}

    A record with no A/AAAA answer (a dangling CNAME, a TXT-only row) contributes
    no address and is counted, not guessed at.
    """
    index = RecordsIndex()
    seen: set[str] = set()

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            payload = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue

        raw_host = payload.get("host")
        if not isinstance(raw_host, str):
            # A DNS record's host is always a string; a number (or anything
            # else) is tool noise and is counted, not coerced.
            index.skipped += 1
            continue
        host = canonicalize_host(raw_host)
        if host is None:
            index.skipped += 1
            continue

        cnames: list[str] = []
        for value in payload.get("cname") or ():
            target = canonicalize_host(str(value))
            if target and target not in cnames:
                cnames.append(target)

        found_any = False
        for field_name in ("a", "aaaa"):
            for value in payload.get(field_name) or ():
                address = canonicalize_ip(value)
                if address is None:
                    continue
                found_any = True
                names = index.names_by_ip.setdefault(address, [])
                if host not in names:
                    names.append(host)
                if cnames:
                    targets = index.cname_targets.setdefault(address, [])
                    for target in cnames:
                        if target not in targets:
                            targets.append(target)
                if address not in seen:
                    seen.add(address)
                    index.addresses.append(address)
        if not found_any and cnames:
            # A dangling CNAME: no address of its own, so nothing to scan, but it
            # is not an error — record it as skipped rather than inventing a host.
            index.skipped += 1

    return index


def read_host_list(paths: Iterable[Path | str]) -> list[str]:
    """Read one or more host lists into canonical, deduplicated names.

    These are the sibling stage's ``resolved.txt`` / ``live_hosts.txt``.  A line
    that is not a hostname is dropped, so pointing this at a mixed file (or at an
    address list) degrades to a smaller name set rather than inventing names.
    """
    hosts: list[str] = []
    seen: set[str] = set()
    for path in paths:
        for line in read_text(path).splitlines():
            host = canonicalize_host(line)
            if host and host not in seen:
                seen.add(host)
                hosts.append(host)
    return hosts


def resolve_hosts(
    hosts: Iterable[str],
    *,
    output_dir: Path | str,
    timeout: float = 300.0,
    resolvers: Path | str | None = None,
    run: object | None = None,
    suffix: str = "missing-",
) -> RecordsIndex:
    """Resolve names that have no address yet, via ``dnsx -a -json``.

    This exists for a real coverage gap rather than for symmetry: ``records.jsonl``
    is produced by the sibling stage's *active* pass, so a host that only the
    *permutation* stage found has no record.  Without this step those hosts
    silently contribute no address to the scan set, and "we scanned everything we
    knew about" would be false.  The output shape is identical to the records
    file, so :func:`parse_records` parses it unchanged.
    """
    from .active.tools import dnsx_a_args, run_tool

    hosts = list(dict.fromkeys(hosts))
    if not hosts:
        return RecordsIndex()

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    input_path = output_dir / f"{suffix}resolve-input.txt"
    stdout_path = output_dir / f"{suffix}resolve.jsonl"
    log_path = output_dir / f"{suffix}resolve.log"
    write_lines(input_path, hosts)

    runner = run or run_tool
    args = dnsx_a_args(
        input_path=f"/work/{input_path.name}",
        resolvers=f"/work/{Path(resolvers).name}" if resolvers else None,
    )
    log.info("resolving %d host(s) that had no DNS record", len(hosts))
    try:
        runner(
            "dnsx",
            args,
            output_dir=output_dir,
            timeout=timeout,
            stdout_name=stdout_path.name,
            stderr_name=log_path.name,
            # stdout/stderr names are explicit, so the suffix would only affect
            # the container name; "missing-" is already in both file names.
            suffix="",
        )
    except Exception as exc:  # a fill-in step must never fail the stage
        log.warning("could not resolve %d host(s): %s: %s", len(hosts), type(exc).__name__, exc)
        return RecordsIndex()
    return parse_records(read_text(stdout_path))


@dataclass
class SeedSet:
    """The scan set plus everything needed to explain it."""

    target: str = ""
    addresses: list[str] = field(default_factory=list)
    refused: list[tuple[str, str]] = field(default_factory=list)
    #: Addresses named by an explicit CIDR/IP scope declaration.
    scope_declared: set[str] = field(default_factory=set)
    names_by_ip: dict[str, list[str]] = field(default_factory=dict)
    cname_targets: dict[str, list[str]] = field(default_factory=dict)
    #: Address -> the inputs that contributed it (``records``, ``scope``).
    sources: dict[str, list[str]] = field(default_factory=dict)
    #: Hosts the DNS stage knows about but for which no address was available.
    unresolved_hosts: list[str] = field(default_factory=list)
    #: True when the head-count cap truncated the set.
    capped: bool = False

    @property
    def declared(self) -> list[str]:
        """The declared-scope subset, in scan-set order."""
        return [address for address in self.addresses if address in self.scope_declared]

    def names(self, address: str) -> list[str]:
        return list(self.names_by_ip.get(address, ()))

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "addresses": len(self.addresses),
            "scope_declared": len(self.scope_declared),
            "with_names": sum(1 for address in self.addresses if self.names_by_ip.get(address)),
            "with_cname_evidence": sum(
                1 for address in self.addresses if self.cname_targets.get(address)
            ),
            "refused": len(self.refused),
            "unresolved_hosts": len(self.unresolved_hosts),
            "capped": self.capped,
            "sources": {
                source: sum(1 for values in self.sources.values() if source in values)
                for source in ("records", "scope", "explicit")
            },
        }


def build(
    *,
    target: str = "",
    records_file: Path | str | None = ACTIVE_RECORDS_FILE,
    host_files: Iterable[Path | str] = (ACTIVE_RESOLVED_FILE, LIVE_HOSTS_FILE),
    scope_files: Iterable[Path | str] = SCOPE_FILES,
    extra_addresses: Iterable[str] = (),
    max_ips: int = MAX_IPS,
    output_dir: Path | str = OUTPUT_DIR,
    resolve_uncovered: bool = False,
    resolve_timeout: float = 300.0,
    resolvers: Path | str | None = None,
    run: object | None = None,
) -> SeedSet:
    """Assemble the scan set from every seed source.

    Ordering is stable and meaningful: addresses recovered from our own DNS
    records come first (in first-seen order, so the list reads like the discovery
    that produced it), then declared-scope additions.  When *max_ips* truncates
    the set, the addresses that survive are therefore the best-evidenced ones —
    and the truncation is reported, never silent.
    """
    records_path = Path(records_file) if records_file else None
    index = parse_records(read_text(records_path)) if records_path else RecordsIndex()

    if records_path and not index.addresses:
        log.warning(
            "no addresses recovered from %s - run the subdomain stage's active pass "
            "first, or pass an explicit scope file (PSH_SCOPE_FILE / --scope)",
            records_path,
        )

    known_hosts = read_host_list(host_files)
    uncovered = [
        host
        for host in known_hosts
        if not any(host in names for names in index.names_by_ip.values())
    ]
    if uncovered and resolve_uncovered:
        filled = resolve_hosts(
            uncovered,
            output_dir=output_dir,
            timeout=resolve_timeout,
            resolvers=resolvers,
            run=run,
        )
        for address, names in filled.names_by_ip.items():
            merged = index.names_by_ip.setdefault(address, [])
            for name in names:
                if name not in merged:
                    merged.append(name)
            if address not in index.addresses:
                index.addresses.append(address)
        for address, targets in filled.cname_targets.items():
            merged_targets = index.cname_targets.setdefault(address, [])
            for target in targets:
                if target not in merged_targets:
                    merged_targets.append(target)
        uncovered = [
            host
            for host in uncovered
            if not any(host in names for names in index.names_by_ip.values())
        ]
    if uncovered:
        log.warning(
            "%d known host(s) have no DNS address in the inputs and will not be "
            "scanned (e.g. %s); enable PSH_RESOLVE_UNCOVERED to resolve them here",
            len(uncovered),
            ", ".join(uncovered[:3]),
        )

    seeds = SeedSet(target=target, names_by_ip=index.names_by_ip, cname_targets=index.cname_targets)
    seeds.unresolved_hosts = uncovered

    for address in index.addresses:
        seeds.sources.setdefault(address, []).append("records")

    ordered: list[str] = list(index.addresses)

    # Declared scope: expanded, capped per network, and reported when refused.
    scope_tokens: list[str] = []
    for path in scope_files:
        scope_tokens += [
            line.split("#", 1)[0].strip()
            for line in read_text(path).splitlines()
            if line.split("#", 1)[0].strip()
        ]
    if scope_tokens:
        scope_addresses, scope_refused = expand_networks(scope_tokens, host_limit=max_ips or 0)
        seeds.refused.extend(scope_refused)
        for address in scope_addresses:
            seeds.scope_declared.add(address)
            seeds.sources.setdefault(address, []).append("scope")
            if address not in ordered:
                ordered.append(address)
        log.info(
            "declared scope: %d address(es) from %d file(s) (%d token(s) refused)",
            len(scope_addresses),
            len(list(scope_files)),
            len(scope_refused),
        )

    # Operator-supplied addresses (inline, e.g. from the CLI).
    extra, extra_refused = dedupe_addresses(extra_addresses)
    seeds.refused.extend(extra_refused)
    for address in extra:
        seeds.sources.setdefault(address, []).append("explicit")
        if address not in ordered:
            ordered.append(address)

    accepted, refused = dedupe_addresses(ordered)
    seeds.refused.extend(refused)

    if max_ips and len(accepted) > max_ips:
        seeds.capped = True
        log.warning(
            "scan set capped at %d address(es) (PSH_MAX_IPS); %d dropped",
            max_ips,
            len(accepted) - max_ips,
        )
        accepted = accepted[:max_ips]

    seeds.addresses = accepted
    # In-scope means "one of our target's names resolves here" — supplied by the
    # DNS records, never by the scope file (declared scope is a *legal* claim,
    # not a technical one, and the ladder treats the two differently).
    return seeds


def write_seeds(output_dir: Path | str, seeds: SeedSet) -> Path:
    """Write ``ips_raw.txt`` — one address per line, in scan-set order."""
    path = Path(output_dir) / IPS_RAW_FILE
    write_lines(path, seeds.addresses)
    return path


def refused_report(seeds: SeedSet) -> dict[str, list[str]]:
    """``{reason: [tokens]}`` for the addresses the gate rejected, for the report."""
    grouped: dict[str, list[str]] = {}
    for token, reason in seeds.refused:
        grouped.setdefault(reason, []).append(token)
    return {reason: sorted(set(tokens))[:50] for reason, tokens in sorted(grouped.items())}


__all__ = [
    "IPS_RAW_FILE",
    "RecordsIndex",
    "SeedSet",
    "build",
    "read_host_list",
    "resolve_hosts",
    "parse_records",
    "refused_report",
    "write_seeds",
]
