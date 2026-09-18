"""Turn source rows into model nodes and edges — the normalisation itself.

One function per artifact stream, each of which does two things and nothing
else: it names the nodes the row implies, and it states the edges the row
asserts.  The rules the whole file follows:

* **A row never invents a fact its artifact does not carry.**  ``ownership.jsonl``
  says an address belongs to an AS; it does not say the address is alive, so the
  node gets ``discovered`` and only our own scan upgrades it to ``observed``.
* **Trust is per contribution, not per node.**  Each call passes the trust class
  of the specific claim, and the model keeps the strongest — which is why a
  hostname can be ``observed`` while the wildcard that covers it stays
  ``discovered``.
* **Edges carry the artifact's own words.**  Where a sibling recorded evidence
  (the CDN verdict's evidence list), a bounded slice of it travels with the edge,
  so the model's reader does not have to go back to the source file to know why.
* **A failure to link is reported, not papered over.**  ``parameters.txt`` is a
  bare name list with no URL linkage, so parameters become nodes and the run
  report counts them as unlinked.  Inventing a ``has_parameter`` edge from the
  whole URL set to every parameter name would be a lie with good manners.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from . import normalize as norm
from . import settings, vocabulary as vocab
from .sources import SourceFacts

if TYPE_CHECKING:  # a runtime import would be a cycle: score imports the model
    from .score import ScoreStats

#: Which stream carries which evidence, for the ``sources`` field of a node.
SOURCE_LABEL = {
    "hosts": "subdomain_domain_wildcards:active/live_hosts",
    "records": "subdomain_domain_wildcards:active/records",
    "subdomains": "subdomain_domain_wildcards:passive/subdomains",
    "wildcards": "subdomain_domain_wildcards:passive/wildcards",
    "wildcard_suppressed": "subdomain_domain_wildcards:passive/wildcards",
    "ownership": "port_service_host:rdap+cymru ownership",
    "open_ports": "port_service_host:scan",
    "passive_intel": "port_service_host:internetdb",
    "verdicts": "port_service_host:classify",
    "ptr": "port_service_host:ptr",
    "urls": "url_endpoint:urls",
    "url_hosts": "url_endpoint:hosts",
    "endpoints": "url_endpoint:endpoints",
    "javascript": "url_endpoint:javascript",
    "interesting": "url_endpoint:interesting",
    "parameters": "url_endpoint:parameters",
    "networks": "asn_cidr:networks",
    "asns": "asn_cidr:asns",
}

#: URL roles: which derived artifact a URL appeared in, and what that means.
URL_ROLE_STREAMS = (
    ("endpoints", "endpoint", "endpoint in the harvested URL set"),
    ("javascript", "javascript", "JavaScript asset in the harvested URL set"),
    ("interesting", "interesting", "flagged interesting by the URL pipeline"),
)


@dataclass
class MergeResult:
    """The model plus everything the report needs to describe how it was built."""

    model: norm.Model
    scope_applied: bool = False
    registered_networks: int = 0
    unlinked: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    wildcard_edges_truncated: int = 0
    rows_by_stream: dict[str, int] = field(default_factory=dict)
    #: What the S2 scoring pass did, or why it was skipped.
    score_stats: ScoreStats | None = None


def build_model(
    facts: list[SourceFacts],
    *,
    target: str,
    scope=None,
    max_nodes: int | None = settings.MAX_NODES,
    max_edges: int | None = settings.MAX_EDGES,
    max_evidence: int = settings.MAX_EVIDENCE,
    max_wildcard_edges: int = settings.MAX_WILDCARD_EDGES,
    scored: bool = settings.SCORE_MODEL,
    max_score_audit: int = settings.MAX_SCORE_AUDIT,
    top_scored: int = settings.MAX_TOP_SCORED,
) -> MergeResult:
    """Build the model, annotate it with scope, then score every node."""
    model = norm.Model()
    result = MergeResult(model=model)

    # The one thing we can state without any artifact: the operator's target.
    model.add_node(
        vocab.DOMAIN,
        norm.domain_identity(target),
        source="platform:declared target",
        trust=vocab.DECLARED,
        props={"apex": True},
        evidence=f"the operator's target for this run: {target}",
        max_nodes=max_nodes,
        max_evidence=max_evidence,
    )

    for source in facts:
        result.rows_by_stream.update(
            {artifact.stream: artifact.rows for artifact in source.artifacts}
        )
        if not source.enabled:
            result.notes.append(f"{source.name}: skipped ({source.skipped_reason})")
            continue
        if source.missing:
            result.notes.append(
                f"{source.name}: missing artifact(s) {', '.join(source.missing)}"
            )
        _merge_source(
            result,
            source,
            max_nodes=max_nodes,
            max_edges=max_edges,
            max_evidence=max_evidence,
        )

    _merge_wildcard_coverage(
        result, max_edges=max_edges, cap=max_wildcard_edges, max_evidence=max_evidence
    )
    _annotate_scope(result, scope)
    _annotate_scores(result, scored=scored, max_audit=max_score_audit, top=top_scored)
    return result


# --------------------------------------------------------------------------- #
# per-source merging
# --------------------------------------------------------------------------- #


def _merge_source(
    result: MergeResult,
    source: SourceFacts,
    *,
    max_nodes: int | None,
    max_edges: int | None,
    max_evidence: int,
) -> None:
    dispatch = {
        "subdomain_domain_wildcards": _merge_names,
        "port_service_host": _merge_ports,
        "url_endpoint": _merge_urls,
        "asn_cidr": _merge_networks,
    }
    handler = dispatch.get(source.name)
    if handler is None:
        result.notes.append(f"{source.name}: no merge handler — ignored")
        return
    handler(result, source, max_nodes=max_nodes, max_edges=max_edges, max_evidence=max_evidence)


def _merge_names(
    result: MergeResult,
    source: SourceFacts,
    *,
    max_nodes: int | None,
    max_edges: int | None,
    max_evidence: int,
) -> None:
    model = result.model

    # Live hosts: our own stages resolved these, so they are observed facts.
    for row in source.streams.get("hosts", []):
        host = norm.domain_identity(str(row.get("value", "")))
        if not host:
            continue
        model.add_node(
            vocab.DOMAIN,
            host,
            source=SOURCE_LABEL["hosts"],
            trust=vocab.OBSERVED,
            props={"live": True},
            evidence="the names pipeline resolved this host",
            max_nodes=max_nodes,
            max_evidence=max_evidence,
        )

    # Known names from passive OSINT/CT sources: discovered, not observed.
    for row in source.streams.get("subdomains", []):
        host = norm.domain_identity(str(row.get("value", "")))
        if not host:
            continue
        model.add_node(
            vocab.DOMAIN,
            host,
            source=SOURCE_LABEL["subdomains"],
            trust=vocab.DISCOVERED,
            evidence="passive source union (CT logs, OSINT datasets)",
            max_nodes=max_nodes,
            max_evidence=max_evidence,
        )

    # DNS records: the addresses, and the resolution claims between them.
    for row in source.streams.get("records", []):
        host = norm.domain_identity(str(row.get("host", "")))
        if not host:
            continue
        record_types = sorted(
            key
            for key, value in row.items()
            if key
            not in {
                "host",
                "ttl",
                "resolver",
                "all",
                "status_code",
                "timestamp",
                "query-time",
            }
            and value not in (None, "", [], {})
        )
        domain = model.add_node(
            vocab.DOMAIN,
            host,
            source=SOURCE_LABEL["records"],
            trust=vocab.OBSERVED,
            props={
                "dns_record_types": record_types,
                "resolved": True,
                "last_status": str(row.get("status_code", "")),
            },
            evidence=f"resolved by our DNS stage (status {row.get('status_code', '?')})",
            max_nodes=max_nodes,
            max_evidence=max_evidence,
        )
        if domain is None:
            continue
        for record_type in ("a", "aaaa"):
            for value in _as_list(row.get(record_type)):
                address = norm.address_identity(str(value))
                if not address:
                    continue
                model.add_node(
                    vocab.IP,
                    address,
                    source=SOURCE_LABEL["records"],
                    trust=vocab.OBSERVED,
                    props={"family": 6 if record_type == "aaaa" else 4},
                    max_nodes=max_nodes,
                    max_evidence=max_evidence,
                )
                model.add_edge(
                    vocab.RESOLVES_TO,
                    domain.id,
                    vocab.node_id(vocab.IP, address),
                    source=SOURCE_LABEL["records"],
                    trust=vocab.OBSERVED,
                    props={"record_type": record_type.upper()},
                    evidence=f"{record_type.upper()} answer for {host}",
                    max_edges=max_edges,
                    max_evidence=max_evidence,
                )

    # Wildcards: the answer itself, and whether the stage suppressed it.
    for stream, suppressed in (("wildcards", False), ("wildcard_suppressed", True)):
        for row in source.streams.get(stream, []):
            token = norm.wildcard_identity(str(row.get("value", "")))
            if token == "*.":
                continue
            model.add_node(
                vocab.WILDCARD,
                token,
                source=SOURCE_LABEL[stream],
                trust=vocab.DISCOVERED,
                props={"suppressed": suppressed},
                evidence=(
                    "wildcard answer suppressed by the names pipeline"
                    if suppressed
                    else "wildcard DNS answer observed by the names pipeline"
                ),
                max_nodes=max_nodes,
                max_evidence=max_evidence,
            )


def _merge_ports(
    result: MergeResult,
    source: SourceFacts,
    *,
    max_nodes: int | None,
    max_edges: int | None,
    max_evidence: int,
) -> None:
    model = result.model

    for row in source.streams.get("ownership", []):
        address = norm.address_identity(str(row.get("ip", "")))
        if not address:
            continue
        address_id = vocab.node_id(vocab.IP, address)
        model.add_node(
            vocab.IP,
            address,
            source=SOURCE_LABEL["ownership"],
            trust=vocab.DISCOVERED,
            props={"country": str(row.get("country", "")), "registry": str(row.get("registry", ""))},
            evidence="registry/RDAP ownership lookup",
            max_nodes=max_nodes,
            max_evidence=max_evidence,
        )

        asn = str(row.get("asn", "")).strip()
        if asn:
            asn_id = vocab.node_id(vocab.ASN, asn)
            model.add_node(
                vocab.ASN,
                asn,
                source=SOURCE_LABEL["ownership"],
                trust=vocab.DISCOVERED,
                props={"as_name": str(row.get("as_name", ""))},
                max_nodes=max_nodes,
                max_evidence=max_evidence,
            )
            model.add_edge(
                vocab.BELONGS_TO_ASN,
                address_id,
                asn_id,
                source=SOURCE_LABEL["ownership"],
                trust=vocab.DISCOVERED,
                evidence=f"{row.get('as_name') or 'AS' + asn} (RDAP/Cymru origin lookup)",
                max_edges=max_edges,
                max_evidence=max_evidence,
            )
            as_name = str(row.get("as_name", "")).strip()
            if as_name:
                org_id = vocab.node_id(vocab.ORGANIZATION, norm.organization_identity(as_name))
                model.add_node(
                    vocab.ORGANIZATION,
                    norm.organization_identity(as_name),
                    source=SOURCE_LABEL["ownership"],
                    trust=vocab.DISCOVERED,
                    props={"names": [as_name]},
                    max_nodes=max_nodes,
                    max_evidence=max_evidence,
                )
                model.add_edge(
                    vocab.REGISTERED_TO,
                    asn_id,
                    org_id,
                    source=SOURCE_LABEL["ownership"],
                    trust=vocab.DISCOVERED,
                    evidence=f"registry names AS{asn} as {as_name}",
                    max_edges=max_edges,
                    max_evidence=max_evidence,
                )

        prefix = str(row.get("prefix", "")).strip()
        handle = str(row.get("handle", "")).strip()
        org = str(row.get("org", "")).strip()
        if prefix:
            network_id = vocab.node_id(vocab.NETWORK, norm.network_identity(prefix))
            model.add_node(
                vocab.NETWORK,
                norm.network_identity(prefix),
                source=SOURCE_LABEL["ownership"],
                trust=vocab.DISCOVERED,
                props={
                    # The same row produces the ``allocated_to`` edge below, so the
                    # node says so too: a reader filtering on ``classes`` must not
                    # see "announced" on a network this model also allocates, or
                    # the field contradicts the edge beside it.
                    "classes": ["allocated"],
                    "registry": str(row.get("registry", "")),
                    "org": org,
                    "org_handle": handle,
                },
                evidence="registry states this prefix holds the address",
                max_nodes=max_nodes,
                max_evidence=max_evidence,
            )
            model.add_edge(
                vocab.IN_NETWORK,
                address_id,
                network_id,
                source=SOURCE_LABEL["ownership"],
                trust=vocab.DISCOVERED,
                evidence=f"registry prefix {prefix} contains the address",
                max_edges=max_edges,
                max_evidence=max_evidence,
            )
            if org or handle:
                holder = org or handle
                org_id = vocab.node_id(vocab.ORGANIZATION, norm.organization_identity(holder))
                model.add_node(
                    vocab.ORGANIZATION,
                    norm.organization_identity(holder),
                    source=SOURCE_LABEL["ownership"],
                    trust=vocab.DISCOVERED,
                    props={"org": org, "handles": [handle] if handle else [], "registry": str(row.get("registry", ""))},
                    max_nodes=max_nodes,
                    max_evidence=max_evidence,
                )
                model.add_edge(
                    vocab.ALLOCATED_TO,
                    network_id,
                    org_id,
                    source=SOURCE_LABEL["ownership"],
                    trust=vocab.DISCOVERED,
                    evidence=f"RDAP allocation: {holder} holds {prefix}",
                    max_edges=max_edges,
                    max_evidence=max_evidence,
                )

    # Our own scan: observed services.
    for row in source.streams.get("open_ports", []):
        address = norm.address_identity(str(row.get("ip", "")))
        port = _port_number(row.get("port"))
        if not address or port is None:
            continue
        proto = str(row.get("proto", "tcp"))
        service = norm.service_identity(address, port, proto)
        service_id = vocab.node_id(vocab.SERVICE, service)
        model.add_node(
            vocab.IP,
            address,
            source=SOURCE_LABEL["open_ports"],
            trust=vocab.OBSERVED,
            evidence="the ports stage scanned this address",
            max_nodes=max_nodes,
            max_evidence=max_evidence,
        )
        model.add_node(
            vocab.SERVICE,
            service,
            source=SOURCE_LABEL["open_ports"],
            trust=vocab.OBSERVED,
            props={
                "port": port,
                "proto": proto.lower(),
                "host": str(row.get("host", "")),
                "scan_mode": str(row.get("scan_mode", "")),
                "discovered_by": [str(row.get("source", "")) or "scan"],
            },
            evidence=f"open {proto}/{port} observed by {row.get('source') or 'our scan'}",
            max_nodes=max_nodes,
            max_evidence=max_evidence,
        )
        model.add_edge(
            vocab.EXPOSES_SERVICE,
            vocab.node_id(vocab.IP, address),
            service_id,
            source=SOURCE_LABEL["open_ports"],
            trust=vocab.OBSERVED,
            evidence=f"{proto}/{port} answered ({row.get('scan_mode') or 'scan'})",
            max_edges=max_edges,
            max_evidence=max_evidence,
        )

    # A third party's index of the same address: ports and hostnames we did not
    # observe ourselves, so everything from here is discovered.
    for row in source.streams.get("passive_intel", []):
        address = norm.address_identity(str(row.get("ip", "")))
        if not address:
            continue
        address_id = vocab.node_id(vocab.IP, address)
        age = row.get("intel_age_days")
        evidence = (
            f"InternetDB index{f' ({age}d old)' if isinstance(age, int) else ''}"
        )
        model.add_node(
            vocab.IP,
            address,
            source=SOURCE_LABEL["passive_intel"],
            trust=vocab.DISCOVERED,
            props={
                "intel_tags": _as_list(row.get("tags")),
                "intel_vulns": _as_list(row.get("vulns")),
                "intel_cpes": _as_list(row.get("cpes")),
            },
            evidence=evidence,
            max_nodes=max_nodes,
            max_evidence=max_evidence,
        )
        for raw_port in _as_list(row.get("ports")):
            port = _port_number(raw_port)
            if port is None:
                continue
            service = norm.service_identity(address, port, "tcp")
            model.add_node(
                vocab.SERVICE,
                service,
                source=SOURCE_LABEL["passive_intel"],
                trust=vocab.DISCOVERED,
                props={"port": port, "proto": "tcp", "discovered_by": ["internetdb"]},
                evidence=f"TCP/{port} indexed by Shodan InternetDB",
                max_nodes=max_nodes,
                max_evidence=max_evidence,
            )
            model.add_edge(
                vocab.EXPOSES_SERVICE,
                address_id,
                vocab.node_id(vocab.SERVICE, service),
                source=SOURCE_LABEL["passive_intel"],
                trust=vocab.DISCOVERED,
                evidence=evidence,
                max_edges=max_edges,
                max_evidence=max_evidence,
            )
        for hostname in _as_list(row.get("hostnames")):
            host = norm.domain_identity(str(hostname))
            if not host:
                continue
            model.add_node(
                vocab.DOMAIN,
                host,
                source=SOURCE_LABEL["passive_intel"],
                trust=vocab.DISCOVERED,
                evidence=evidence,
                max_nodes=max_nodes,
                max_evidence=max_evidence,
            )
            model.add_edge(
                vocab.ATTRIBUTED_TO,
                vocab.node_id(vocab.DOMAIN, host),
                address_id,
                source=SOURCE_LABEL["passive_intel"],
                trust=vocab.DISCOVERED,
                evidence=f"InternetDB lists {host} on {address}",
                max_edges=max_edges,
                max_evidence=max_evidence,
            )

    # Reverse DNS: the mirror of a resolution, and a different claim.
    for row in source.streams.get("ptr", []):
        address = norm.address_identity(str(row.get("ip", "")))
        if not address:
            continue
        for hostname in _ptr_names(row):
            host = norm.domain_identity(hostname)
            if not host:
                continue
            model.add_node(
                vocab.DOMAIN,
                host,
                source=SOURCE_LABEL["ptr"],
                trust=vocab.DISCOVERED,
                evidence="PTR record",
                max_nodes=max_nodes,
                max_evidence=max_evidence,
            )
            model.add_edge(
                vocab.PTR_MAPS_TO,
                vocab.node_id(vocab.IP, address),
                vocab.node_id(vocab.DOMAIN, host),
                source=SOURCE_LABEL["ptr"],
                trust=vocab.DISCOVERED,
                evidence=f"PTR for {address}",
                max_edges=max_edges,
                max_evidence=max_evidence,
            )

    # Hosting verdicts: a judgement, so inferred, carrying the evidence it was
    # made from.
    for row in source.streams.get("verdicts", []):
        address = norm.address_identity(str(row.get("ip", "")))
        verdict = str(row.get("verdict", "")).strip()
        if not address or not verdict:
            continue
        address_id = vocab.node_id(vocab.IP, address)
        provider = str(row.get("provider", "")).strip()
        model.add_node(
            vocab.IP,
            address,
            source=SOURCE_LABEL["verdicts"],
            trust=vocab.DISCOVERED,
            props={
                "hosting_verdict": verdict,
                "hosting_provider": provider,
                "hosting_confidence": str(row.get("confidence", "")),
            },
            evidence=f"classified as {verdict}"
            + (f" ({provider})" if provider else ""),
            max_nodes=max_nodes,
            max_evidence=max_evidence,
        )
        if not provider:
            continue
        org_id = vocab.node_id(vocab.ORGANIZATION, norm.organization_identity(provider))
        model.add_node(
            vocab.ORGANIZATION,
            norm.organization_identity(provider),
            source=SOURCE_LABEL["verdicts"],
            trust=vocab.DISCOVERED,
            props={"names": [provider], "role": "hosting_provider"},
            max_nodes=max_nodes,
            max_evidence=max_evidence,
        )
        model.add_edge(
            vocab.HOSTED_BY,
            address_id,
            org_id,
            source=SOURCE_LABEL["verdicts"],
            trust=vocab.INFERRED,
            props={"verdict": verdict, "confidence": str(row.get("confidence", ""))},
            evidence=_first(_as_list(row.get("evidence"))) or f"classified as {verdict}",
            max_edges=max_edges,
            max_evidence=max_evidence,
        )


def _merge_urls(
    result: MergeResult,
    source: SourceFacts,
    *,
    max_nodes: int | None,
    max_edges: int | None,
    max_evidence: int,
) -> None:
    model = result.model

    # Roles are collected here rather than merged as properties: a URL that
    # appears in two derived artifacts is one node with both roles, and a
    # property merge would call the second role a conflict.
    roles: dict[str, set[str]] = {}

    for row in source.streams.get("urls", []):
        url = norm.url_identity(str(row.get("url", "")))
        if not url:
            continue
        host = norm.domain_identity(str(row.get("host", "")))
        kind = str(row.get("kind", "")).strip()
        if kind:
            roles.setdefault(url, set()).add(kind)
        model.add_node(
            vocab.URL,
            url,
            source=SOURCE_LABEL["urls"],
            trust=vocab.DISCOVERED,
            props={"host": host, "path": str(row.get("path", ""))},
            evidence="harvested from historical URL archives",
            max_nodes=max_nodes,
            max_evidence=max_evidence,
        )
        if not host:
            continue
        model.add_node(
            vocab.DOMAIN,
            host,
            source=SOURCE_LABEL["urls"],
            trust=vocab.DISCOVERED,
            evidence="appears as the host of a harvested URL",
            max_nodes=max_nodes,
            max_evidence=max_evidence,
        )
        model.add_edge(
            vocab.HAS_URL,
            vocab.node_id(vocab.DOMAIN, host),
            vocab.node_id(vocab.URL, url),
            source=SOURCE_LABEL["urls"],
            trust=vocab.DISCOVERED,
            props={"kind": str(row.get("kind", ""))},
            evidence=f"harvested from archives for {host}",
            max_edges=max_edges,
            max_evidence=max_evidence,
        )

    for row in source.streams.get("url_hosts", []):
        token = str(row.get("value", "")).strip()
        if not token:
            continue
        model.add_node(
            vocab.DOMAIN,
            norm.domain_identity(token),
            source=SOURCE_LABEL["url_hosts"],
            trust=vocab.DISCOVERED,
            evidence="appears as the host of a harvested URL",
            max_nodes=max_nodes,
            max_evidence=max_evidence,
        )

    for stream, role, label in URL_ROLE_STREAMS:
        for row in source.streams.get(stream, []):
            token = str(row.get("value", "")).strip()
            if not token:
                continue
            url = norm.url_identity(token)
            roles.setdefault(url, set()).add(role)
            model.add_node(
                vocab.URL,
                url,
                source=SOURCE_LABEL[stream],
                trust=vocab.DISCOVERED,
                evidence=label,
                max_nodes=max_nodes,
                max_evidence=max_evidence,
            )
            # The URL's own authority is a fact about the URL, not an inference:
            # a derived list carries full URLs, so their host is stated, not
            # guessed, and the edge is the same claim ``urls.jsonl`` makes.
            host = _host_of(url)
            if not host:
                continue
            model.add_node(
                vocab.DOMAIN,
                host,
                source=SOURCE_LABEL[stream],
                trust=vocab.DISCOVERED,
                evidence=f"authority of a URL in the {stream} list",
                max_nodes=max_nodes,
                max_evidence=max_evidence,
            )
            model.add_edge(
                vocab.HAS_URL,
                vocab.node_id(vocab.DOMAIN, host),
                vocab.node_id(vocab.URL, url),
                source=SOURCE_LABEL[stream],
                trust=vocab.DISCOVERED,
                evidence=label,
                max_edges=max_edges,
                max_evidence=max_evidence,
            )

    # Parameters: names with no URL linkage in the artifact, so nodes only — and
    # the report counts them as unlinked rather than inventing an edge.
    for row in source.streams.get("parameters", []):
        name = str(row.get("value", "")).strip()
        if not name:
            continue
        model.add_node(
            vocab.PARAMETER,
            name,
            source=SOURCE_LABEL["parameters"],
            trust=vocab.DISCOVERED,
            props={"name": name},
            evidence=(
                "harvested parameter name; the URL pipeline's artifact carries no "
                "URL linkage for it, so no edge is stated"
            ),
            max_nodes=max_nodes,
            max_evidence=max_evidence,
        )
        result.unlinked.append(vocab.node_id(vocab.PARAMETER, name))

    _mark_roles(result, roles)


def _merge_networks(
    result: MergeResult,
    source: SourceFacts,
    *,
    max_nodes: int | None,
    max_edges: int | None,
    max_evidence: int,
) -> None:
    model = result.model

    for row in source.streams.get("networks", []):
        network = norm.network_identity(str(row.get("network", "")))
        if not network:
            continue
        network_id = vocab.node_id(vocab.NETWORK, network)
        classes = _as_list(row.get("classes"))
        as_names = row.get("as_names") if isinstance(row.get("as_names"), dict) else {}
        model.add_node(
            vocab.NETWORK,
            network,
            source=SOURCE_LABEL["networks"],
            trust=vocab.DISCOVERED,
            props={
                "classes": classes,
                "num_addresses": row.get("num_addresses"),
                "known_hosts": row.get("known_hosts"),
                "registry": str(row.get("registry", "")),
                "org": str(row.get("org", "")),
            },
            evidence="network-ownership lookup (RIPEstat/RDAP): "
            + "/".join(_strings(classes) or ["claim"]),
            max_nodes=max_nodes,
            max_evidence=max_evidence,
        )
        for asn_value in _as_list(row.get("asns")):
            asn = str(asn_value).strip()
            if not asn:
                continue
            as_name = str(as_names.get(asn, "")) if isinstance(as_names, dict) else ""
            model.add_node(
                vocab.ASN,
                asn,
                source=SOURCE_LABEL["networks"],
                trust=vocab.DISCOVERED,
                props={"as_name": as_name},
                max_nodes=max_nodes,
                max_evidence=max_evidence,
            )
            if "announced" in classes:
                model.add_edge(
                    vocab.ANNOUNCED_BY,
                    network_id,
                    vocab.node_id(vocab.ASN, asn),
                    source=SOURCE_LABEL["networks"],
                    trust=vocab.DISCOVERED,
                    evidence=f"RIPEstat: AS{asn} announces {network}",
                    max_edges=max_edges,
                    max_evidence=max_evidence,
                )
            if as_name:
                org_id = vocab.node_id(vocab.ORGANIZATION, norm.organization_identity(as_name))
                model.add_node(
                    vocab.ORGANIZATION,
                    norm.organization_identity(as_name),
                    source=SOURCE_LABEL["networks"],
                    trust=vocab.DISCOVERED,
                    props={"names": [as_name]},
                    max_nodes=max_nodes,
                    max_evidence=max_evidence,
                )
                model.add_edge(
                    vocab.REGISTERED_TO,
                    vocab.node_id(vocab.ASN, asn),
                    org_id,
                    source=SOURCE_LABEL["networks"],
                    trust=vocab.DISCOVERED,
                    evidence=f"registry names AS{asn} as {as_name}",
                    max_edges=max_edges,
                    max_evidence=max_evidence,
                )
        # Allocation is a claim *about the network*, not about any AS, so it is
        # read here rather than inside the loop above: a pure allocation row
        # (RDAP says "Cloudflare holds 104.16.0.0/12", with no announcement in
        # the registry's routing view) carries no ASN at all, and nesting this in
        # the ASN loop silently dropped exactly those claims.
        if "allocated" in classes:
            holder = str(row.get("org", "")).strip() or str(row.get("org_handle", "")).strip()
            if holder:
                org_id = vocab.node_id(vocab.ORGANIZATION, norm.organization_identity(holder))
                model.add_node(
                    vocab.ORGANIZATION,
                    norm.organization_identity(holder),
                    source=SOURCE_LABEL["networks"],
                    trust=vocab.DISCOVERED,
                    props={
                        "org": str(row.get("org", "")),
                        "handles": [str(row.get("org_handle", ""))] if row.get("org_handle") else [],
                    },
                    max_nodes=max_nodes,
                    max_evidence=max_evidence,
                )
                model.add_edge(
                    vocab.ALLOCATED_TO,
                    network_id,
                    org_id,
                    source=SOURCE_LABEL["networks"],
                    trust=vocab.DISCOVERED,
                    evidence=f"RDAP allocation: {holder} holds {network}",
                    max_edges=max_edges,
                    max_evidence=max_evidence,
                )

    for row in source.streams.get("asns", []):
        asn = str(row.get("asn", "")).strip()
        if not asn:
            continue
        model.add_node(
            vocab.ASN,
            asn,
            source=SOURCE_LABEL["asns"],
            trust=vocab.DISCOVERED,
            props={
                "as_name": str(row.get("as_name", "")),
                "network_count": row.get("networks"),
                "origins": _as_list(row.get("origins")),
            },
            max_nodes=max_nodes,
            max_evidence=max_evidence,
        )


# --------------------------------------------------------------------------- #
# post-passes
# --------------------------------------------------------------------------- #


def _mark_roles(result: MergeResult, roles: dict[str, set[str]]) -> None:
    """Attach the union of derived-artifact roles to each URL node.

    A URL that appears in ``endpoints.txt`` *and* ``javascript.txt`` is one node
    with both roles: the derived lists are facets of the same asset, not separate
    assets.  A URL whose *host* the names pipeline resolved keeps its own
    ``resolves_to`` edge — that is the host answering, a different claim.
    """
    for node in result.model.nodes.values():
        if node.kind != vocab.URL:
            continue
        node.props["roles"] = sorted(roles.get(node.identity, set()))


def _merge_wildcard_coverage(
    result: MergeResult,
    *,
    max_edges: int | None,
    cap: int,
    max_evidence: int,
) -> None:
    """State which known hosts a wildcard answer covers.

    Bounded on purpose: the relationship is real, but a single ``*.example.com``
    can restate it thousands of times.  The count of covered hosts always lands
    as a node property; the edges stop at the cap, and the report says how many
    were withheld.
    """
    wildcards = [node for node in result.model.nodes.values() if node.kind == vocab.WILDCARD]
    domains = sorted(
        (node for node in result.model.nodes.values() if node.kind == vocab.DOMAIN),
        key=lambda node: node.identity,
    )
    for wildcard in wildcards:
        suffix = wildcard.identity.removeprefix("*.")
        covered = [
            node
            for node in domains
            if node.identity != suffix and node.identity.endswith("." + suffix)
        ]
        wildcard.props["covers_known_hosts"] = len(covered)
        for node in covered[:cap]:
            result.model.add_edge(
                vocab.WILDCARD_COVERS,
                wildcard.id,
                node.id,
                source=SOURCE_LABEL["wildcards"],
                trust=vocab.INFERRED,
                evidence=f"the wildcard answer for {wildcard.identity} covers this host",
                max_edges=max_edges,
                max_evidence=max_evidence,
            )
        if len(covered) > cap:
            result.wildcard_edges_truncated += len(covered) - cap


def _annotate_scores(
    result: MergeResult, *, scored: bool, max_audit: int, top: int
) -> None:
    """Attach the platform's S2 score and band to every node.

    The pass runs after scope annotation because the penalties read the model's
    own relationships (wildcard coverage, resolutions, hosting verdicts) — the
    score is a statement about the finished model, not about a row.
    """
    from . import score as score_mod

    if not scored:
        result.score_stats = score_mod.ScoreStats(skipped="GN_SCORE_MODEL is off")
        return
    result.score_stats = score_mod.score_model(
        result.model, max_audit=max_audit, top_limit=top
    )


def _annotate_scope(result: MergeResult, scope) -> None:
    """Attach the platform's scope verdict to every node that poses the question.

    Domains, addresses and networks are the kinds a scope decision applies to;
    URLs, services, parameters, ASNs and organisations are objects, not places,
    and are left unannotated rather than being given a meaningless verdict.

    Discovered networks are registered with the engine first, which is what makes
    their answers ``needs_review`` instead of ``out_of_scope``: the model then
    carries the platform's verdict *and* the reason for it.
    """
    if scope is None:
        return
    registered = 0
    for node in result.model.nodes.values():
        if node.kind == vocab.NETWORK:
            scope.add_discovered_network(node.identity)
            registered += 1
    result.registered_networks = registered
    for node in result.model.nodes.values():
        if node.kind == vocab.DOMAIN:
            decision = scope.check_host(node.identity)
        elif node.kind == vocab.IP:
            decision = scope.check_address(node.identity)
        elif node.kind == vocab.NETWORK:
            decision = scope.check_network(node.identity)
        else:
            continue
        node.props["scope_state"] = decision.state
        node.props["scope_reason"] = decision.reason
    result.scope_applied = True


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #


def _as_list(value: object) -> list[object]:
    if value in (None, "", [], {}):
        return []
    if isinstance(value, (list, tuple, set)):
        return [item for item in value if item not in (None, "")]
    return [value]


def _host_of(url: str) -> str:
    """The canonical host stated by a URL's own authority component."""
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return ""
    return norm.domain_identity(host)


def _strings(values: list[object]) -> list[str]:
    """Non-empty string forms of a loose list, for joining into prose."""
    return [str(value).strip() for value in values if str(value).strip()]


def _port_number(value: object) -> int | None:
    """A port number, or None when the artifact row did not carry one."""
    if value in (None, ""):
        return None
    try:
        port = int(str(value))
    except ValueError:
        return None
    return port if 0 < port < 65536 else None


def _first(values: list[object]) -> str:
    for value in values:
        token = str(value).strip()
        if token:
            return token
    return ""


def _ptr_names(row: dict) -> list[str]:
    """PTR names from whichever key the ports stage's runner used."""
    names: list[str] = []
    for key in ("names", "hostnames", "ptr", "hostname", "host", "name"):
        for value in _as_list(row.get(key)):
            token = str(value).strip()
            if token:
                names.append(token)
    return names
