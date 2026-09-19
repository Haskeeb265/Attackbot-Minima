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
    "parameter_observations": "url_endpoint:parameter-observations",
    "url_validations": "url_endpoint:validation",
    "networks": "asn_cidr:networks",
    "asns": "asn_cidr:asns",
    # cloud pipeline
    "buckets": "cloud_resource:probe",
    "dangling": "cloud_resource:dangling",
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
    #: Distinct ``(url, parameter)`` observations, built from the URL stage's
    #: ``parameters.jsonl``.  Distinct because the artifact may repeat a pair
    #: (two sources saw the same query); the graph carries the same fact as
    #: ``observed_parameter`` edges, and the count must not exceed them.
    parameter_observations: int = 0
    #: The pairs already counted, so a repeated row cannot inflate the count.
    observed_pairs: set = field(default_factory=set, repr=False)
    parameter_urls: dict[str, list[str]] = field(default_factory=dict)
    #: URL live-validation outcomes, for the report's own accounting.
    url_validations: int = 0
    urls_live: int = 0
    urls_dead: int = 0
    #: Networks by relevance state (``discovered`` … ``active_candidate``).
    networks_by_relevance: dict[str, int] = field(default_factory=dict)
    #: What the escalation policy decided, per operation.
    escalation: dict[str, object] = field(default_factory=dict)
    #: The assets the policy says are worth active validation, best-first.
    active_candidates: list[dict[str, object]] = field(default_factory=list)
    #: One row per *refused* candidate: the asset, the operation, the rule that
    #: refused it and the reason in full.  Written as an artifact because "0
    #: eligible / 33 considered" is only actionable next to the rule that fired,
    #: and because a refusal nobody can list is indistinguishable from an asset
    #: nobody looked at.
    escalation_refusals: list[dict[str, object]] = field(default_factory=list)
    #: Addresses the scope engine accepted on DNS evidence (see
    #: ``ScopeEngine.add_resolved_address``) — the bridge that let the target's
    #: own addresses reach the policy at all.
    dns_scoped_addresses: int = 0


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
    plan_escalation: bool = settings.PLAN_ESCALATION,
    allow_needs_review: bool = settings.ESCALATION_ALLOW_NEEDS_REVIEW,
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
    _annotate_network_relevance(result)
    _annotate_scores(result, scored=scored, max_audit=max_score_audit, top=top_scored)
    # Last, because it reads every annotation above it: the policy decides what
    # deserves active work from the *finished* model (scope verdicts, hosting
    # classes, evidence states), never from a row.
    if plan_escalation:
        _plan_escalation(result, scope, allow_needs_review=allow_needs_review)
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
        "cloud_resource": _merge_cloud,
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
            at=str(row.get("timestamp", "")),
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
                    at=str(row.get("timestamp", "")),
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
                    at=str(row.get("timestamp", "")),
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
                    vocab.OWNED_BY,
                    asn_id,
                    org_id,
                    source=SOURCE_LABEL["ownership"],
                    trust=vocab.DISCOVERED,
                    props={"claim": "registration"},
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
                    vocab.OWNED_BY,
                    network_id,
                    org_id,
                    source=SOURCE_LABEL["ownership"],
                    trust=vocab.DISCOVERED,
                    props={"claim": "allocation"},
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
                vocab.RESOLVES_TO,
                vocab.node_id(vocab.DOMAIN, host),
                address_id,
                source=SOURCE_LABEL["passive_intel"],
                trust=vocab.DISCOVERED,
                props={"method": "shodan"},
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
                vocab.RESOLVES_TO,
                vocab.node_id(vocab.IP, address),
                vocab.node_id(vocab.DOMAIN, host),
                source=SOURCE_LABEL["ptr"],
                trust=vocab.DISCOVERED,
                props={"method": "ptr"},
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
                # Explicit, because its *absence* is a state the policy acts on: a
                # verdict of ``unknown`` means the classifier looked and found no
                # signal, while a missing verdict means nobody looked.  Only an
                # address with a row here can reach a port scan.
                "hosting_classified": True,
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

    _merge_url_validations(
        result, source, max_nodes=max_nodes, max_edges=max_edges, max_evidence=max_evidence
    )
    _merge_parameter_observations(
        result, source, max_nodes=max_nodes, max_edges=max_edges, max_evidence=max_evidence
    )

    # Parameters: names the URL pipeline harvested.  A name that carries an
    # observation above already has its ``observed_parameter`` edge; what is left
    # here is a name whose artifact predates ``parameters.jsonl`` (or which the
    # observation rows filtered out), and *that* is what the report counts as
    # unlinked — the honest answer, rather than inventing an edge from every URL
    # to every name.
    for row in source.streams.get("parameters", []):
        name = str(row.get("value", "")).strip()
        if not name:
            continue
        linked = bool(result.parameter_urls.get(name))
        model.add_node(
            vocab.PARAMETER,
            name,
            source=SOURCE_LABEL["parameters"],
            trust=vocab.DISCOVERED,
            props={"name": name},
            evidence=(
                "harvested parameter name, observed on at least one URL"
                if linked
                else (
                    "harvested parameter name; the URL pipeline's artifact carries "
                    "no URL linkage for it, so no edge is stated"
                )
            ),
            max_nodes=max_nodes,
            max_evidence=max_evidence,
        )
        if not linked:
            result.unlinked.append(vocab.node_id(vocab.PARAMETER, name))

    _mark_roles(result, roles)


def _merge_url_validations(
    result: MergeResult,
    source: SourceFacts,
    *,
    max_nodes: int | None,
    max_edges: int | None,
    max_evidence: int,
) -> None:
    """Fold live validation records onto the URL nodes they measured.

    Discovery and validation stay separate claims: the node keeps its historical
    ``sources`` (the archives that mentioned it) *and* gains the validation's own
    provenance.  The record's own words become ``props.validation_*`` — status,
    final URL, redirect chain, content type, title, server, technology and the
    timestamp — so a consumer can tell ``historically discovered`` from
    ``currently verified``, ``currently dead``, ``redirected`` and ``errored``
    without going back to the URL stage's artifact.
    """
    model = result.model
    label = SOURCE_LABEL["url_validations"]

    for row in source.streams.get("url_validations", []):
        url = norm.url_identity(str(row.get("url", "")))
        if not url:
            continue
        state = str(row.get("state", "")).strip()
        status = _port_number(row.get("status"))
        final_url = norm.url_identity(str(row.get("final_url", "")))
        chain = _as_list(row.get("redirect_chain"))
        # Two different statements, kept apart on purpose: ``alive`` is "a server
        # answered" (a 404 answers), ``serving`` is "this URL serves something"
        # (a 200/3xx).  Collapsing them would make a 404 look like a live asset,
        # which is the exact confusion this whole stage exists to remove.
        alive = bool(row.get("alive"))
        serving = state in {"verified", "redirected"}
        url_id = vocab.node_id(vocab.URL, url)

        model.add_node(
            vocab.URL,
            url,
            source=label,
            trust=vocab.OBSERVED,
            props={
                "validation_state": state,
                "alive": alive,
                "serving": serving,
                "http_status": status,
                "final_url": final_url,
                "redirect_chain": chain,
                "content_type": str(row.get("content_type", "")),
                "title": str(row.get("title", "")),
                "server": str(row.get("server", "")),
                "tech": _as_list(row.get("tech")),
                "validated_at": str(row.get("validated_at", "")),
                "validation_tool": str(row.get("validation_tool", "")),
                "validation_source": "active",
            },
            evidence=(
                f"live validation ({row.get('validation_tool') or 'httpx'}): "
                f"{state or 'unknown'}" + (f" {status}" if status is not None else "")
            ),
            max_nodes=max_nodes,
            max_evidence=max_evidence,
            at=str(row.get("validated_at", "")),
        )
        result.url_validations += 1
        if serving:
            result.urls_live += 1
        elif state in {"dead", "unreachable"}:
            result.urls_dead += 1

        if not final_url or final_url == url:
            continue
        if state != "redirected" and not chain:
            # A URL the tool reported at a different location *without* observing a
            # redirect hop is an artefact of a failed probe (httpx normalises the
            # scheme on an error response), not a relationship worth stating.
            continue
        # A redirect is a relationship between two URLs we know, not a property
        # that overwrites the first one: the archived URL *and* where it went are
        # both assets, and a later run validating the destination corroborates
        # this edge rather than replacing it.
        model.add_node(
            vocab.URL,
            final_url,
            source=label,
            trust=vocab.OBSERVED,
            evidence=f"the final URL of {url} (redirect target)",
            max_nodes=max_nodes,
            max_evidence=max_evidence,
        )
        model.add_edge(
            vocab.REDIRECTS_TO,
            url_id,
            vocab.node_id(vocab.URL, final_url),
            source=label,
            trust=vocab.OBSERVED,
            props={
                "chain": chain,
                "status": status,
                "observed_at": str(row.get("validated_at", "")),
            },
            evidence=f"{url} answered with a redirect to {final_url}",
            max_edges=max_edges,
            max_evidence=max_evidence,
            at=str(row.get("validated_at", "")),
        )

    # Contradictions are *represented*, not resolved by dropping one of the two
    # claims: an archived URL that now answers 404 is a real, useful fact (the
    # endpoint moved or was retired), and a model that quietly deleted the
    # historical claim would hide the only evidence of where it went.  The URL
    # keeps both, says so in ``evidence_conflicts``, and the scoring pass applies
    # the engine's dead-host penalty on top of the historical claim's weight.
    historical_labels = {
        SOURCE_LABEL[stream] for stream in ("urls", "endpoints", "javascript", "interesting")
    }
    for node in result.model.nodes.values():
        if node.kind != vocab.URL:
            continue
        if str(node.props.get("validation_state", "")) not in {"dead", "unreachable"}:
            continue
        if not (set(node.sources) & historical_labels):
            continue
        node.props["evidence_conflicts"] = sorted(
            {
                *[str(item) for item in _as_list(node.props.get("evidence_conflicts"))],
                "historical archive claim contradicted by live validation "
                f"({node.props.get('validation_state')})",
            }
        )


def _merge_parameter_observations(
    result: MergeResult,
    source: SourceFacts,
    *,
    max_nodes: int | None,
    max_edges: int | None,
    max_evidence: int,
) -> None:
    """State ``url --observed_parameter--> parameter`` for every observation.

    The pair — not the name — is the unit: one parameter seen on forty URLs is
    forty edges on one node, and one URL exposing eight parameters is eight edges
    on one URL.  Both questions the model has to answer ("which URLs expose this
    parameter?", "which parameters were observed on this URL?") are then a single
    traversal, and neither is answered by a flat name list.
    """
    model = result.model
    label = SOURCE_LABEL["parameter_observations"]

    for row in source.streams.get("parameter_observations", []):
        name = str(row.get("parameter", "")).strip()
        url = norm.url_identity(str(row.get("url", "")))
        if not name or not url:
            continue
        location = str(row.get("location", "") or "query")
        model.add_node(
            vocab.PARAMETER,
            name,
            source=label,
            trust=vocab.DISCOVERED,
            props={"name": name, "locations": [location]},
            evidence=f"observed on a harvested URL ({location})",
            max_nodes=max_nodes,
            max_evidence=max_evidence,
        )
        model.add_node(
            vocab.URL,
            url,
            source=label,
            trust=vocab.DISCOVERED,
            evidence="carries a harvested query parameter",
            max_nodes=max_nodes,
            max_evidence=max_evidence,
        )
        model.add_edge(
            vocab.OBSERVED_PARAMETER,
            vocab.node_id(vocab.URL, url),
            vocab.node_id(vocab.PARAMETER, name),
            source=label,
            trust=vocab.DISCOVERED,
            props={
                "location": location,
                "path": str(row.get("path", "")),
                "kind": str(row.get("kind", "")),
            },
            evidence=f"{name} was observed on {url} ({location})",
            max_edges=max_edges,
            max_evidence=max_evidence,
        )
        pair = (url, name)
        if pair not in result.observed_pairs:
            result.observed_pairs.add(pair)
            result.parameter_observations += 1
        result.parameter_urls.setdefault(name, [])
        if url not in result.parameter_urls[name]:
            result.parameter_urls[name].append(url)


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
                    vocab.OWNED_BY,
                    vocab.node_id(vocab.ASN, asn),
                    org_id,
                    source=SOURCE_LABEL["networks"],
                    trust=vocab.DISCOVERED,
                    props={"claim": "registration"},
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
                    vocab.OWNED_BY,
                    network_id,
                    org_id,
                    source=SOURCE_LABEL["networks"],
                    trust=vocab.DISCOVERED,
                    props={"claim": "allocation"},
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
# cloud pipeline
# --------------------------------------------------------------------------- #


_CLOUD_OUTCOME = {
    "open": "open",
    "auth_required": "auth_required",
    "dangling": "dangling",
    "absent": "dangling",
    "nxdomain_absent": "dangling",
    "exists_other_region": "exists_other_region",
}


def _merge_cloud(
    result: MergeResult,
    source: SourceFacts,
    *,
    max_nodes: int | None,
    max_edges: int | None,
    max_evidence: int,
) -> None:
    """Cloud resources: the one asset kind the file model was missing.

    A bucket row becomes a ``cloud`` node whose identity is ``provider:name`` —
    the two facts about it that never change — with the probe outcome as
    properties.  A row with CNAME claimants also writes one ``cname_points_to``
    edge per claimant: the dangling reference, the run's most actionable
    finding, is one traversable edge carrying its outcome, not a row in a pile.
    """
    model = result.model
    label = SOURCE_LABEL["buckets"]

    # One write per bucket: the *latest* probe's outcome is the node's state
    # (that is what ``last_seen`` semantics mean), and the rows for one bucket
    # are folded before any write so a later probe never dies as a property
    # conflict.  Claimants union across every probe row; outcome, code and
    # status come from the newest row.
    grouped: dict[tuple[str, str], list[dict]] = {}
    for row in source.streams.get("buckets", []):
        name = str(row.get("name", "")).strip().lower()
        provider = str(row.get("provider", "")).strip().lower()
        if not name or not provider:
            continue
        grouped.setdefault((provider, name), []).append(row)
    for (provider, name), rows in sorted(grouped.items()):
        row = max(rows, key=lambda item: str(item.get("probed_at", "")))
        claimants = sorted({str(c) for item in rows for c in _as_list(item.get("claimants"))})
        state = str(row.get("state", "")).strip()
        outcome = _CLOUD_OUTCOME.get(state, "")
        at = str(row.get("probed_at", ""))
        # A distinctive CNAME-claimed bucket is an asset the target's own DNS
        # vouched for; a brand-derived candidate is a guess about naming, so it
        # stays discovered.  Decided *before* the write: trust merges by taking
        # the strongest claim, so a wrong first write cannot be taken back.
        trust = vocab.OBSERVED if "cname" in _as_list(row.get("origins")) else vocab.DISCOVERED
        cloud_identity = norm.cloud_identity(provider, name)
        cloud_id = vocab.node_id(vocab.CLOUD, cloud_identity)
        model.add_node(
            vocab.CLOUD,
            cloud_identity,
            source=label,
            trust=trust,
            props={
                "provider": provider,
                "bucket": name,
                # The outcome of the latest probe: open (listable), auth_required
                # (exists, refuses anonymous reads), dangling (the provider says
                # no such bucket), exists_other_region.  ``unavailable`` rows
                # carry no outcome — the probe failed, which is not knowledge.
                **({"outcome": outcome} if outcome else {}),
                **({"probe_code": str(row.get("code", ""))} if row.get("code") else {}),
                "probe_url": str(row.get("probe_url", "")),
                "http_status": row.get("http_status"),
                "evidence_class": str(row.get("evidence_class", "")),
            },
            evidence=f"probed: {state or 'unknown'}"
            + (f" ({row.get('code')})" if row.get("code") else ""),
            max_nodes=max_nodes,
            max_evidence=max_evidence,
            at=at,
        )
        # The edge is the finding: name -> cloud, with the outcome on it.  A row
        # without claimants (derived/branded candidates) writes no edge — there is
        # no name to hang it on, and inventing one would fabricate the relation.
        for claimant in claimants:
            host = norm.domain_identity(str(claimant))
            if not host:
                continue
            model.add_node(
                vocab.DOMAIN,
                host,
                source=label,
                trust=vocab.OBSERVED,
                evidence="this host's DNS names a cloud resource",
                max_nodes=max_nodes,
                max_evidence=max_evidence,
                at=at,
            )
            model.add_edge(
                vocab.CNAME_POINTS_TO,
                vocab.node_id(vocab.DOMAIN, host),
                cloud_id,
                source=label,
                trust=vocab.OBSERVED,
                props={
                    **({"outcome": outcome} if outcome else {}),
                    **({"code": str(row.get("code", ""))} if row.get("code") else {}),
                    "probe_url": str(row.get("probe_url", "")),
                },
                evidence=f"CNAME claim probed: {state or 'unknown'}",
                max_edges=max_edges,
                max_evidence=max_evidence,
                at=at,
            )

    # The dangling artifact restates the strongest subset — keep it merged into
    # the same nodes/edges rather than a second model: the artifact exists so the
    # finding survives on its own, and reading it here corroborates the rows the
    # buckets stream already produced.
    for row in source.streams.get("dangling", []):
        name = str(row.get("name", "")).strip().lower()
        provider = str(row.get("provider", "")).strip().lower()
        at = str(row.get("probed_at", ""))
        if not name or not provider:
            continue
        cloud_identity = norm.cloud_identity(provider, name)
        cloud_id = vocab.node_id(vocab.CLOUD, cloud_identity)
        model.add_node(
            vocab.CLOUD,
            cloud_identity,
            source=SOURCE_LABEL["dangling"],
            trust=vocab.OBSERVED,
            props={"outcome": "dangling"},
            evidence="CNAME-claimed resource the provider reports as absent",
            max_nodes=max_nodes,
            max_evidence=max_evidence,
            at=at,
        )
        for claimant_row in _as_list(row.get("claimants")):
            host = norm.domain_identity(str(claimant_row))
            if not host:
                continue
            model.add_edge(
                vocab.CNAME_POINTS_TO,
                vocab.node_id(vocab.DOMAIN, host),
                cloud_id,
                source=SOURCE_LABEL["dangling"],
                trust=vocab.OBSERVED,
                props={"outcome": "dangling", "code": str(row.get("code", ""))},
                evidence="CNAME-claimed resource the provider reports as absent",
                max_edges=max_edges,
                max_evidence=max_evidence,
                at=at,
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


def derived_operations(model: norm.Model, node: norm.Node) -> set[str]:
    """Which operations the model's own evidence says have already happened.

    Read out of the *relationships and provenance* the merge already recorded,
    never out of a new mutable field: a ``resolves_to`` edge whose source is our
    records stream **is** the record that DNS resolution was attempted for that
    host, and a validated URL is a URL an experiment already touched.  Deriving
    it keeps one notion of "done" in the model, and the escalation policy uses it
    to refuse paying for the same work twice (see :mod:`platform.escalation`).

    Idempotency that lives in a *property* would be a second source of truth that
    a half-finished run could disagree with.
    """
    operations: set[str] = set()
    sources = set(node.sources)
    records = SOURCE_LABEL["records"]
    scan = SOURCE_LABEL["open_ports"]
    validations = SOURCE_LABEL["url_validations"]

    # ``scan`` is **our own** output and the only sound proof that a scan happened.
    # A third party's index (``intel``) is a claim *about* an address, not a record
    # that we touched it, and treating it as a completed operation refused a
    # legitimate escalation: on the measured run the target's one ``dedicated``
    # address was refused as "port_scan already attempted" because InternetDB had
    # seen an open port on it.  The evidence to act on a third party's finding is
    # to verify it, and "already attempted" must mean attempted by us.
    if node.kind in (vocab.IP, vocab.SERVICE) and scan in sources:
        operations.add("port_scan")
    if node.kind == vocab.DOMAIN and records in sources:
        operations.add("dns_resolution")
    if node.kind == vocab.CLOUD and SOURCE_LABEL["buckets"] in sources:
        # Our own probe is the only sound proof the bucket was checked — same
        # rule as the scan: a third party's word is not an attempt by us.
        operations.add("cloud_probe")
    if node.kind == vocab.URL and validations in sources:
        operations.add("url_validation")
    if node.kind == vocab.PARAMETER or any(
        edge.type == vocab.OBSERVED_PARAMETER and edge.source_id == node.id
        for edge in model.edges.values()
    ):
        operations.add("parameter_extraction")
    # Deliberately *no* ``network_expansion`` derivation: a network holding hosts
    # our DNS resolved proves discovery happened *inside* it, not that the prefix
    # was enumerated.  Marking it done would refuse the very expansion the
    # relevance state says is worth doing — a network is a candidate until an
    # active pass actually walks it, and the graph has no artifact that says one
    # did.
    return operations


def _annotate_network_relevance(result: MergeResult) -> None:
    """Place every network in the ``discovered → … → active_candidate`` progression.

    The progression the design asks for, applied to facts the model already has:
    an announcement is a routing claim, an ``allocated_to`` edge is a registry's
    ownership claim, and ``known_hosts`` is the count of addresses inside the
    prefix that our own DNS resolution reached.  A broadly announced prefix with
    none of the latter two therefore stays ``discovered`` — it does not become
    operationally equal to a validated target network just by existing, which is
    what stops thousands of unrelated BGP ranges from dominating the model.

    The states are recorded as node properties *and* counted in the report, so
    "how much of this graph is actually the target's" is a number, not an
    impression.
    """
    from service.recon_pipeline.platform import escalation

    allocated_ids = {
        edge.source_id for edge in result.model.edges.values() if edge.type == vocab.OWNED_BY
    }
    counts: dict[str, int] = {}
    for node in result.model.nodes.values():
        if node.kind != vocab.NETWORK:
            continue
        classes = [str(item) for item in _as_list(node.props.get("classes"))]
        relevance = escalation.network_relevance(
            allocated="allocated" in classes or node.id in allocated_ids,
            announced="announced" in classes,
            known_hosts=_as_int(node.props.get("known_hosts")),
            in_scope=str(node.props.get("scope_state", "")) == "in_scope",
        )
        node.props.update(relevance.to_dict())
        counts[relevance.state] = counts.get(relevance.state, 0) + 1
    result.networks_by_relevance = dict(sorted(counts.items()))


def _plan_escalation(
    result: MergeResult, scope, *, allow_needs_review: bool = False
) -> None:
    """Ask the platform's policy which assets deserve active validation next.

    Three operations are planned, because they are the ones a *graph* can hand
    to an execution path: port/service scanning of addresses, live validation of
    URLs, and expansion of networks.  Each candidate carries the reason it was
    allowed and its exact evidence bundle, so the artifact is auditable — and the
    refusals are counted too, because "3 431 networks considered, 40 relevant" is
    the number that matters here, not the queue size.

    Nothing in this pass sends a packet: it writes a plan.  The stages that do
    act read the same policy, so a decision cannot be made twice in two ways.
    """
    from service.recon_pipeline.platform import escalation
    from service.recon_pipeline.platform import scoring as engine

    policy = escalation.EscalationPolicy(allow_needs_review=allow_needs_review)
    operations = (
        escalation.OPERATION_PORT_SCAN,
        escalation.OPERATION_URL_VALIDATION,
        escalation.OPERATION_NETWORK_EXPANSION,
    )
    addresses: list[escalation.AssetEvidence] = []
    urls: list[escalation.AssetEvidence] = []
    networks: list[escalation.AssetEvidence] = []
    # Service evidence *we* measured, computed once for the whole pass: an
    # ``exposes_service`` edge whose trust is ``observed`` is a port an HTTP probe
    # or a scan answered on.  A service node from a third party's index is a lead
    # to verify, not evidence that leaves nothing to escalate (see
    # :func:`derived_operations` for the same distinction on idempotency).
    measured_services = {
        edge.source_id
        for edge in result.model.edges.values()
        if edge.type == vocab.EXPOSES_SERVICE and edge.trust == vocab.OBSERVED
    }

    for node in result.model.nodes.values():
        scope_state = str(node.props.get("scope_state", ""))
        operations_done = frozenset(derived_operations(result.model, node))
        if node.kind == vocab.IP:
            classified = bool(node.props.get("hosting_classified", False))
            addresses.append(
                escalation.AssetEvidence(
                    asset_type="ip",
                    identity=node.identity,
                    scope_state=scope_state,
                    score=node.score,
                    band=node.band,
                    evidence_state=node.evidence_state,
                    hosting=escalation.hosting_class(
                        str(node.props.get("hosting_verdict", "")),
                        str(node.props.get("hosting_provider", "")),
                        classified=classified,
                    ),
                    hosting_classified=classified,
                    origin_declared=_origin_declared(node),
                    origin_address_declared=_declaration_level(node) == "address",
                    has_service_evidence=node.id in measured_services,
                    operations=operations_done,
                )
            )
        elif node.kind == vocab.URL:
            urls.append(
                escalation.AssetEvidence(
                    asset_type="url",
                    identity=node.identity,
                    # A URL is not a place, so the scope engine never annotated it
                    # — but the *host* it names is one, and the URL's scope is its
                    # host's scope.  Without this every URL would be refused for
                    # having no verdict, which is right for an unknown host and
                    # wrong for the target's own.
                    scope_state=_host_scope_state(result.model, node.identity),
                    score=node.score,
                    band=node.band,
                    evidence_state=node.evidence_state
                    or engine.EVIDENCE_HISTORICAL,
                    operations=operations_done,
                )
            )
        elif node.kind == vocab.NETWORK:
            classes = [str(item) for item in _as_list(node.props.get("classes"))]
            networks.append(
                escalation.AssetEvidence(
                    asset_type="network",
                    identity=node.identity,
                    scope_state=scope_state,
                    score=node.score,
                    band=node.band,
                    evidence_state=node.evidence_state,
                    allocated="allocated" in classes,
                    announced="announced" in classes,
                    known_hosts=_as_int(node.props.get("known_hosts")),
                    already_expanded="network_expansion" in operations_done,
                )
            )

    cohort = {
        escalation.OPERATION_PORT_SCAN: addresses,
        escalation.OPERATION_URL_VALIDATION: urls,
        escalation.OPERATION_NETWORK_EXPANSION: networks,
    }
    summary: dict[str, object] = {}
    queue: list[dict[str, object]] = []
    refusals: list[dict[str, object]] = []
    for operation in operations:
        decisions = escalation.plan(cohort[operation], operation, policy=policy)
        block = escalation.summarise(decisions)
        # The per-candidate refusal rows are an artifact of their own; keeping
        # them inside the report block as well would write the same 3 000 rows
        # twice into one JSON document.
        refusals.extend(
            row for row in block.pop("refusals", [])  # type: ignore[arg-type]
        )
        summary[operation] = block
        for decision in decisions:
            if decision.eligible:
                queue.append(decision.to_dict())

    result.escalation = summary
    result.active_candidates = queue
    result.escalation_refusals = sorted(
        refusals, key=lambda row: (str(row["operation"]), str(row["identity"]))
    )


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
    result.dns_scoped_addresses = _register_dns_scope(result, scope)
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


def _register_dns_scope(result: MergeResult, scope) -> int:
    """Hand the engine the model's own DNS evidence: name → address.

    A ``resolves_to`` edge the *records* stream contributed to is a resolution
    we performed, and it is the only thing this adds — no inference, no names
    from artifacts nobody resolved.  The same edge type also carries other
    hands' claims of the same shape (``method: ptr`` — the operator's reverse
    label; ``method: shodan`` — a third party's per-address list), and those
    are not ours to act on: whose evidence an edge holds is read from its
    ``sources``, not from its type, which is exactly why the fold kept one type
    and put the method on the edge.  Only the target's own names count: a
    ``needs_review`` hostname cannot drag an address into scope, and an
    explicit refusal always wins (both rules live in the engine, not here).
    Edges are walked in a deterministic order so the registration — and
    therefore every verdict — is identical between runs.
    """
    registered = 0
    records = SOURCE_LABEL["records"]
    for edge in sorted(result.model.edges.values(), key=lambda item: item.key):
        if edge.type != vocab.RESOLVES_TO:
            continue
        if records not in edge.sources:
            continue
        source = result.model.nodes.get(edge.source_id)
        target = result.model.nodes.get(edge.target_id)
        if source is None or target is None:
            continue
        if source.kind != vocab.DOMAIN or target.kind != vocab.IP:
            continue
        if scope.check_host(source.identity).state != "in_scope":
            continue
        if scope.add_resolved_address(target.identity, source.identity):
            registered += 1
    return registered


def _declaration_level(node: norm.Node) -> str:
    """``"address"``, ``"network"`` or ``""`` — what the operator declared here.

    Read from the scope engine's own wording rather than kept as a second field:
    the engine already distinguishes a declaration from an inference (and a
    declaration of an address from one of a range), so the policy asks it instead
    of maintaining a parallel notion of "ours".

    A DNS-derived verdict is deliberately **not** a declaration.  That is the
    whole reason the distinction is worth this function: the target's name
    pointing at a CDN edge makes the address *ours to probe with a URL*, and it
    must never make it ours to port-scan.
    """
    reason = str(node.props.get("scope_reason", ""))
    if reason.startswith("declared address"):
        return "address"
    if any(
        marker in reason
        for marker in (
            "declared network",
            "inside declared network",
            "contained in declared network",
        )
    ):
        return "network"
    return ""


def _origin_declared(node: norm.Node) -> bool:
    """True when the operator declared this address, or a network holding it."""
    return _declaration_level(node) in ("address", "network")


def _host_scope_state(model: norm.Model, url: str) -> str:
    """The scope verdict of the host a URL names, if the model has one.

    Empty when the host is not in the model at all — which the policy correctly
    reads as "no verdict", and refuses.  Never guessed from the URL string: the
    verdict comes from the node the scope engine actually annotated.
    """
    from urllib.parse import urlsplit

    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""
    if not host:
        return ""
    for kind in (vocab.DOMAIN, vocab.IP):
        node = model.nodes.get(vocab.node_id(kind, host))
        if node is not None:
            return str(node.props.get("scope_state", ""))
    return ""


def _as_int(value: object) -> int:
    """An integer from a loose artifact value; ``0`` when it is not one."""
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


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
