"""Measure one run: what progressed, what did not, and which rule decided.

The escalation policy already answers *whether* an asset may be escalated.  This
module answers the question an operator asks next, and which the first version of
the policy could not: **why did nothing progress?**  A number like ``port_scan:
0 eligible / 33 considered`` is a fact with no diagnosis attached, and the
measured ``qbsco.net`` run showed why that matters — every one of the 33 was
refused as ``needs_review``, so the CDN gate that the number *looked* like it was
enforcing had never run at all.

So the report is built from the finished model (not from any stage's own claim
about itself) and it is organised as the pipeline is, one block per progression:

``url``
    candidates → considered → eligible → validated → verified / redirected /
    dead / unreachable / errored
``ip_port``
    addresses → shared / dedicated / unknown / unclassified → eligible →
    refused (by rule) → scanned → services discovered
``networks``
    discovered → ownership_verified → host_discovered → relevant →
    active-expansion eligible / refused
``evidence``
    how many nodes sit in each evidence state

Every refused candidate is accounted for by a *code* (see
``platform.escalation.REFUSAL_*``), so "refused" is never a black box: each count
names the rule that produced it, and every individual row is in
``escalation_refusals.jsonl`` beside this file.

The module is pure — model in, dict out — so the arithmetic that reports a run is
testable without running one.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from service.recon_pipeline.platform import escalation

from . import vocabulary as vocab

#: Node kinds whose evidence state is worth counting in the evidence block.  The
#: three that carry operational weight: names/addresses (hosts and IPs), URLs, and
#: networks.
EVIDENCE_KINDS: tuple[str, ...] = (vocab.DOMAIN, vocab.IP, vocab.URL, vocab.NETWORK, vocab.CLOUD)

#: Evidence states, in report order, so two runs print the same table.
EVIDENCE_STATES: tuple[str, ...] = (
    "actively_verified",
    "needs_review",
    "unverified",
    "passive",
    "historical",
    "dead",
)


def _block(summary: dict[str, object], operation: str) -> dict[str, object]:
    """The escalation summary for one operation, or an empty stand-in."""
    value = summary.get(operation)
    return value if isinstance(value, dict) else {}


def _as_int(value: object) -> int:
    """An integer from a loose report value; ``0`` when it is not one."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return 0
    return 0


def _escalation_counts(block: dict[str, object]) -> tuple[int, int, dict[str, int]]:
    """``(considered, eligible, refusal codes)`` from one policy block."""
    considered = _as_int(block.get("considered"))
    eligible = _as_int(block.get("eligible"))
    codes = block.get("refusal_codes")
    return considered, eligible, dict(codes) if isinstance(codes, dict) else {}


def measure(result) -> dict[str, Any]:
    """The four progression blocks for a finished merge.

    *result* is a :class:`~.merge.MergeResult`; nothing here mutates it, so the
    measurement can be taken before or after the artifacts are written and the
    two can never disagree.
    """
    model = result.model

    hosts = {"url": 0, "ip": 0, "domain": 0, "network": 0}
    evidence: dict[str, Counter] = {state: Counter() for state in EVIDENCE_STATES}
    url_states: Counter = Counter()
    hosting: Counter = Counter()
    hosting_classified = 0
    scanned_addresses = 0
    services_observed = 0
    services_claimed = 0
    services = 0
    relevance: Counter = Counter()
    # The same provenance rule the policy uses: our own scan output is what proves
    # an address was scanned, and an ``observed`` service is one we measured.
    from . import merge as merge_mod

    scan_label = merge_mod.SOURCE_LABEL["open_ports"]

    for node in model.nodes.values():
        state = node.evidence_state or "unverified"
        if state in evidence and node.kind in EVIDENCE_KINDS:
            evidence[state][node.kind] += 1

        if node.kind == vocab.URL:
            hosts["url"] += 1
            url_states[str(node.props.get("validation_state", "") or "unvalidated")] += 1
        elif node.kind == vocab.IP:
            hosts["ip"] += 1
            classified = bool(node.props.get("hosting_classified", False))
            if classified:
                hosting_classified += 1
            hosting[
                escalation.hosting_class(
                    str(node.props.get("hosting_verdict", "")),
                    str(node.props.get("hosting_provider", "")),
                    classified=classified,
                )
            ] += 1
        elif node.kind == vocab.DOMAIN:
            hosts["domain"] += 1
        elif node.kind == vocab.NETWORK:
            hosts["network"] += 1
            relevance[str(node.props.get("relevance_state", "") or "unknown")] += 1
        elif node.kind == vocab.SERVICE:
            services += 1

    for node in model.nodes.values():
        if node.kind == vocab.IP and scan_label in node.sources:
            scanned_addresses += 1
    for edge in model.edges.values():
        if edge.type != vocab.EXPOSES_SERVICE:
            continue
        # Split by who measured it: a third party's port claim is a lead, and
        # counting the two together is what made "already scanned" untrustworthy.
        if edge.trust == vocab.OBSERVED:
            services_observed += 1
        else:
            services_claimed += 1

    # The two ways a legitimate address can fail to progress without any policy
    # being at fault, counted because they are the *actionable* finding in a run
    # that ends with zero candidates: neither is fixed by widening scope, and
    # both are fixed by re-running an upstream stage.
    classified_unlinked = 0
    linked_unclassified = 0
    linked = {
        edge.target_id.split(":", 1)[1]
        for edge in model.edges.values()
        if edge.type == vocab.RESOLVES_TO
    }
    for node in model.nodes.values():
        if node.kind != vocab.IP:
            continue
        classified = bool(node.props.get("hosting_classified", False))
        has_link = node.identity in linked
        if classified and not has_link:
            classified_unlinked += 1
        elif has_link and not classified:
            linked_unclassified += 1

    url_considered, url_eligible, url_codes = _escalation_counts(
        _block(result.escalation, escalation.OPERATION_URL_VALIDATION)
    )
    ip_considered, ip_eligible, ip_codes = _escalation_counts(
        _block(result.escalation, escalation.OPERATION_PORT_SCAN)
    )
    net_considered, net_eligible, net_codes = _escalation_counts(
        _block(result.escalation, escalation.OPERATION_NETWORK_EXPANSION)
    )

    return {
        "url": {
            "total_candidates": hosts["url"],
            "considered": url_considered,
            "eligible": url_eligible,
            "validated": result.url_validations,
            "alive": result.urls_live,
            "verified": url_states.get("verified", 0),
            "redirected": url_states.get("redirected", 0),
            "protected": url_states.get("protected", 0),
            "dead": url_states.get("dead", 0),
            "errored": url_states.get("errored", 0),
            "unreachable": url_states.get("unreachable", 0),
            "unvalidated": url_states.get("unvalidated", 0),
            "refused_by_rule": url_codes,
        },
        "ip_port": {
            "addresses": hosts["ip"],
            "hosting_confirmed_shared": hosting.get(escalation.HOSTING_SHARED_EDGE, 0),
            "hosting_shared_cloud": hosting.get(escalation.HOSTING_SHARED_CLOUD, 0),
            "hosting_dedicated": hosting.get(escalation.HOSTING_DEDICATED, 0),
            "hosting_unknown": hosting.get(escalation.HOSTING_UNKNOWN, 0),
            "hosting_unclassified": hosting.get(escalation.HOSTING_UNCLASSIFIED, 0),
            "hosting_classified": hosting_classified,
            "considered": ip_considered,
            "eligible": ip_eligible,
            "refused": max(ip_considered - ip_eligible, 0),
            "refused_by_rule": ip_codes,
            "scanned_by_us": scanned_addresses,
            "services_discovered": services,
            "services_observed": services_observed,
            "services_claimed": services_claimed,
        },
        "networks": {
            "discovered": relevance.get(escalation.RELEVANCE_DISCOVERED, 0),
            "ownership_verified": relevance.get(escalation.RELEVANCE_OWNERSHIP_VERIFIED, 0),
            "host_discovered": relevance.get(escalation.RELEVANCE_HOST_DISCOVERED, 0),
            "relevant": relevance.get(escalation.RELEVANCE_RELEVANT, 0),
            "active_candidate": relevance.get(escalation.RELEVANCE_ACTIVE_CANDIDATE, 0),
            "considered": net_considered,
            "expansion_eligible": net_eligible,
            "expansion_refused": max(net_considered - net_eligible, 0),
            "refused_by_rule": net_codes,
        },
        "evidence": {
            state: {
                "total": sum(evidence[state].values()),
                **{kind: count for kind, count in sorted(evidence[state].items())},
            }
            for state in EVIDENCE_STATES
        },
        "scope_bridge": {
            "dns_scoped_addresses": result.dns_scoped_addresses,
            "registered_networks": result.registered_networks,
        },
        "data_gaps": {
            # Classified, but no name in the current records artifact resolves to
            # it: re-run the names stage and these become in-scope by themselves.
            "classified_without_dns_link": classified_unlinked,
            # A name of ours resolves to it, but no classification exists: run the
            # ports stage's classify pass over the current address set.
            "dns_linked_without_classification": linked_unclassified,
        },
    }


def _codes(codes: dict[str, int]) -> str:
    if not codes:
        return "—"
    return ", ".join(f"`{code}` × {count}" for code, count in codes.items())


def render(measurement: dict[str, Any], *, target: str = "") -> str:
    """The measurement as markdown, for a terminal or a report directory."""
    url = measurement["url"]
    ip_port = measurement["ip_port"]
    networks = measurement["networks"]
    lines = [
        f"# Active pipeline measurement{f' — {target}' if target else ''}",
        "",
        "## URL",
        "",
        f"- candidates: **{url['total_candidates']}**, considered **{url['considered']}**, "
        f"eligible **{url['eligible']}**",
        f"- validated: **{url['validated']}** (alive {url['alive']}: verified "
        f"{url['verified']}, redirected {url['redirected']}, protected {url['protected']}), "
        f"dead {url['dead']}, errored {url['errored']}, unreachable {url['unreachable']}, "
        f"unvalidated {url['unvalidated']}",
        f"- refused by rule: {_codes(url['refused_by_rule'])}",
        "",
        "## IP / port",
        "",
        f"- addresses: **{ip_port['addresses']}** — hosting classified "
        f"{ip_port['hosting_classified']} (shared edge {ip_port['hosting_confirmed_shared']}, "
        f"shared cloud {ip_port['hosting_shared_cloud']}, dedicated "
        f"{ip_port['hosting_dedicated']}, unknown {ip_port['hosting_unknown']}), "
        f"unclassified {ip_port['hosting_unclassified']}",
        f"- considered **{ip_port['considered']}**, eligible **{ip_port['eligible']}**, "
        f"refused **{ip_port['refused']}**",
        f"- refused by rule: {_codes(ip_port['refused_by_rule'])}",
        f"- scanned by us {ip_port['scanned_by_us']}, service nodes "
        f"{ip_port['services_discovered']} ({ip_port['services_observed']} we measured, "
        f"{ip_port['services_claimed']} claimed by a third party)",
        "",
        "## Networks",
        "",
        f"- discovered {networks['discovered']}, ownership_verified "
        f"{networks['ownership_verified']}, host_discovered {networks['host_discovered']}, "
        f"relevant {networks['relevant']}, active_candidate {networks['active_candidate']}",
        f"- expansion considered {networks['considered']}, eligible "
        f"{networks['expansion_eligible']}, refused {networks['expansion_refused']}",
        f"- refused by rule: {_codes(networks['refused_by_rule'])}",
        "",
        "## Evidence",
        "",
    ]
    for state, block in measurement["evidence"].items():
        lines.append(f"- {state}: **{block['total']}**")
    lines.append("")

    # Last, and deliberately not under "policy refusals": these two counts are the
    # ways a run can end with nothing to do when no rule was wrong.
    gaps = measurement.get("data_gaps", {})
    if gaps:
        lines.extend(
            [
                "## Data gaps (not policy refusals)",
                "",
                f"- classified but not linked by the current DNS records: "
                f"**{gaps.get('classified_without_dns_link', 0)}** — re-run the names "
                "stage and these scope themselves",
                f"- linked by DNS but never classified: "
                f"**{gaps.get('dns_linked_without_classification', 0)}** — run the "
                "ports stage's classify pass over the current address set",
                "",
            ]
        )
    return "\n".join(lines)


__all__ = ["EVIDENCE_KINDS", "EVIDENCE_STATES", "measure", "render"]
