"""The vocabulary: one neutral asset model, and one provisional graph mapping.

Two things live here, and they are deliberately separate.

**The model** — node kinds, edge types and trust classes.  This is *our*
vocabulary: it is what the pipelines' facts were normalised *into*, and it does
not depend on any storage decision.  ``domain`` is a hostname, ``ip`` is an
address, ``service`` is an address:port speaking a protocol, and so on.

**The mapping** — :data:`GRAPH_LABELS` and :data:`GRAPH_RELATIONSHIPS` translate
those neutral names into the label and relationship names a graph database would
use.  **The schema is not final**, so this mapping is explicitly provisional: it
is a single dict each, it is emitted alongside every run (``vocabulary.json``) so
artifacts record which mapping produced them, and it is the *only* thing that has
to change when the schema settles.  No other module in this package names a
label.

Trust classes say how the claim was obtained, which is the difference between a
fact and a rumour:

============================ ==================================================
``declared``                 the operator stated it (the apex/scope they gave us)
``observed``                 we measured it (a DNS answer, a scan, a probe)
``discovered``               a third party claims it (CT logs, registries, archives)
``inferred``                 we derived it by arithmetic (a classification, a
                             containment, an attribution)
============================ ==================================================
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
# Node kinds
# --------------------------------------------------------------------------- #

DOMAIN = "domain"
WILDCARD = "wildcard"
IP = "ip"
SERVICE = "service"
URL = "url"
PARAMETER = "parameter"
ASN = "asn"
NETWORK = "network"
ORGANIZATION = "organization"

NODE_KINDS = (DOMAIN, WILDCARD, IP, SERVICE, URL, PARAMETER, ASN, NETWORK, ORGANIZATION)

# --------------------------------------------------------------------------- #
# Edge types
# --------------------------------------------------------------------------- #

#: A hostname resolves to an address (forward DNS we performed).
RESOLVES_TO = "resolves_to"
#: An address's PTR name (reverse DNS).  The mirror of ``resolves_to`` is *not*
#: the same claim: a PTR record is the network operator's label for an address,
#: which is exactly why the pair lives as two edge types.
PTR_MAPS_TO = "ptr_maps_to"
#: A hostname appears in the URL pipeline's harvest.
HAS_URL = "has_url"
#: A wildcard DNS answer covers a hostname.
WILDCARD_COVERS = "wildcard_covers"
#: An address exposes a port/service (our scan).
EXPOSES_SERVICE = "exposes_service"
#: An address is inside a network, per a registry's own prefix statement.
IN_NETWORK = "in_network"
#: An address's origin AS, per registry/RDAP data.
BELONGS_TO_ASN = "belongs_to_asn"
#: A network is announced by an AS (a routing claim, not an ownership claim).
ANNOUNCED_BY = "announced_by"
#: A registry allocates a network to an organisation.
ALLOCATED_TO = "allocated_to"
#: An AS is operated by / registered to an organisation.
REGISTERED_TO = "registered_to"
#: An address is hosted by a provider, per a classification verdict.  Inferred,
#: never observed: "this looks like a CDN edge" is a judgement (the ports stage's
#: ``cdn_classified.jsonl`` carries the evidence list it was made from).
HOSTED_BY = "hosted_by"
#: A third-party index says a hostname sits on an address (Shodan InternetDB's
#: per-address hostname list).  Deliberately *not* collapsed into ``ptr_maps_to``
#: or ``resolves_to``: a PTR label and a third party's observation are different
#: claims from different hands, and ASM cares which one it is holding.
ATTRIBUTED_TO = "attributed_to"

EDGE_TYPES = (
    RESOLVES_TO,
    PTR_MAPS_TO,
    HAS_URL,
    WILDCARD_COVERS,
    EXPOSES_SERVICE,
    IN_NETWORK,
    BELONGS_TO_ASN,
    ANNOUNCED_BY,
    ALLOCATED_TO,
    REGISTERED_TO,
    HOSTED_BY,
    ATTRIBUTED_TO,
)

# --------------------------------------------------------------------------- #
# Trust classes, strongest first
# --------------------------------------------------------------------------- #

DECLARED = "declared"
OBSERVED = "observed"
DISCOVERED = "discovered"
INFERRED = "inferred"

#: Precedence for merging the same node from several sources: the strongest claim
#: wins the ``trust`` field, and every contributing source is still recorded, so
#: a hostname we resolved *and* saw in CT logs is ``observed`` with both sources
#: listed rather than being silently downgraded.
TRUST_ORDER = (DECLARED, OBSERVED, DISCOVERED, INFERRED)

TRUST_UNKNOWN = "unknown"


def strongest_trust(candidates: "list[str] | tuple[str, ...]") -> str:
    """The strongest trust class among *candidates* (``unknown`` when empty)."""
    present = [value for value in candidates if value in TRUST_ORDER]
    if not present:
        return TRUST_UNKNOWN
    return min(present, key=TRUST_ORDER.index)


# --------------------------------------------------------------------------- #
# Identity
# --------------------------------------------------------------------------- #


def node_id(kind: str, identity: str) -> str:
    """Stable, readable id for a node: ``kind:identity``.

    Deliberately not a hash: the ids appear in every artifact, in diffs and in
    edge endpoints, and a reader should be able to see what they mean.  They are
    deterministic because the identity strings they are built from are already
    canonical (see :mod:`.normalize`).
    """
    return f"{kind}:{identity}"


# --------------------------------------------------------------------------- #
# The provisional graph mapping — the one file to edit when the schema settles
# --------------------------------------------------------------------------- #

#: Neutral node kind → the labels a graph write would use.  Provisional: taken
#: from the vocabulary the design documents already use, so a future writer has a
#: starting point rather than a blank page.  Values are tuples because a node may
#: carry several labels (a hostname is both an asset and a domain).
GRAPH_LABELS: dict[str, tuple[str, ...]] = {
    DOMAIN: ("Asset", "Domain"),
    WILDCARD: ("Asset", "Wildcard"),
    IP: ("Asset", "IP"),
    SERVICE: ("Asset", "Service"),
    URL: ("Asset", "URL"),
    PARAMETER: ("Asset", "Parameter"),
    ASN: ("Asset", "ASN"),
    NETWORK: ("Asset", "CIDR"),
    ORGANIZATION: ("Asset", "Organization"),
}

#: Neutral edge type → the relationship a graph write would use, plus its
#: direction, written as ``"from -> to"`` so a reader can check it against the
#: neutral description in :data:`EDGE_TYPES` comments above.
GRAPH_RELATIONSHIPS: dict[str, tuple[str, str]] = {
    RESOLVES_TO: ("RESOLVES_TO", "domain -> ip"),
    PTR_MAPS_TO: ("PTR_MAPS_TO", "ip -> domain"),
    HAS_URL: ("HAS_URL", "domain -> url"),
    WILDCARD_COVERS: ("WILDCARD_COVERS", "wildcard -> domain"),
    EXPOSES_SERVICE: ("EXPOSES_SERVICE", "ip -> service"),
    IN_NETWORK: ("IN_NETWORK", "ip -> network"),
    BELONGS_TO_ASN: ("BELONGS_TO_ASN", "ip -> asn"),
    ANNOUNCED_BY: ("ANNOUNCED_BY", "network -> asn"),
    ALLOCATED_TO: ("ALLOCATED_TO", "network -> organization"),
    REGISTERED_TO: ("REGISTERED_TO", "asn -> organization"),
    HOSTED_BY: ("HOSTED_BY", "ip -> organization"),
    ATTRIBUTED_TO: ("ATTRIBUTED_TO", "domain -> ip"),
}

#: The one-sentence caveat that travels with every artifact of this pipeline.
SCHEMA_NOTE = (
    "label/relationship names are provisional: this pipeline emits a file-only "
    "model and does not write to the graph database, because the schema is not "
    "final. Edit vocabulary.py's GRAPH_LABELS / GRAPH_RELATIONSHIPS to settle it."
)

#: The field the model writes to say a mapping exists but was not used.
GRAPH_WRITTEN = False


def mapping_document() -> dict[str, object]:
    """The mapping as emitted data, so artifacts record the vocabulary used."""
    return {
        "note": SCHEMA_NOTE,
        "graph_written": GRAPH_WRITTEN,
        "node_kinds": list(NODE_KINDS),
        "edge_types": list(EDGE_TYPES),
        "trust_order": list(TRUST_ORDER),
        "labels": {kind: list(labels) for kind, labels in GRAPH_LABELS.items()},
        "relationships": {
            edge: {"type": rel, "direction": direction}
            for edge, (rel, direction) in GRAPH_RELATIONSHIPS.items()
        },
    }
