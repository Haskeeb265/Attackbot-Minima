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
#: A cloud resource a provider hosts, named by the provider's own namespace.
#: The identity is ``provider:name`` (see :func:`.normalize.cloud_identity`) —
#: the two facts about a bucket that will never change.  Everything observed
#: (region, endpoint spellings, last probe outcome) is a property, because a
#: bucket reached at three regional endpoints is one asset, and a *dangling*
#: reference has no region at all.
CLOUD = "cloud"

NODE_KINDS = (DOMAIN, WILDCARD, IP, SERVICE, URL, PARAMETER, ASN, NETWORK, ORGANIZATION, CLOUD)

# --------------------------------------------------------------------------- #
# Edge types
#
# The type names the *claim*, not the data shape: claims that differ in who
# made them or in kind of assertion get different types; claims that differ
# only in detail carry the detail as properties (``method``, ``claim``).
# --------------------------------------------------------------------------- #

#: One name's answer about where another asset lives.  Carries ``method``:
#: ``a`` (our forward DNS), ``ptr`` (the operator's reverse-DNS label), or
#: ``shodan`` (a third party's per-address hostname list).  A PTR label and a
#: third party's observation are different claims from different hands — the
#: type is shared because the *question* is one question (what does this name
#: point at?); the method is on the edge so a scope decision can weigh them
#: differently.
RESOLVES_TO = "resolves_to"
#: A hostname's CNAME names a cloud resource.  Carries the probe outcome as
#: properties (``outcome``, ``code``, ``probe_url``): the dangling reference —
#: a name that claims a bucket the provider says is absent — is *one edge with
#: an outcome property*, which is exactly the finding a vuln engine traverses.
CNAME_POINTS_TO = "cname_points_to"
#: A hostname appears in the URL pipeline's harvest.
HAS_URL = "has_url"
#: A URL exposes a named query parameter, *as observed on that URL*.
#: Deliberately not a global ``has_parameter`` from every URL to every name: the
#: provenance is the fact.  A name list answers "which parameters exist"; this
#: edge answers "which URLs expose this parameter" and "which parameters were
#: observed on this URL", which is the pair a testing pass is built from.
OBSERVED_PARAMETER = "observed_parameter"
#: A URL answered with a redirect to another location we validated (or at least
#: observed as the final URL).  ``url -> url``, with the status chain on the edge.
REDIRECTS_TO = "redirects_to"
#: A wildcard DNS answer covers a hostname.
WILDCARD_COVERS = "wildcard_covers"
#: An address exposes a port/service (our scan).
EXPOSES_SERVICE = "exposes_service"
#: An address is inside a network, per a registry's own prefix statement.
IN_NETWORK = "in_network"
#: An address's origin AS, per registry/RDAP data.
BELONGS_TO_ASN = "belongs_to_asn"
#: A network is announced by an AS (a routing claim, not an ownership claim).
#: Deliberately separate from ``owned_by``: an AS transits prefixes it does not
#: own, and "does this org actually control this network?" is a question the
#: engine must be able to ask — collapsing the two would answer it in advance.
ANNOUNCED_BY = "announced_by"
#: A registry's ownership claim over a network or an AS.  Carries ``claim``:
#: ``allocation`` (a network was allocated to an organisation) or
#: ``registration`` (an AS is registered to one).  One type because the question
#: is one question — who holds this? — and the claim kind is the detail.
OWNED_BY = "owned_by"
#: An address is hosted by a provider, per a classification verdict.  Inferred,
#: never observed: "this looks like a CDN edge" is a judgement (the ports stage's
#: ``cdn_classified.jsonl`` carries the evidence list it was made from).  Also
#: deliberately separate from ``owned_by``: "hosted by Cloudflare" mislabeled as
#: ownership would actively mislead a scope judgment.
HOSTED_BY = "hosted_by"

EDGE_TYPES = (
    RESOLVES_TO,
    CNAME_POINTS_TO,
    HAS_URL,
    OBSERVED_PARAMETER,
    REDIRECTS_TO,
    WILDCARD_COVERS,
    EXPOSES_SERVICE,
    IN_NETWORK,
    BELONGS_TO_ASN,
    ANNOUNCED_BY,
    OWNED_BY,
    HOSTED_BY,
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
# The graph mapping — settled by the schema discussion of 2026-09-19
#
# Nodes are the ten asset kinds.  Edge types name claims; who claimed a thing
# travels as edge properties (``trust``, ``sources``, ``evidence``, ``method``,
# ``claim``), because the vuln engine reasons about the relation and cites the
# provenance.  ``GRAPH_WRITTEN`` is still ``False``: no database writer exists
# yet, and the field says so rather than promising one.
# --------------------------------------------------------------------------- #

#: Neutral node kind → the labels a graph write would use.
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
    CLOUD: ("Asset", "CloudResource"),
}

#: Neutral edge type → the relationship a graph write would use, plus the
#: endpoint kinds it may join, written as ``"from -> to"`` so a reader can check
#: it against the neutral descriptions above.  ``resolves_to`` joins names to
#: addresses in *both* directions (forward and reverse claims), which is why its
#: direction names both.
GRAPH_RELATIONSHIPS: dict[str, tuple[str, str]] = {
    RESOLVES_TO: ("RESOLVES_TO", "domain -> ip | ip -> domain (ptr/shodan carry method)"),
    CNAME_POINTS_TO: ("CNAME_POINTS_TO", "domain -> cloud"),
    HAS_URL: ("HAS_URL", "domain -> url"),
    OBSERVED_PARAMETER: ("OBSERVED_PARAMETER", "url -> parameter"),
    REDIRECTS_TO: ("REDIRECTS_TO", "url -> url"),
    WILDCARD_COVERS: ("WILDCARD_COVERS", "wildcard -> domain"),
    EXPOSES_SERVICE: ("EXPOSES_SERVICE", "ip -> service"),
    IN_NETWORK: ("IN_NETWORK", "ip -> network"),
    BELONGS_TO_ASN: ("BELONGS_TO_ASN", "ip -> asn"),
    ANNOUNCED_BY: ("ANNOUNCED_BY", "network -> asn"),
    OWNED_BY: ("OWNED_BY", "network -> organization | asn -> organization"),
    HOSTED_BY: ("HOSTED_BY", "ip -> organization"),
}

#: The one-sentence caveat that travels with every artifact of this pipeline.
SCHEMA_NOTE = (
    "the schema is settled (2026-09-19): ten asset kinds, twelve claim-typed "
    "edges; the mapping below is normative. This pipeline still emits a "
    "file-only model — no database writer exists yet, so nothing was written "
    "to a graph (graph_written: false)."
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
