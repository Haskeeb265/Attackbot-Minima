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

# --------------------------------------------------------------------------- #
# Program intelligence — the bug-bounty layer above the assets
#
# These nodes come from the scraper (via PostgreSQL), not from recon. They are
# separate kinds from the asset taxonomy because they answer different
# questions: an asset node says "this exists"; a scope rule says "the program
# said this is (not) ours to test"; a policy says "if a bug exists here, is it
# potentially eligible?".  Keeping them distinct is what lets the graph answer
# "why is this asset out of scope?" and "which program rule decided that?".
# --------------------------------------------------------------------------- #

#: A bug-bounty program — the root of the intelligence graph.  Distinct from an
#: ``organization`` (a registry ownership claim over networks/ASNs): a program
#: is a *policy* entity — who declared what, under which rules.
PROGRAM = "program"
#: One declared scope asset with its boundary.  Properties carry ``kind``
#: (``in_scope`` / ``out_of_scope``), ``asset_type`` and ``identifier`` — the
#: program's own words — so the rule itself is the evidence for a verdict. The
#: *identifier* is deliberately kept on the rule even though the classifier may
#: also link the rule to an asset node: an out-of-scope host rediscovered during
#: recon must be recognisable even before an asset node exists for it.
SCOPE_RULE = "scope_rule"
#: A program's vulnerability/bounty policy: the rules that decide whether a
#: discovered vulnerability is potentially eligible.
POLICY = "vulnerability_policy"
#: A vulnerability class (a CWE / weakness family) a policy allows or refuses.
WEAKNESS_CLASS = "weakness_class"

NODE_KINDS = (
    DOMAIN,
    WILDCARD,
    IP,
    SERVICE,
    URL,
    PARAMETER,
    ASN,
    NETWORK,
    ORGANIZATION,
    CLOUD,
    PROGRAM,
    SCOPE_RULE,
    POLICY,
    WEAKNESS_CLASS,
)

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
#: A program owns a scope rule (in-scope or out-of-scope).
HAS_SCOPE_RULE = "has_scope_rule"
#: A scope rule names an asset.  Carries ``state`` (``in_scope`` /
#: ``out_of_scope``) so an asset declared both ways resolves to the refusal —
#: the same precedence the scope engine applies.
DECLARES = "declares"
#: A program owns a vulnerability/bounty policy.
HAS_POLICY = "has_policy"
#: A policy permits a vulnerability class (bounty-eligible).
ELIGIBLE_CLASS = "eligible_class"
#: A policy refuses a vulnerability class (explicitly ineligible).
INELIGIBLE_CLASS = "ineligible_class"

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
    HAS_SCOPE_RULE,
    DECLARES,
    HAS_POLICY,
    ELIGIBLE_CLASS,
    INELIGIBLE_CLASS,
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
    # Program intelligence — deliberately NOT labelled :Asset: they are not
    # things on the attack surface, and a query for assets must not pick them up.
    PROGRAM: ("Program",),
    SCOPE_RULE: ("ScopeRule",),
    POLICY: ("VulnerabilityPolicy",),
    WEAKNESS_CLASS: ("WeaknessClass",),
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
    HAS_SCOPE_RULE: ("HAS_SCOPE_RULE", "program -> scope_rule"),
    DECLARES: ("DECLARES", "scope_rule -> asset (state on the edge)"),
    HAS_POLICY: ("HAS_POLICY", "program -> vulnerability_policy"),
    ELIGIBLE_CLASS: ("ELIGIBLE_CLASS", "vulnerability_policy -> weakness_class"),
    INELIGIBLE_CLASS: ("INELIGIBLE_CLASS", "vulnerability_policy -> weakness_class"),
}

#: The node kinds and edges that come from the scraper rather than recon.
#: Kept named so a consumer can tell the two layers apart without re-deriving
#: which strings are which.
PROGRAM_NODE_KINDS = (PROGRAM, SCOPE_RULE, POLICY, WEAKNESS_CLASS)
PROGRAM_EDGE_TYPES = (
    HAS_SCOPE_RULE,
    DECLARES,
    HAS_POLICY,
    ELIGIBLE_CLASS,
    INELIGIBLE_CLASS,
)

#: The one-sentence caveat that travels with every artifact of this pipeline.
SCHEMA_NOTE = (
    "the schema is settled (2026-09-19): ten asset kinds, twelve claim-typed "
    "edges; the mapping below is normative. The program-intelligence layer "
    "(program / scope_rule / vulnerability_policy / weakness_class and their "
    "edges) was added on 2026-09-26 — it comes from the scraper via PostgreSQL, "
    "not from this pipeline, and is loaded by the graph's program loader. This "
    "pipeline still emits a file-only model for the asset layer — no database "
    "writer exists there yet (graph_written: false), though the program loader "
    "does write the program layer."
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
