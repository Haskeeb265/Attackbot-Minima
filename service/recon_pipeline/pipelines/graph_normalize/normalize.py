"""The model and its merge rules — pure, no IO, no clock.

A pipeline artifact row becomes a ``Node`` when it names something and an
``Edge`` when it states a relationship.  Everything interesting happens in the
merge:

* **Identity is the key.**  A node is ``(kind, identity)``, and the identity is
  already canonical (a hostname lowercased, an address normalised, a URL
  stripped of its fragment).  Two artifacts mentioning ``www.example.com``
  produce one node.
* **Provenance accumulates, it does not overwrite.**  Merging unions the
  ``sources`` and ``evidence`` lists, so the node records *every* pipeline that
  saw it — which is the whole point of normalising four outputs into one model.
* **Trust is the strongest claim, not the latest.**  ``observed`` beats
  ``discovered`` (see :mod:`.vocabulary`); a hostname we resolved ourselves stays
  ``observed`` when an archive list also mentions it.
* **Properties never contradict silently.**  The first non-empty value wins and
  the collision is recorded as a note, so a disagreement between two artifacts
  shows up in the report rather than being resolved by file-read order.
* **Edges dedupe on ``(type, from, to)``.**  The same resolution seen twice is
  one edge with two pieces of evidence.

The module is pure so all of this is testable without touching the disk; the
sibling ``sources`` module does the reading and ``emit`` does the writing.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from . import vocabulary as vocab

#: Properties whose value is a *set of facts*, not a single value.  Two
#: artifacts naming different registry handles, tags or record types for the same
#: asset are both right, so these union; treating them as scalars would report a
#: disagreement where there is none.  Everything else keeps the first non-empty
#: value and records the collision.
UNION_PROPS = frozenset(
    {
        "handles",
        "names",
        "intel_tags",
        "intel_vulns",
        "intel_cpes",
        "dns_record_types",
        "origins",
        "classes",
        "roles",
        "discovered_by",
        # Multi-valued by nature: a redirect chain, a technology list and the
        # locations a parameter was seen in all union across artifacts, and
        # treating them as scalars would report a disagreement where there is
        # none (two validations observing different chains is two facts).
        "redirect_chain",
        "tech",
        "locations",
    }
)

#: How many distinct property collisions are kept in the report.
_MERGE_NOTE_LIMIT = 20


@dataclass
class Node:
    """One asset in the model."""

    kind: str
    identity: str
    props: dict[str, object] = field(default_factory=dict)
    trust: str = vocab.TRUST_UNKNOWN
    sources: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    #: Set by the scoring pass (S2), not by the merge: ``None`` means "not
    #: scored" — either scoring was switched off for the run or the pass refused
    #: to guess (see :mod:`~.score`).
    score: int | None = None
    band: str = ""
    #: The engine's line-by-line explanation of the score, capped by
    #: ``GN_MAX_SCORE_AUDIT`` — a score nobody can explain is a number, not a
    #: decision.
    score_audit: list[str] = field(default_factory=list)
    #: The categorical half of "how much attention?" — ``actively_verified``,
    #: ``passive``, ``historical``, ``unverified``, ``dead``, ``needs_review``
    #: (see :mod:`platform.scoring`).  Set by the scoring pass, not the merge: it
    #: is a judgement about the finished evidence, and it exists because a number
    #: cannot say whether the claim was measured today or found in a 2019 crawl.
    evidence_state: str = ""

    @property
    def id(self) -> str:
        return vocab.node_id(self.kind, self.identity)

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "kind": self.kind,
            "identity": self.identity,
            "trust": self.trust,
            "sources": sorted(set(self.sources)),
            **({"score": self.score, "band": self.band} if self.score is not None else {}),
            **({"evidence_state": self.evidence_state} if self.evidence_state else {}),
            **({"score_audit": self.score_audit} if self.score_audit else {}),
            "props": self.props,
            **({"evidence": self.evidence} if self.evidence else {}),
        }


@dataclass
class Edge:
    """One relationship in the model, always with the claim behind it."""

    type: str
    source_id: str
    target_id: str
    props: dict[str, object] = field(default_factory=dict)
    trust: str = vocab.TRUST_UNKNOWN
    sources: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.type, self.source_id, self.target_id)

    def to_dict(self) -> dict[str, object]:
        return {
            "type": self.type,
            "from": self.source_id,
            "to": self.target_id,
            "trust": self.trust,
            "sources": sorted(set(self.sources)),
            "props": self.props,
            **({"evidence": self.evidence} if self.evidence else {}),
        }


@dataclass
class Model:
    """The accumulated node/edge model, with merge accounting."""

    nodes: dict[str, Node] = field(default_factory=dict)
    edges: dict[tuple[str, str, str], Edge] = field(default_factory=dict)
    #: Property collisions between artifacts — reported, never silently resolved.
    conflicts: list[dict[str, object]] = field(default_factory=list)
    #: Edges whose endpoint node was never separately named by an artifact.  The
    #: endpoint node is still created (an edge must have both ends), but the fact
    #: is counted so a half-described relationship is visible.
    endpoint_only: list[str] = field(default_factory=list)
    truncated_nodes: int = 0
    truncated_edges: int = 0

    def note_conflict(self, entry: dict[str, object]) -> None:
        """Record a property collision once — the same one repeats per row."""
        signature = (entry.get("node"), entry.get("property"), str(entry.get("kept")), str(entry.get("seen")))
        for existing in self.conflicts:
            if (
                existing.get("node"),
                existing.get("property"),
                str(existing.get("kept")),
                str(existing.get("seen")),
            ) == signature:
                return
        if len(self.conflicts) < _MERGE_NOTE_LIMIT:
            self.conflicts.append(entry)

    # ------------------------------------------------------------------ #
    # building
    # ------------------------------------------------------------------ #

    def add_node(
        self,
        kind: str,
        identity: str,
        *,
        source: str,
        trust: str,
        props: dict[str, object] | None = None,
        evidence: str = "",
        max_nodes: int | None = None,
        max_evidence: int = 8,
    ) -> Node | None:
        """Add or merge one node; ``None`` when the node cap refused it."""
        if not identity:
            return None
        if kind not in vocab.NODE_KINDS:
            raise ValueError(f"unknown node kind {kind!r}")
        key = vocab.node_id(kind, identity)
        existing = self.nodes.get(key)
        if existing is None:
            if max_nodes is not None and len(self.nodes) >= max_nodes:
                self.truncated_nodes += 1
                return None
            existing = Node(kind=kind, identity=identity, trust=trust)
            self.nodes[key] = existing
        existing.trust = vocab.strongest_trust([existing.trust, trust])
        _merge_into(existing, source, evidence, props, self, max_evidence)
        return existing

    def add_edge(
        self,
        edge_type: str,
        source_id: str,
        target_id: str,
        *,
        source: str,
        trust: str,
        props: dict[str, object] | None = None,
        evidence: str = "",
        max_edges: int | None = None,
        max_evidence: int = 8,
    ) -> Edge | None:
        """Add or merge one edge; ``None`` when the edge cap refused it."""
        if edge_type not in vocab.EDGE_TYPES:
            raise ValueError(f"unknown edge type {edge_type!r}")
        if not source_id or not target_id or source_id == target_id:
            # A self-loop is a modelling error, not a relationship.
            return None
        key = (edge_type, source_id, target_id)
        existing = self.edges.get(key)
        if existing is None:
            if max_edges is not None and len(self.edges) >= max_edges:
                self.truncated_edges += 1
                return None
            existing = Edge(
                type=edge_type,
                source_id=source_id,
                target_id=target_id,
                trust=trust,
            )
            self.edges[key] = existing
            for endpoint in (source_id, target_id):
                if endpoint not in self.nodes:
                    self.endpoint_only.append(endpoint)
        existing.trust = vocab.strongest_trust([existing.trust, trust])
        _merge_edge(existing, source, evidence, props, max_evidence)
        return existing

    # ------------------------------------------------------------------ #
    # accounting + reading
    # ------------------------------------------------------------------ #

    def orphan_ids(self, *, limit: int = 50) -> tuple[int, list[str]]:
        """Nodes with no edge at all: ``(total, first *limit* ids)``.

        An orphan is not an error — a harvested parameter with no URL linkage is
        a legitimate node — but it is a fact the report owes the operator,
        because orphans are what a graph query will never find by traversal.
        """
        connected: set[str] = set()
        for edge in self.edges.values():
            connected.add(edge.source_id)
            connected.add(edge.target_id)
        orphans = sorted(node_id for node_id in self.nodes if node_id not in connected)
        return len(orphans), orphans[:limit]

    def counts_by_kind(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for node in self.nodes.values():
            counts[node.kind] = counts.get(node.kind, 0) + 1
        return dict(sorted(counts.items()))

    def counts_by_type(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for edge in self.edges.values():
            counts[edge.type] = counts.get(edge.type, 0) + 1
        return dict(sorted(counts.items()))

    def counts_by_trust(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for node in self.nodes.values():
            counts[node.trust] = counts.get(node.trust, 0) + 1
        return dict(sorted(counts.items()))

    def counts_by_evidence_state(self) -> dict[str, int]:
        """How the model's evidence is *established*, not how strong it is.

        The second axis a band cannot carry: 3 000 URLs at score 44 are not one
        kind of thing — some were verified alive this run, some are historical
        claims nobody has checked, and some answered 404.
        """
        counts: dict[str, int] = {}
        for node in self.nodes.values():
            if not node.evidence_state:
                continue
            counts[node.evidence_state] = counts.get(node.evidence_state, 0) + 1
        return dict(sorted(counts.items()))

    def operations_for(self, node: Node) -> set[str]:
        """Operations the model's own evidence says were already performed.

        Derived, never stored: the artifacts *are* the operation state (a
        ``resolves_to`` edge from our records stream is the record that DNS was
        attempted for that host).  Keeping it derived is what stops a second,
        drifting notion of "scanned" from appearing in a node property.
        """
        from . import merge as merge_mod

        return merge_mod.derived_operations(self, node)

    def sorted_nodes(self) -> list[Node]:
        """Nodes in a stable order: by kind, then identity."""
        return sorted(self.nodes.values(), key=lambda node: (node.kind, node.identity))

    def sorted_edges(self) -> list[Edge]:
        """Edges in a stable order: by type, then both endpoints."""
        return sorted(self.edges.values(), key=lambda edge: edge.key)


def _merge_into(
    node: Node,
    source: str,
    evidence: str,
    props: dict[str, object] | None,
    model: Model,
    max_evidence: int,
) -> None:
    if source and source not in node.sources:
        node.sources.append(source)
    if evidence and evidence not in node.evidence and len(node.evidence) < max_evidence:
        node.evidence.append(evidence)
    for key, value in (props or {}).items():
        if value in (None, "", [], {}):
            continue
        current = node.props.get(key)
        if current in (None, "", [], {}):
            node.props[key] = value
        elif key in UNION_PROPS:
            node.props[key] = _union(current, value)
        elif current != value:
            model.note_conflict(
                {
                    "node": node.id,
                    "property": key,
                    "kept": current,
                    "seen": value,
                    "sources": sorted({*node.sources, source}),
                }
            )


def _merge_edge(
    edge: Edge,
    source: str,
    evidence: str,
    props: dict[str, object] | None,
    max_evidence: int,
) -> None:
    if source and source not in edge.sources:
        edge.sources.append(source)
    if evidence and evidence not in edge.evidence and len(edge.evidence) < max_evidence:
        edge.evidence.append(evidence)
    for key, value in (props or {}).items():
        if value in (None, "", [], {}):
            continue
        current = edge.props.get(key)
        if current in (None, "", [], {}):
            edge.props[key] = value
        elif key in UNION_PROPS:
            edge.props[key] = _union(current, value)


def _union(current: object, value: object) -> list[object]:
    """Union two set-shaped property values, preserving a readable order."""
    left = current if isinstance(current, list) else [current]
    right = value if isinstance(value, list) else [value]
    merged: list[object] = []
    for item in [*left, *right]:
        if item not in merged:
            merged.append(item)
    if all(isinstance(item, str) for item in merged):
        # Strings sort; mixed or numeric values keep insertion order, because
        # sorting them would either raise or invent an ordering nobody asked for.
        return sorted(merged, key=str)
    return merged


# --------------------------------------------------------------------------- #
# identity helpers — the canonical forms every converter must use
# --------------------------------------------------------------------------- #

_FRAGMENT = re.compile(r"#.*$")


def domain_identity(host: str) -> str:
    """Canonical identity for a hostname (lowercase, no trailing dot)."""
    return host.strip().rstrip(".").lower()


def address_identity(address: str) -> str:
    """Canonical identity for an address (``ipaddress`` form, or as given)."""
    try:
        return str(ipaddress.ip_address(address.strip()))
    except ValueError:
        return address.strip().lower()


def network_identity(network: str) -> str:
    """Canonical identity for a CIDR (network address, not host bits)."""
    try:
        return str(ipaddress.ip_network(network.strip(), strict=False))
    except ValueError:
        return network.strip()


def service_identity(address: str, port: int | str, proto: str = "tcp") -> str:
    """Identity for a service: ``address:port/proto``.

    The protocol is part of the identity because TCP/443 and UDP/443 are
    different services with the same number, and collapsing them would merge two
    facts into a false one.
    """
    return f"{address_identity(str(address))}:{int(port)}/{(proto or 'tcp').lower()}"


def url_identity(url: str) -> str:
    """Light canonicalisation for a harvested URL.

    The URL pipeline already canonicalised its artifact (case-folded host,
    folded default ports, sorted query); this only removes the fragment and
    surrounding whitespace, because re-implementing that pipeline's rules here
    would let the two disagree about what one URL is.
    """
    return _FRAGMENT.sub("", url.strip())


def wildcard_identity(suffix: str) -> str:
    """Identity for a wildcard answer: the ``*.`` form, lowercased."""
    token = suffix.strip().rstrip(".").lower()
    return token if token.startswith("*.") else f"*.{token}"


def organization_identity(name: str) -> str:
    """Identity for an organisation name or registry handle."""
    return " ".join(name.split()).lower()
