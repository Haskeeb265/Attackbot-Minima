"""Score every node with the platform's S2 engine — no scoring rules of our own.

The engine (`platform.scoring`) is deliberately dumb about *what* an asset is: it
scores ``ScoredAsset`` records that callers build.  This module is that caller.
It does one thing — translate a model node into the evidence the engine expects —
and then asks the engine for the score, so the arithmetic, the weights, the
corroboration rule and the band thresholds all come from the platform and cannot
drift from it.

Translation
-----------

**Signals come from the node's own sources.**  Each artifact label the merge
recorded maps onto the engine's source vocabulary (``rdap``, ``ripestat``,
``active-resolve``, ``naabu``, ``internetdb``, ``wayback``, …), and the engine
supplies that source's §4 weight.  Two artifacts that are the same *kind* of
evidence (``live_hosts`` and ``records`` are both our own resolution) map to the
same source key, so they corroborate once instead of counting twice — which is
the engine's whole point.

**One signal is derived rather than sourced**, from a fact the merge already
proved and never re-stating a source that is already counted: a network that
contains a host the names stage resolved (``known_hosts >= 1``) — the difference
between "this AS announces the range" and "the range actually holds the
target's infrastructure".

**The routing/ownership distinction survives scoring.**  The engine calls
ASN/CIDR ownership a hard signal (weight 100), and the network pipeline is
careful to label an announcement as a *routing claim* rather than ownership — so
the two do not map to the same weight here either: only a network the registry
*allocates* to the organisation earns the ownership weight, while an
announced-only prefix (and an AS known only from its announcements) scores in the
third-party tier.  Conflating them at the scoring step would undo the distinction
the pipeline exists to preserve.

The allocation claim is read from the ``allocated_to`` **edge the merge wrote**,
not from the node's ``classes``: that property aggregates every stream's claims,
so a prefix one stream announces and another allocates would otherwise be scored
as owned because of an announcement it never made.

**A verdict is not evidence.**  ``cdn_classified.jsonl`` is our own judgement,
so it contributes no signal at all; its effect is the shared-infrastructure
penalty, which is the shape a judgement should take.

**Penalties only where the model can prove them.**  Two of the engine's four
penalties fire here: a host covered by a wildcard that we have never resolved
(the engine's ``P_WILDCARD_MATCH``), and an address a classification verdict
calls a CDN/cloud edge (``P_SHARED_INFRASTRUCTURE``).  The other two are
deliberately **not** applied: there is no takedown feed in this tree and no
NXDOMAIN re-check in the model, and inventing either would put a number on
evidence nobody collected.

Every node the model *claims* is scored, including organisations: the engine asks
how strong the evidence for a record is, and a registry naming an organisation is
evidence like any other.  Nodes whose sources are unknown to the engine fall to
its documented weak default rather than being given a weight they did not earn.

**A node with no claim at all is left unscored, not zeroed.**  The engine's
rule for an empty signal set is "score 0 by definition — an asset without
provenance has no place in a triage queue", which is a statement about missing
evidence rather than about an asset.  A node whose only contributor is a
classification verdict (the provider organisation in ``cdn_classified.jsonl``)
has that shape: it is context the model carries, not an asset anyone claimed.
Such nodes get no ``score`` field, and the report counts them with the reason,
so a reader never mistakes "nobody claimed this" for "this scored zero".
"""

from __future__ import annotations

from dataclasses import dataclass, field

from service.recon_pipeline.platform import scoring as engine

from . import normalize as norm
from . import settings, vocabulary as vocab

#: Artifact label (as recorded in a node's ``sources``) → the engine's source
#: key.  Where the engine already has the concept, we use its own key so its
#: weight table stays the single source of truth; where it does not, the mapping
#: is explicit here rather than hidden in a default.
SOURCE_KEY = {
    "platform:declared target": "scope-declared",
    "subdomain_domain_wildcards:active/records": "active-resolve",
    "subdomain_domain_wildcards:active/live_hosts": "active-resolve",
    # The passive stage's union is OSINT/CT-derived; the engine's nearest
    # vocabulary is a passive source, and its weight is the passive tier.
    "subdomain_domain_wildcards:passive/subdomains": "subfinder",
    "subdomain_domain_wildcards:passive/wildcards": "wildcard-negative",
    "port_service_host:scan": "naabu",
    "port_service_host:internetdb": "internetdb",
    "port_service_host:ptr": "dnsx",
    "port_service_host:rdap+cymru ownership": "rdap",
    # A classification verdict is our own judgement, not evidence of an asset, so
    # it contributes no signal — its effect is the shared-infrastructure penalty.
    "url_endpoint:urls": "wayback",
    "url_endpoint:hosts": "wayback",
    "url_endpoint:endpoints": "gau",
    "url_endpoint:javascript": "gau",
    "url_endpoint:interesting": "gau",
    "url_endpoint:parameters": "gau",
    # A parameter observation is still archive-derived evidence about the URL
    # that carries it — the *provenance* is new, not the strength.
    "url_endpoint:parameter-observations": "gau",
    "asn_cidr:networks": "ripestat",
    "asn_cidr:asns": "ripestat",
}

#: A live validation is our own measurement of the URL itself, so it maps to the
#: engine's live-confirmation weight rather than to an archive mention.  This one
#: line is what makes "archived in 2019" and "answered 200 just now" score
#: differently — the entire reason the URL validation stage exists.
SOURCE_KEY["url_endpoint:validation"] = "url-validated-live"

#: Sources that deliberately contribute no signal, so they are not reported as
#: unknown: a classification verdict is a judgement about other evidence.
NO_SIGNAL_SOURCES = frozenset({"port_service_host:classify"})

#: Artifact label → *how* the evidence for a node is established.  This is the
#: input to the engine's categorical ``evidence_state``: the score says how much
#: the evidence supports the claim, this says what kind of claim it is.
CATEGORY_ACTIVE = "active"
CATEGORY_HISTORICAL = "historical"
CATEGORY_PASSIVE = "passive"
CATEGORY_CONTEXT = "context"

SOURCE_CATEGORY: dict[str, str] = {
    "platform:declared target": CATEGORY_CONTEXT,
    "subdomain_domain_wildcards:active/records": CATEGORY_ACTIVE,
    "subdomain_domain_wildcards:active/live_hosts": CATEGORY_ACTIVE,
    "subdomain_domain_wildcards:passive/subdomains": CATEGORY_PASSIVE,
    "subdomain_domain_wildcards:passive/wildcards": CATEGORY_PASSIVE,
    "port_service_host:scan": CATEGORY_ACTIVE,
    "port_service_host:internetdb": CATEGORY_PASSIVE,
    "port_service_host:ptr": CATEGORY_PASSIVE,
    "port_service_host:rdap+cymru ownership": CATEGORY_CONTEXT,
    "port_service_host:classify": CATEGORY_CONTEXT,
    "url_endpoint:urls": CATEGORY_HISTORICAL,
    "url_endpoint:hosts": CATEGORY_HISTORICAL,
    "url_endpoint:endpoints": CATEGORY_HISTORICAL,
    "url_endpoint:javascript": CATEGORY_HISTORICAL,
    "url_endpoint:interesting": CATEGORY_HISTORICAL,
    "url_endpoint:parameters": CATEGORY_HISTORICAL,
    "url_endpoint:parameter-observations": CATEGORY_HISTORICAL,
    "url_endpoint:validation": CATEGORY_ACTIVE,
    "asn_cidr:networks": CATEGORY_CONTEXT,
    "asn_cidr:asns": CATEGORY_CONTEXT,
}

#: The artifact label the URL pipeline's validation stage writes.
VALIDATION_SOURCE = "url_endpoint:validation"

#: Validation states that mean the URL was measured and did not answer.
DEAD_VALIDATION_STATES = frozenset({"dead", "unreachable"})


def _validated_dead(node: norm.Node) -> bool:
    return str(node.props.get("validation_state", "")) in DEAD_VALIDATION_STATES

#: Weight and wording for the keys the engine's table does not carry.  Both use
#: the engine's own constants — no weight is invented here.
_EXTRA_SIGNALS: dict[str, tuple[int, str]] = {
    "wildcard-negative": (engine.W_WILDCARD_NEGATIVE, "source: wildcard-negative"),
    "routing-announcement": (
        engine.W_THIRD_PARTY_DATASET,
        "routing announcement (announced, not allocated)",
    ),
    "url-validated-live": (
        engine.W_LIVE_CONFIRMATION,
        "source: live URL validation (this run)",
    ),
}

#: Verdicts that mean the address is somebody else's edge, not the target's own.
SHARED_INFRA_VERDICTS = frozenset({"cdn", "hosted"})


@dataclass
class ScoreStats:
    """What the scoring pass did — the report's view of it."""

    scored: int = 0
    by_band: dict[str, int] = field(default_factory=dict)
    by_kind: dict[str, dict[str, int]] = field(default_factory=dict)
    top: list[dict[str, object]] = field(default_factory=list)
    penalised: int = 0
    #: Nodes by evidence state — the axis a band cannot carry (see
    #: :func:`platform.scoring.evidence_state`).
    by_state: dict[str, int] = field(default_factory=dict)
    unscored: int = 0
    unscored_ids: list[str] = field(default_factory=list)
    unknown_sources: list[str] = field(default_factory=list)
    skipped: str = ""

    @property
    def unscored_reason(self) -> str:
        return (
            "no scoring signal: every contributor is a classification verdict or an "
            "unknown source, so nothing claimed this node as an asset"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "scored_nodes": self.scored,
            "unscored_nodes": self.unscored,
            **(
                {"unscored_sample": self.unscored_ids, "unscored_reason": self.unscored_reason}
                if self.unscored
                else {}
            ),
            "nodes_by_band": self.by_band,
            "nodes_by_evidence_state": self.by_state,
            "bands_by_kind": self.by_kind,
            "penalised_nodes": self.penalised,
            "top_scored": self.top,
            **({"unknown_sources": self.unknown_sources} if self.unknown_sources else {}),
            **({"skipped": self.skipped} if self.skipped else {}),
        }


def _source_key(node: norm.Node, source: str, allocated_by: dict[str, set[str]]) -> str | None:
    """The engine source key for one contribution, aware of *how* it was claimed.

    ``allocated_by`` maps a network node to the artifact labels that wrote an
    ``allocated_to`` edge for it — the merge's own record of which stream made an
    ownership claim, which is the fact this needs.  A node's ``classes`` cannot
    answer it: it unions every stream's claims.
    """
    if source == "asn_cidr:networks":
        # A routing claim unless this stream is also the one that allocated it.
        return "rdap" if source in allocated_by.get(node.id, set()) else "routing-announcement"
    if source == "asn_cidr:asns":
        return "routing-announcement"
    return SOURCE_KEY.get(source)


def score_model(
    model: norm.Model,
    *,
    max_audit: int = settings.MAX_SCORE_AUDIT,
    top_limit: int = settings.MAX_TOP_SCORED,
) -> ScoreStats:
    """Attach ``score`` / ``band`` / ``score_audit`` to every node in *model*."""
    stats = ScoreStats()
    address_verdicts = {
        node.identity: str(node.props.get("hosting_verdict", ""))
        for node in model.nodes.values()
        if node.kind == vocab.IP
    }
    wildcard_hosts = {
        edge.target_id for edge in model.edges.values() if edge.type == vocab.WILDCARD_COVERS
    }
    resolved_hosts = {
        edge.source_id for edge in model.edges.values() if edge.type == vocab.RESOLVES_TO
    }
    allocated_by: dict[str, set[str]] = {}
    for edge in model.edges.values():
        if edge.type == vocab.ALLOCATED_TO:
            allocated_by.setdefault(edge.source_id, set()).update(edge.sources)

    unknown: set[str] = set()
    for node in model.nodes.values():
        asset = engine.ScoredAsset(asset_type=node.kind, canonical_value=node.identity)
        for source in sorted(set(node.sources)):
            if source in NO_SIGNAL_SOURCES:
                continue
            if source == VALIDATION_SOURCE and _validated_dead(node):
                # A measurement that came back dead is not evidence that the URL
                # is there.  The engine's dead-host penalty below is the whole of
                # what it says, and letting the live-confirmation weight stand on
                # a 404 would make the penalty a rounding error.
                continue
            kind = _source_key(node, source, allocated_by)
            if kind is None:
                unknown.add(source)
            asset.signals.append(_signal_for(kind or source))
        asset.signals.extend(_derived_signals(node))
        asset.penalties.extend(_penalties(node, address_verdicts, resolved_hosts, wildcard_hosts))
        # The categorical half of the judgement, set for every node the model
        # claims — including the ones with no score — because "we have no
        # evidence" and "we verified nothing" are different answers a consumer
        # must be able to tell apart.
        node.evidence_state = _evidence_state(node)
        stats.by_state[node.evidence_state] = stats.by_state.get(node.evidence_state, 0) + 1
        if not asset.signals:
            # Nothing claimed this node as an asset. Leave it unscored rather
            # than publishing the engine's "0 by definition" as if it were a
            # judgement about the thing itself.
            stats.unscored += 1
            if len(stats.unscored_ids) < top_limit:
                stats.unscored_ids.append(node.id)
            continue

        result = engine.score(asset)
        node.score = result.score
        node.band = result.band
        node.score_audit = _cap(result.audit, max_audit)

        stats.scored += 1
        stats.by_band[node.band] = stats.by_band.get(node.band, 0) + 1
        per_kind = stats.by_kind.setdefault(node.kind, {})
        per_kind[node.band] = per_kind.get(node.band, 0) + 1
        if asset.penalties:
            stats.penalised += 1

    stats.unknown_sources = sorted(unknown)
    stats.by_band = dict(sorted(stats.by_band.items()))
    stats.by_state = dict(sorted(stats.by_state.items()))
    stats.by_kind = {kind: dict(sorted(bands.items())) for kind, bands in sorted(stats.by_kind.items())}
    stats.top = _top(model, top_limit)
    return stats


def _signal_for(source_key: str) -> engine.Signal:
    """The engine's signal for a source key — its weight table, not ours."""
    extra = _EXTRA_SIGNALS.get(source_key)
    if extra is None:
        return engine.signal_for_source(source_key)
    weight, reason = extra
    return engine.Signal(weight=weight, reason=reason, kind=f"source:{source_key}")


def _derived_signals(node: norm.Node) -> list[engine.Signal]:
    """Signals that come from the model's own relationships, not from a source."""
    signals: list[engine.Signal] = []
    if node.kind == vocab.NETWORK and _as_int(node.props.get("known_hosts")) > 0:
        # A routing claim that also holds infrastructure DNS points at is no
        # longer just a claim.
        signals.append(
            engine.Signal(
                weight=engine.W_ACTIVE_DNS_RESOLUTION,
                reason="network contains a host the names stage resolved",
                kind="network-confirmed",
            )
        )
    return signals


def _evidence_state(node: norm.Node) -> str:
    """The engine's categorical state for one node, from its own provenance.

    Every flag is a fact the merge already recorded: a live validation answering
    (``alive`` + the validation source), a validation that did not answer, a scope
    verdict saying ``needs_review``, and the *category* of each contributing
    artifact.  Nothing is guessed from the score, which is the point — the score
    and the state are independent answers to two different questions.
    """
    categories = {SOURCE_CATEGORY.get(source, CATEGORY_CONTEXT) for source in node.sources}
    verified = bool(node.props.get("alive")) and CATEGORY_ACTIVE in categories
    return engine.evidence_state(
        verified_alive=verified and not _validated_dead(node),
        verified_dead=_validated_dead(node),
        needs_review=str(node.props.get("scope_state", "")) == "needs_review",
        active=CATEGORY_ACTIVE in categories,
        historical=CATEGORY_HISTORICAL in categories,
        passive=CATEGORY_PASSIVE in categories,
    )


def _penalties(
    node: norm.Node,
    address_verdicts: dict[str, str],
    resolved_hosts: set[str],
    wildcard_hosts: set[str],
) -> list[engine.Signal]:
    """The engine's penalties, applied only where the model can prove them."""
    penalties: list[engine.Signal] = []
    if node.kind == vocab.URL and _validated_dead(node):
        # The engine's dead-host penalty existed but was deliberately unused
        # while the model had no re-check to prove it; live URL validation is
        # exactly that re-check, so the documented gap is now closed rather than
        # re-stated.
        penalties.append(
            engine.penalty_for_dead_host(
                "live validation measured it "
                f"{node.props.get('validation_state')}"
                + (
                    f" (HTTP {node.props.get('http_status')})"
                    if node.props.get("http_status")
                    else ""
                )
            )
        )
    if node.kind == vocab.DOMAIN and node.id in wildcard_hosts and node.id not in resolved_hosts:
        # Covered by a wildcard *and* never resolved on its own: the host's
        # only claim to exist is a wildcard match.
        penalties.append(engine.penalty_for_wildcard())
    if node.kind == vocab.IP and address_verdicts.get(node.identity, "") in SHARED_INFRA_VERDICTS:
        penalties.append(engine.penalty_for_shared_infra())
    if node.kind == vocab.SERVICE:
        address = node.identity.split(":", 1)[0]
        if address_verdicts.get(address, "") in SHARED_INFRA_VERDICTS:
            # A service on somebody else's edge is still true and still worth
            # knowing — it is simply not the target's infrastructure to own.
            penalties.append(engine.penalty_for_shared_infra())
    return penalties


def _top(model: norm.Model, limit: int) -> list[dict[str, object]]:
    """The highest-scoring nodes, for eyeballing a run without a query language."""
    ranked = sorted(
        (node for node in model.nodes.values() if node.score is not None),
        key=lambda node: (-int(node.score or 0), node.kind, node.identity),
    )
    return [
        {
            "id": node.id,
            "kind": node.kind,
            "trust": node.trust,
            "score": node.score,
            "band": node.band,
            "evidence_state": node.evidence_state,
            "sources": sorted(set(node.sources)),
        }
        for node in ranked[:limit]
    ]


def _cap(audit: list[str], limit: int) -> list[str]:
    """Keep the explanation, including the total, inside a bounded size.

    The audit's value is the *account* of the score, and its last line states the
    outcome; dropping lines from the middle keeps the reason legible when a node
    accumulated more evidence than the cap allows.
    """
    if limit <= 0 or len(audit) <= limit:
        return list(audit)
    kept = audit[: max(1, limit - 1)]
    return [*kept, f"... {len(audit) - len(kept)} more", audit[-1]]


def _as_int(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def weights_document() -> dict[str, object]:
    """The scoring contract, emitted with every run next to ``vocabulary.json``."""
    return {
        "engine": "service.recon_pipeline.platform.scoring",
        "composition": "round(strongest signal + 10% of each distinct extra kind - penalties), clamped to [0, 100]",
        "bands": {"core": 90, "high": 70, "medium": 40, "low": 0},
        "source_keys": SOURCE_KEY,
        "corroboration": {
            "strong_signal_factor": engine.CORROBORATION_FACTOR,
            "passive_signal_factor": engine.PASSIVE_CORROBORATION_FACTOR,
            "strong_at_or_above": engine.STRONG_SIGNAL_WEIGHT,
            "rule": (
                "each additional *distinct* signal corroborates: 10% of its weight "
                "for strong evidence (already near-certain), 25% for weak/medium "
                "evidence (only meaningful in aggregate)"
            ),
        },
        "evidence_states": list(engine.EVIDENCE_ORDER),
        "evidence_state_rule": (
            "a live measurement outranks every claim about the past; a measured "
            "'dead' outranks anything nobody has checked; a needs_review scope "
            "verdict outranks provenance"
        ),
        "weights": {
            "exact_domain_match": engine.W_EXACT_DOMAIN_MATCH,
            "live_confirmation": engine.W_LIVE_CONFIRMATION,
            "asn_cidr_ownership": engine.W_ASN_CIDR_OWNERSHIP,
            "authenticated_source": engine.W_AUTHENTICATED_SOURCE,
            "active_dns_resolution": engine.W_ACTIVE_DNS_RESOLUTION,
            "certificate_san": engine.W_CERTIFICATE_SAN,
            "service_response": engine.W_SERVICE_RESPONSE,
            "wildcard_negative": engine.W_WILDCARD_NEGATIVE,
            "passive_dns": engine.W_PASSIVE_DNS,
            "crt_log": engine.W_CRT_LOG,
            "archive_mention": engine.W_ARCHIVE_MENTION,
            "third_party_dataset": engine.W_THIRD_PARTY_DATASET,
            "name_similarity": engine.W_NAME_SIMILARITY,
            "wordlist_derivation": engine.W_WORDLIST_DERIVATION,
            "permutation_only": engine.W_PERMUTATION_ONLY,
        },
        "unknown_source_weight": engine.UNKNOWN_SOURCE_WEIGHT,
        "unknown_source_rule": (
            "a source key the engine does not know scores at the weakest tier and "
            "says so in the node's audit, so a mapping typo cannot pass as evidence"
        ),
        "penalties_applied": ["wildcard_match", "shared_infrastructure", "dead_host"],
        "penalties_not_applied": {
            "takedown_notice": "no takedown feed exists in this tree",
        },
        "dead_host_rule": (
            "applied only to a URL the validation stage itself measured as dead or "
            "unreachable: 'never resolved' is still not 'dead', but a 404 is"
        ),
    }
