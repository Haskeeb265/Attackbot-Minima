"""S16 — the escalation policy: passive evidence in, one decision per operation out.

The missing half of the pipeline.  Discovery already exists (the passive sources,
the classification verdicts, the ASN/CIDR expansion) and so does execution (the
ladder, the HTTP probes, the DNS engines) — what did not exist is one place that
answers *should this asset be escalated into active validation at all, and why*.

Before this module the answer was scattered: the ports ladder had its own rules,
the URL stage had none (it was passive by declaration), and the graph had a score
but no notion of "what has already been done to this asset".  Three consequences
followed, all of them observed on a live run:

* a dedicated address with no service evidence was indistinguishable from one
  that had already been scanned — so it was scanned again, or not at all;
* CDN/shared infrastructure had a *penalty* but no rule preventing a future step
  from treating it like an origin;
* broad announced ASN/BGP prefixes (``3431`` networks in one graph, most of them
  nowhere near the target) sat in the same band as validated target networks.

This module is the one answer.  It is pure — no network, no clock, no I/O — so
the rule that decides how much of somebody else's infrastructure gets touched is
readable and testable on its own, which is the only way to trust it.

The model
---------

An **operation** is a unit of active work (resolve a name, validate a URL, scan a
port, inspect a service, expand a network).  An **evidence bundle**
(:class:`AssetEvidence`) is everything the graph already knows about an asset.
:func:`decide` maps the pair to an :class:`Eligibility`: allowed or not, with a
reason an operator can read and a priority that says how urgent it is.

The ordering of the checks *is* the policy, and it is deny-by-default:

1. **scope** — ``out_of_scope`` is final for every operation (a scope failure can
   never be scored away); ``needs_review`` requires the explicit operator
   override;
2. **shared infrastructure and hosting state** — CDN/shared-edge addresses are
   never port-scanned or service-inspected without a declaration of *that address*
   as an origin (a URL validation is allowed, because probing the target's *own*
   hostname is not a scan of the platform behind it); ``unclassified`` (nobody
   looked) is refused for the noisiest operations; ``unknown`` (looked, found no
   signal) is allowed on an in-scope verdict.  Three classes, three answers: the
   measured consequence of collapsing them was shared infrastructure being
   *admitted*, because a missing verdict read as "not shared";
3. **idempotency** — an operation the asset's evidence says has already been
   attempted *by us* is refused, so an expensive step cannot be paid for twice.
   After the safety rules, so a refusal reports the fundamental objection;
4. **evidence floor** — the operation's minimum score, and the positive evidence
   that operation requires (a port scan wants an in-scope, non-shared address
   with no service evidence yet; a network expansion wants ownership or a known
   host inside the prefix, never a bare announcement).

Every branch returns a `code` (:data:`REFUSAL_*` / :data:`ALLOW_*`) beside its
reason, so a run's statistics are counted *by rule* rather than by prose, and
:func:`summarise` reports both halves — the counters and the per-candidate rows.

Network relevance
-----------------

:func:`network_relevance` implements the progression the design asks for::

    discovered -> ownership_verified -> host_discovered -> relevant -> active_candidate

A discovered BGP prefix is *not* operationally equal to a validated
target-owned network, and nothing here promotes one on its own: an announcement
is a routing claim, allocation is a registry's claim, and only a combination of
ownership and target-related evidence (a host the names stage resolved inside the
prefix) makes a network ``relevant``.  ``active_candidate`` is then a *decision*
about a relevant network, not another kind of evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# --------------------------------------------------------------------------- #
# Operations — the units of active work this policy gates
# --------------------------------------------------------------------------- #

OPERATION_DNS_RESOLUTION = "dns_resolution"
OPERATION_URL_VALIDATION = "url_validation"
OPERATION_PARAMETER_EXTRACTION = "parameter_extraction"
OPERATION_PORT_SCAN = "port_scan"
OPERATION_SERVICE_INSPECTION = "service_inspection"
OPERATION_NETWORK_EXPANSION = "network_expansion"

OPERATIONS: tuple[str, ...] = (
    OPERATION_DNS_RESOLUTION,
    OPERATION_URL_VALIDATION,
    OPERATION_PARAMETER_EXTRACTION,
    OPERATION_PORT_SCAN,
    OPERATION_SERVICE_INSPECTION,
    OPERATION_NETWORK_EXPANSION,
)

#: Operations that put packets in front of somebody else's infrastructure.
ACTIVE_OPERATIONS: frozenset[str] = frozenset(
    {
        OPERATION_DNS_RESOLUTION,
        OPERATION_URL_VALIDATION,
        OPERATION_PORT_SCAN,
        OPERATION_SERVICE_INSPECTION,
    }
)

# --------------------------------------------------------------------------- #
# Decision codes — the machine-readable half of every reason
# --------------------------------------------------------------------------- #

#: Refusals, one code per *deciding rule*.
#:
#: These exist because the first version of this module reported refusals by
#: splitting the human reason on ``":"``, which collapsed "3339 networks below
#: the relevance bar" and "3339 networks out of scope" into the same bucket and
#: made "0 eligible" impossible to explain.  A code is the rule that fired; the
#: reason is the reading of it.  Nothing here is a fallback: every branch in
#: :func:`decide` sets one, and a test asserts it.
REFUSAL_NO_SCOPE_VERDICT = "no_scope_verdict"
REFUSAL_OUT_OF_SCOPE = "out_of_scope"
REFUSAL_NEEDS_REVIEW = "needs_review"
#: ``needs_review`` **and classified**: another stage resolved one of the target's
#: names to this address at some point, but the names artifact the graph read does
#: not link them.  Separated from the code above because the remedy is different
#: and the difference was measured: on the live ``qbsco.net`` run 14 addresses
#: carried a ``cdn``/``hosted`` verdict (the ports stage had name evidence) while
#: the current ``records.jsonl`` had no name resolving to them, so the DNS-derived
#: scope verdict could not be issued.  Refreshing the names stage fixes those;
#: nothing fixes them by widening scope, which is exactly the trade this code makes
#: visible instead of silently blurring.
REFUSAL_NEEDS_REVIEW_UNLINKED = "needs_review_awaiting_dns_link"
REFUSAL_ALREADY_ATTEMPTED = "already_attempted"
#: Shared/CDN infrastructure with no operator declaration placing an origin
#: behind it.  The *only* thing that overrides this is an explicit declaration
#: (see :attr:`AssetEvidence.origin_declared`) — never an inference.
REFUSAL_SHARED_INFRASTRUCTURE = "shared_infrastructure_without_origin_evidence"
#: No classification verdict on file for the address *and* no declaration: we
#: have not looked, so active work is denied by default.  Distinct from a verdict
#: of ``unknown``, which means we looked (see :data:`HOSTING_UNCLASSIFIED`).
REFUSAL_HOSTING_UNCLASSIFIED = "hosting_unclassified"
REFUSAL_SCORE_BELOW_FLOOR = "score_below_floor"
REFUSAL_SERVICE_EVIDENCE = "service_evidence_present"
REFUSAL_NO_PARAMETER_EVIDENCE = "no_parameter_evidence"
REFUSAL_ALREADY_VALIDATED = "already_validated"
REFUSAL_URL_DEAD = "url_dead"
#: Prefix for the network progression: ``network_relevance_discovered`` etc.
REFUSAL_NETWORK_RELEVANCE = "network_relevance_"
#: A network the target does use, but which is shared/CDN-classified.
REFUSAL_NETWORK_SHARED = "network_shared_infrastructure"

#: Allowances, one code per *deciding rule* too — an eligibility without a code is
#: as unauditable as a refusal without one.
ALLOW_DEDICATED_RELEVANT = "dedicated_relevant_target"
ALLOW_IN_SCOPE_EVIDENCED = "in_scope_evidenced_asset"
#: In scope, hosting verdict exists but is ``unknown``: allowed, because a
#: verdict of *unknown* is not a verdict of *shared* — and the policy says so in
#: one place rather than by omission.
ALLOW_IN_SCOPE_UNKNOWN_HOSTING = "in_scope_unknown_hosting"
#: In scope **by the operator's own declaration** with no classification on file.
#: Allowed, and named separately from the rule above because the justification is
#: different: nobody classified it, but the person running the engagement said the
#: address is theirs.  A generated artifact being one run behind the DNS stage is
#: not a reason for the pipeline to overrule an operator's scope declaration.
ALLOW_DECLARED_HOSTING_UNCLASSIFIED = "declared_scope_unclassified_hosting"
#: A shared/CDN address the operator declared as holding an origin.  Named for
#: what it is: the gate opened on a declaration, not on an inference.
ALLOW_DECLARED_ORIGIN_ON_SHARED = "declared_origin_behind_shared_infrastructure"
ALLOW_URL_CANDIDATE = "in_scope_url_candidate"
ALLOW_RESOLUTION = "scope_cleared_candidate"
ALLOW_PARAMETER_EVIDENCE = "parameter_evidence_present"
ALLOW_NETWORK_RELEVANT = "network_relevant"

# --------------------------------------------------------------------------- #
# Hosting classes — the shared/dedicated distinction, in one place
# --------------------------------------------------------------------------- #

#: The address is the target's own (or unknown, which is treated as not-shared).
HOSTING_DEDICATED = "dedicated"
#: A CDN/WAF edge: many tenants answer on one address.
HOSTING_SHARED_EDGE = "shared_edge"
#: A third-party platform the target is a tenant of (a hosted verdict from a
#: CNAME chain) — shared infrastructure, but the target's *own* names resolve
#: through it, so it is not the same thing as an unrelated CDN edge.
HOSTING_SHARED_CLOUD = "shared_cloud"
HOSTING_UNKNOWN = "unknown"
#: **We have not looked.**  No classification verdict exists for this address at
#: all, so nothing is known about what platform it belongs to.
#:
#: This class exists because the two were the same state on the first run and the
#: consequence was inverted risk.  ``cdn_classified.jsonl`` is a snapshot of
#: *another* stage's seed set: on the measured ``qbsco.net`` run 14 of the graph's
#: 33 addresses had no row, including Cloudflare and Microsoft 365 addresses whose
#: identical siblings were classified.  Absence used to resolve to
#: :data:`HOSTING_UNKNOWN`, ``is_shared`` said ``False``, and the policy therefore
#: *admitted* infrastructure nobody had classified — the one error the CDN gate
#: exists to prevent.  An unclassified address is now refused for active work, and
#: the refusal says which file is missing a row for it.
HOSTING_UNCLASSIFIED = "unclassified"

#: Verdict → hosting class.  Kept as a table rather than a chain of ``if``s so a
#: new verdict is added in one place; the pipeline's own vocabulary
#: (``classify/cdn.py``) is the *input*, never re-derived here.  An *empty*
#: verdict is not in this table on purpose: it maps to :data:`HOSTING_UNCLASSIFIED`
#: through the ``classified`` argument, which is the only way to tell "the
#: classifier said ''" from "nobody ever asked it".
VERDICT_CLASSES: dict[str, str] = {
    "cdn": HOSTING_SHARED_EDGE,
    "hosted": HOSTING_SHARED_CLOUD,
    "dedicated": HOSTING_DEDICATED,
    "unknown": HOSTING_UNKNOWN,
}

SHARED_CLASSES: frozenset[str] = frozenset({HOSTING_SHARED_EDGE, HOSTING_SHARED_CLOUD})


def hosting_class(verdict: str = "", provider: str = "", *, classified: bool | None = None) -> str:
    """The hosting class for a classification verdict.

    *classified* is whether a verdict was ever produced for this address; when it
    is omitted it is inferred from the verdict being non-empty, which is right for
    every caller that passes the artifact's own vocabulary.  Passing it explicitly
    is how a caller that knows an address was *skipped* says so.

    Three answers, deliberately distinct:

    ``dedicated``
        the classifier saw no CDN/WAF signal **and** one of the target's names
        resolves here — positive evidence, and the class active work is for;
    ``unknown``
        the classifier looked and found no signal either way;
    ``unclassified``
        nobody looked.  Not the same answer, and the policy treats it differently.
    """
    token = (verdict or "").strip().lower()
    if not token and classified is not False:
        return HOSTING_UNCLASSIFIED
    if classified is False:
        return HOSTING_UNCLASSIFIED
    return VERDICT_CLASSES.get(token, HOSTING_UNCLASSIFIED if not token else HOSTING_UNKNOWN)


def is_shared(hosting: str) -> bool:
    return hosting in SHARED_CLASSES


#: Classes an address must be in to reach the noisiest operations.  ``unclassified``
#: is excluded: the refusal is the point.
SCANNABLE_HOSTING: frozenset[str] = frozenset(
    {HOSTING_DEDICATED, HOSTING_UNKNOWN}
)


# --------------------------------------------------------------------------- #
# Network relevance — the progression the ASN/CIDR output feeds
# --------------------------------------------------------------------------- #

RELEVANCE_DISCOVERED = "discovered"
RELEVANCE_OWNERSHIP_VERIFIED = "ownership_verified"
RELEVANCE_HOST_DISCOVERED = "host_discovered"
RELEVANCE_RELEVANT = "relevant"
RELEVANCE_ACTIVE_CANDIDATE = "active_candidate"

RELEVANCE_ORDER: tuple[str, ...] = (
    RELEVANCE_DISCOVERED,
    RELEVANCE_OWNERSHIP_VERIFIED,
    RELEVANCE_HOST_DISCOVERED,
    RELEVANCE_RELEVANT,
    RELEVANCE_ACTIVE_CANDIDATE,
)

#: States from which expanding the network into further active discovery is
#: permissible.  A discovered prefix is never in this set: "somebody announces
#: this range" is a statement about the internet, not about the target.
EXPANDABLE_RELEVANCE: frozenset[str] = frozenset({RELEVANCE_RELEVANT, RELEVANCE_ACTIVE_CANDIDATE})


@dataclass(frozen=True)
class Relevance:
    """A network's place in the progression, with the reason it is there."""

    state: str
    reason: str

    @property
    def expandable(self) -> bool:
        return self.state in EXPANDABLE_RELEVANCE

    def to_dict(self) -> dict[str, str]:
        return {"relevance_state": self.state, "relevance_reason": self.reason}


def network_relevance(
    *,
    allocated: bool = False,
    announced: bool = False,
    known_hosts: int = 0,
    in_scope: bool = False,
    already_expanded: bool = False,
) -> Relevance:
    """Where a network sits in ``discovered → … → active_candidate``.

    ``allocated`` (a registry says the organisation holds the prefix) is the only
    thing that earns ``ownership_verified``; ``announced`` alone never does.
    Either ownership **or** a host our own resolution found inside the prefix is
    required for ``relevant`` — one claim about ownership plus one observation is
    the difference between "the target's network" and "a network in the same
    part of the world as the target".

    Pure *evidence* progression: an ``announced`` flag is never promoted, and
    sharing is not consulted here at all — a shared network is still relevant, it
    is just not expandable, and that is :func:`decide`'s call.
    """
    if not allocated and not known_hosts:
        return Relevance(
            RELEVANCE_DISCOVERED,
            "routing announcement only: no registry allocation and no host our "
            "own DNS resolved inside the prefix",
        )
    if allocated and not known_hosts:
        return Relevance(
            RELEVANCE_OWNERSHIP_VERIFIED,
            "registry allocation (RDAP) names the organisation as the holder; no "
            "target infrastructure observed inside it yet",
        )
    if not allocated and known_hosts:
        return Relevance(
            RELEVANCE_HOST_DISCOVERED,
            f"{known_hosts} address(es) our own DNS resolved are inside the prefix",
        )
    # Sharing is *not* a branch here, and that is deliberate.  Relevance is a
    # statement about evidence; whether the network may be expanded is a
    # *decision*, and it is taken in :func:`decide`.  The earlier version returned
    # ``relevant`` here with the reason "not an active candidate" — and because
    # ``relevant`` is expandable, the network was expandable.  A reason that
    # contradicts the field beside it is worse than no reason: the measured
    # consequence would have been a sweep of a CDN's announced space, described in
    # prose as something we do not do.
    if not in_scope:
        return Relevance(
            RELEVANCE_RELEVANT,
            "allocated and holding target infrastructure; outside declared scope, so "
            "the operator must move it into scope before active expansion",
        )
    if already_expanded:
        return Relevance(
            RELEVANCE_RELEVANT,
            "allocated, holding target infrastructure, in scope, and already expanded "
            "into active discovery",
        )
    return Relevance(
        RELEVANCE_ACTIVE_CANDIDATE,
        "allocated to the organisation and holding target infrastructure, in scope, "
        "and not yet expanded",
    )


# --------------------------------------------------------------------------- #
# The evidence bundle and the decision
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class AssetEvidence:
    """Everything the graph knows about one asset, in the policy's vocabulary.

    Deliberately flat and primitive-valued: it is built from a graph node by the
    caller (``graph_normalize``) and from a candidate by the URL stage, so it must
    not depend on either one's model.
    """

    asset_type: str = ""
    identity: str = ""
    #: ``in_scope`` / ``needs_review`` / ``out_of_scope`` / ``""`` (no verdict).
    scope_state: str = ""
    score: int | None = None
    band: str = ""
    #: One of the engine's evidence states (see :mod:`platform.scoring`).
    evidence_state: str = ""
    hosting: str = HOSTING_UNKNOWN
    #: Whether a hosting classification verdict exists at all.  ``False`` means the
    #: artifact had no row for this address, which the policy treats as "denied by
    #: default", not as "not shared".
    hosting_classified: bool = True
    #: True when the operator *declared* this address or a network containing it,
    #: rather than the pipeline inferring scope.  First-hand intent, which is why
    #: it can stand in where a generated classification artifact is missing.
    origin_declared: bool = False
    #: True only when the operator declared **this address**, not a range around
    #: it.  The distinction matters exactly once, and it is the difference between
    #: a policy and a hole: a broad declaration that happens to contain a CDN's
    #: space must not authorise scanning addresses in it, because the declaration
    #: was about a network and the address is somebody else's edge.  An origin
    #: behind an edge is a specific host, so only a specific declaration opens it.
    origin_address_declared: bool = False
    #: True when a service/port is already known for this asset.
    has_service_evidence: bool = False
    #: Operations the evidence already says were attempted (``port_scan``, …).
    operations: frozenset[str] = frozenset()
    #: Network facts, ignored for other asset types.
    allocated: bool = False
    announced: bool = False
    known_hosts: int = 0
    already_expanded: bool = False
    #: Set when the asset is a URL/host that historical archives mentioned.
    historical: bool = False
    #: Set when the asset exposes parameters (which is what makes extraction
    #: worth doing at all).
    has_parameters: bool = False

    def with_operations(self, operations: frozenset[str]) -> "AssetEvidence":
        return AssetEvidence(**{**self.__dict__, "operations": operations})


@dataclass
class EscalationPolicy:
    """The operator-tunable thresholds.  Defaults are the conservative ones.

    Every number here has to be justified by the evidence model, because this is
    the gate that decides how much traffic the engagement produces:

    * ``min_score_port_scan = 70`` — the ``high`` band.  A port scan is the
      noisiest thing this system does, so nothing below "a claim with real
      support" earns it;
    * ``min_score_url_validation = 0`` — the floor is deliberately absent: a
      single archived URL is *exactly* the thing validation exists to check, and
      refusing to validate it because it is weakly evidenced would leave the
      question permanently open.  Volume, not score, is the control here
      (``max_url_validations_per_host``);
    * ``allow_needs_review`` — off.  A discovered asset is the operator's
      decision, not the pipeline's.
    """

    min_score_port_scan: int = 70
    min_score_service_inspection: int = 70
    min_score_url_validation: int = 0
    min_score_dns_resolution: int = 0
    #: Cap on validations per host, so one chatty host cannot consume the run.
    max_url_validations_per_host: int = 25
    #: Allow active work on needs_review assets (operator override).
    allow_needs_review: bool = False
    #: Re-run an operation the evidence says was already attempted.
    repeat_operations: bool = False
    #: Allow a *shared/CDN* address to be port-scanned when the operator declared
    #: it (or its network) in scope.  Off by default is the safe reading, but an
    #: engagement where the origin sits behind the provider's own edge is real and
    #: the declaration is the operator's statement, so the gate opens on that and
    #: nothing else.  Never inferred from a score, a name or a CNAME.
    allow_declared_origin_on_shared: bool = True
    #: Allow active work on an address with no hosting classification on file.
    #: Off, and deliberately: see :data:`HOSTING_UNCLASSIFIED`.
    allow_unclassified_hosting: bool = False


@dataclass(frozen=True)
class Eligibility:
    """The policy's answer for one (asset, operation) pair."""

    eligible: bool
    operation: str
    reason: str
    #: The rule that decided it — one of the ``REFUSAL_*``/``ALLOW_*`` codes.  A
    #: decision without a code cannot be counted, and "which rule refused 3 339
    #: networks" is the question this field answers.
    code: str = ""
    asset_type: str = ""
    identity: str = ""
    #: Sort key for the triage queue: evidence state first, then score, then
    #: identity - so two runs over the same graph order candidates identically.
    priority: tuple = field(default_factory=tuple)

    @property
    def verb(self) -> str:
        return "ALLOW" if self.eligible else "SKIP"

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_type": self.asset_type,
            "identity": self.identity,
            "operation": self.operation,
            "verb": self.verb,
            "code": self.code,
            "reason": self.reason,
        }


def _floor_for(policy: EscalationPolicy, operation: str) -> int | None:
    """The score floor for *operation*, or ``None`` for no floor."""
    return {
        OPERATION_PORT_SCAN: policy.min_score_port_scan,
        OPERATION_SERVICE_INSPECTION: policy.min_score_service_inspection,
        OPERATION_URL_VALIDATION: policy.min_score_url_validation,
        OPERATION_DNS_RESOLUTION: policy.min_score_dns_resolution,
    }.get(operation)


def decide(
    evidence: AssetEvidence,
    operation: str,
    *,
    policy: EscalationPolicy | None = None,
) -> Eligibility:
    """Should *operation* run against this asset?  Always with a reason.

    Pure: the same evidence and policy always produce the same decision, which is
    what makes an active step auditable after the fact rather than "the tool ran".
    """
    policy = policy or EscalationPolicy()
    state_rank = _evidence_rank(evidence)
    priority = (state_rank, -(evidence.score or 0), evidence.identity)

    def answer(eligible: bool, reason: str, code: str) -> Eligibility:
        return Eligibility(
            eligible=eligible,
            operation=operation,
            reason=reason,
            code=code,
            asset_type=evidence.asset_type,
            identity=evidence.identity,
            priority=priority,
        )

    if operation not in OPERATIONS:
        raise ValueError(f"unknown operation {operation!r}; known: {', '.join(OPERATIONS)}")

    # 1. scope — a scope failure is final for every operation, and *no* verdict is
    #    a failure too: deny-by-default is the whole rule.  An asset nobody asked
    #    the scope engine about is exactly the asset a pipeline bug would send
    #    traffic to, so the policy refuses it instead of assuming it is ours.
    if operation in ACTIVE_OPERATIONS or operation == OPERATION_NETWORK_EXPANSION:
        if not evidence.scope_state:
            return answer(
                False,
                "no scope verdict for this asset: active work is denied by default",
                REFUSAL_NO_SCOPE_VERDICT,
            )
    if evidence.scope_state == "out_of_scope":
        return answer(
            False,
            "out of declared scope: never actively touched",
            REFUSAL_OUT_OF_SCOPE,
        )
    if evidence.scope_state == "needs_review" and not policy.allow_needs_review:
        # Only an *address* can be "classified but unlinked": hosting classes are a
        # property of addresses, and a network has no classification to be missing.
        if evidence.hosting_classified and evidence.asset_type == "ip":
            return answer(
                False,
                "needs_review, but a classification verdict exists for this "
                "address: a stage had name evidence the current DNS records "
                "artifact does not link, so re-run the names stage (or declare the "
                "address) rather than widening scope",
                REFUSAL_NEEDS_REVIEW_UNLINKED,
            )
        return answer(
            False,
            "needs_review: discovered but not declared, so an operator must move it "
            "into scope first",
            REFUSAL_NEEDS_REVIEW,
        )

    # 2. shared infrastructure and hosting state — before idempotency, because
    #    *why* an asset may not be touched is more fundamental than whether the
    #    budget was already spent on it.  An address that was scanned and is also a
    #    CDN edge must report the safety rule, or an operator auditing refusals
    #    would read "already attempted" on a host that should never have been in
    #    the scan set at all.
    #
    #    Shared infrastructure — never port-scan somebody's edge, unless the
    #    operator told us an origin lives behind it.
    if operation in {OPERATION_PORT_SCAN, OPERATION_SERVICE_INSPECTION}:
        if is_shared(evidence.hosting) and not (
            evidence.origin_address_declared and policy.allow_declared_origin_on_shared
        ):
            return answer(
                False,
                f"{evidence.hosting} infrastructure and no declaration of this "
                "address as an origin: shared infrastructure is never port-scanned "
                "(declare the exact address, not the range it sits in, to override)",
                REFUSAL_SHARED_INFRASTRUCTURE,
            )
        # 3b. never scanned either when nobody has classified it — unless the
        #     *operator* declared the address or its network.  Absence of a verdict
        #     is not evidence that the address is the target's own, but a
        #     declaration is not an inference: the classification artifact being a
        #     run behind the DNS stage must not let a generated file overrule the
        #     scope the engagement was set up with.
        if (
            evidence.hosting == HOSTING_UNCLASSIFIED
            and not policy.allow_unclassified_hosting
            and not evidence.origin_declared
        ):
            return answer(
                False,
                "no hosting classification on file for this address (absent from "
                "cdn_classified.jsonl) and no scope declaration: classify it, or "
                "declare the address, before active scanning",
                REFUSAL_HOSTING_UNCLASSIFIED,
            )

    # 3. idempotency — never pay for the same operation twice.
    if operation in evidence.operations and not policy.repeat_operations:
        return answer(
            False, f"{operation} already attempted for this asset", REFUSAL_ALREADY_ATTEMPTED
        )

    # 4. the operation's own evidence requirement.
    if operation == OPERATION_NETWORK_EXPANSION:
        if is_shared(evidence.hosting):
            # Expansion means actively enumerating what is inside the prefix, and a
            # shared/CDN prefix is the provider's edge: the hosts in it are the
            # provider's tenants, not the target's estate.
            return answer(
                False,
                f"{evidence.hosting} network: relevant to the target, but expanding "
                "it would enumerate shared infrastructure rather than the target's "
                "own space",
                REFUSAL_NETWORK_SHARED,
            )
        relevance = network_relevance(
            allocated=evidence.allocated,
            announced=evidence.announced,
            known_hosts=evidence.known_hosts,
            in_scope=evidence.scope_state == "in_scope",
            already_expanded=evidence.already_expanded,
        )
        if not relevance.expandable:
            return answer(
                False,
                f"network relevance '{relevance.state}': {relevance.reason}",
                REFUSAL_NETWORK_RELEVANCE + relevance.state,
            )
        return answer(True, relevance.reason, ALLOW_NETWORK_RELEVANT)

    if operation == OPERATION_DNS_RESOLUTION:
        return answer(
            True,
            "candidate names are resolved once, through the policy gate",
            ALLOW_RESOLUTION,
        )

    if operation == OPERATION_PARAMETER_EXTRACTION:
        if not evidence.has_parameters:
            return answer(
                False, "no parameter evidence to extract from", REFUSAL_NO_PARAMETER_EVIDENCE
            )
        return answer(
            True,
            "parameter provenance is derivable from what is already known",
            ALLOW_PARAMETER_EVIDENCE,
        )

    if operation == OPERATION_URL_VALIDATION:
        if evidence.evidence_state == "dead":
            return answer(
                False, "already validated and did not answer", REFUSAL_URL_DEAD
            )
        if evidence.evidence_state == "actively_verified":
            return answer(
                False,
                "already validated in a previous run (idempotent)",
                REFUSAL_ALREADY_VALIDATED,
            )
        return answer(
            True,
            "URL candidate with a plausible in-scope host: validate it live before "
            "treating the historical claim as a current asset",
            ALLOW_URL_CANDIDATE,
        )

    # port/service scanning
    if evidence.has_service_evidence:
        return answer(
            False,
            "service evidence already exists for this asset; nothing to escalate",
            REFUSAL_SERVICE_EVIDENCE,
        )
    floor = _floor_for(policy, operation)
    if floor and (evidence.score is None or evidence.score < floor):
        return answer(
            False,
            f"score {evidence.score if evidence.score is not None else 'unknown'} below "
            f"the {operation} floor {floor}",
            REFUSAL_SCORE_BELOW_FLOOR,
        )
    if evidence.hosting == HOSTING_DEDICATED:
        return answer(
            True,
            f"dedicated address (no CDN/WAF signal, one of the target's names "
            f"resolves here), {evidence.scope_state}, score {evidence.score}, no "
            "service evidence yet: escalate to active validation",
            ALLOW_DEDICATED_RELEVANT,
        )
    if evidence.hosting == HOSTING_UNCLASSIFIED:
        return answer(
            True,
            "address is in declared scope but carries no hosting classification: "
            "escalated on the operator's own declaration, so the classification "
            "gap is reported rather than silently becoming a refusal",
            ALLOW_DECLARED_HOSTING_UNCLASSIFIED,
        )
    if is_shared(evidence.hosting):
        return answer(
            True,
            f"{evidence.hosting} address the operator declared as its own origin: "
            "escalated on that declaration, because only the engagement knows an "
            "origin lives behind the provider's edge",
            ALLOW_DECLARED_ORIGIN_ON_SHARED,
        )
    return answer(
        True,
        f"{evidence.evidence_state or 'evidenced'} asset, hosting classified as "
        f"'{evidence.hosting}' (not shared), score {evidence.score}, no service "
        "evidence yet: escalate to active validation",
        ALLOW_IN_SCOPE_UNKNOWN_HOSTING
        if evidence.hosting == HOSTING_UNKNOWN
        else ALLOW_IN_SCOPE_EVIDENCED,
    )


# --------------------------------------------------------------------------- #
# URL validation priority — which candidates get the budget
# --------------------------------------------------------------------------- #

#: The host already served something on this run: a name that answers is worth
#: more checks than one that has only ever been mentioned by an archive.
URL_HOST_VERIFIED = "verified"
#: Every measurement for this host so far failed: the host is *cheap to skip*.
URL_HOST_DEAD = "dead"
#: Nothing measured on this host yet.
URL_HOST_UNKNOWN = "unknown"


@dataclass(frozen=True)
class UrlPriority:
    """Where one URL candidate sits in the validation queue, and why.

    This is a *selection* priority, not a graph score: it orders a bounded budget
    and never changes an asset's standing.  That separation is deliberate — the
    score answers "how evidenced is this?", which the priority must not
    duplicate, or the two would double-count each other.
    """

    rank: int
    reason: str
    components: dict[str, int] = field(default_factory=dict)

    def sort_key(self, *, path_length: int = 0, url: str = "") -> tuple:
        """Total order: rank first, then the deterministic tie-breaks.

        Two runs over the same candidate set therefore validate the same URLs, in
        the same order, which is what makes a validation budget reviewable.
        """
        return (-self.rank, path_length, url)


#: Score contributions.  Named, and documented, because each is a claim about
#: what deserves a request: a sensitive path is worth more than a long one, a
#: parameterised URL is worth more than a bare one, and independent mentions are
#: worth more than repeats from one source.
URL_PRIORITY_INTERESTING = 40
URL_PRIORITY_KIND = {1: 30, 2: 22, 3: 14, 4: 8}
URL_PRIORITY_PARAMETERS = 6
URL_PRIORITY_EXTRA_SOURCE = 4
URL_PRIORITY_MAX_SOURCE_BONUS = 12
URL_PRIORITY_HOST_VERIFIED = 15
URL_PRIORITY_HOST_DEAD = -25
URL_PRIORITY_IN_SCOPE = 5


def url_validation_priority(
    *,
    scope_state: str = "",
    kind_rank: int = 0,
    interesting: bool = False,
    has_parameters: bool = False,
    sources: int = 1,
    host_state: str = URL_HOST_UNKNOWN,
) -> UrlPriority:
    """Rank a URL candidate for live validation — bounded budget, best first.

    The budget is real (a run validates hundreds, not tens of thousands), so the
    queue has to be an argument rather than a file order.  Six signals, all
    available before any request is sent:

    * **scope** — an in-scope host is the only kind that can be probed at all, so
      it is a tie-break, not a promotion;
    * **sensitive path** (``.git/config``, ``.env``, dumps, admin consoles) — the
      single strongest signal, because it is what a human reads first;
    * **kind** — APIs and structured responses ahead of pages, images last;
      the rank comes from the URL pipeline's own vocabulary so this module does
      not have to know it;
    * **parameters** — a parameterised URL is an input surface, and the parameter
      provenance pass exists to record what it exposes;
    * **independent mentions** — a URL several archives agree on is a real
      endpoint, one that a single source mentioned may be a crawler artefact;
    * **host state from this run** — a host that has already answered is worth
      more checks than one whose every measurement failed.  This is the one
      adaptive signal, and it is measured, not guessed.
    """
    components: dict[str, int] = {}

    def add(name: str, value: int) -> None:
        if value:
            components[name] = value

    if scope_state == "in_scope":
        add("in_scope_host", URL_PRIORITY_IN_SCOPE)
    if interesting:
        add("sensitive_path", URL_PRIORITY_INTERESTING)
    add("kind", URL_PRIORITY_KIND.get(kind_rank, 0))
    if has_parameters:
        add("parameters", URL_PRIORITY_PARAMETERS)
    add(
        "independent_sources",
        min(max(sources - 1, 0) * URL_PRIORITY_EXTRA_SOURCE, URL_PRIORITY_MAX_SOURCE_BONUS),
    )
    if host_state == URL_HOST_VERIFIED:
        add("host_verified_this_run", URL_PRIORITY_HOST_VERIFIED)
    elif host_state == URL_HOST_DEAD:
        add("host_dead_this_run", URL_PRIORITY_HOST_DEAD)

    rank = sum(components.values())
    reason = ", ".join(f"{name}{value:+d}" for name, value in components.items())
    return UrlPriority(rank=rank, reason=reason or "no distinguishing evidence", components=components)


#: Host states that make a URL worth re-checking even though it was measured before:
#: a *redirect* or a *protected* response is not a settled answer, and TTL expiry
#: is the other reason a measurement stops counting (see the URL stage's settings).

def _evidence_rank(evidence: AssetEvidence) -> int:
    """Triage position for an evidence bundle (see ``scoring.EVIDENCE_ORDER``)."""
    from .scoring import evidence_state_rank

    state = evidence.evidence_state
    if not state:
        state = "unverified" if evidence.score is not None else ""
    return evidence_state_rank(state)


def plan(
    assets: list[AssetEvidence],
    operation: str,
    *,
    policy: EscalationPolicy | None = None,
) -> list[Eligibility]:
    """Decide many assets for one operation, best-first — the candidate queue."""
    decisions = [decide(asset, operation, policy=policy) for asset in assets]
    decisions.sort(key=lambda decision: (not decision.eligible, decision.priority))
    return decisions


def summarise(decisions: list[Eligibility]) -> dict[str, Any]:
    """The report block for one policy plan, counted by *rule*.

    ``refusal_codes`` is the countable half (which rule fired, how often) and
    ``refusals`` the readable half (one row per refused candidate, with the exact
    reason).  Both exist because either alone is unusable: codes without reasons
    cannot be acted on, and reasons without codes cannot be counted.
    """
    eligible = [decision for decision in decisions if decision.eligible]
    codes: dict[str, int] = {}
    reasons: dict[str, int] = {}
    refusals: list[dict[str, Any]] = []
    for decision in decisions:
        if decision.eligible:
            continue
        codes[decision.code] = codes.get(decision.code, 0) + 1
        reasons[decision.reason] = reasons.get(decision.reason, 0) + 1
        refusals.append(decision.to_dict())
    return {
        "considered": len(decisions),
        "eligible": len(eligible),
        "refused": len(decisions) - len(eligible),
        "refusal_codes": dict(sorted(codes.items(), key=lambda item: (-item[1], item[0]))),
        "refusal_reasons": dict(
            sorted(reasons.items(), key=lambda item: (-item[1], item[0]))
        ),
        "refusals": refusals,
        "queue": [decision.to_dict() for decision in eligible],
    }


__all__ = [
    "ACTIVE_OPERATIONS",
    "ALLOW_DECLARED_HOSTING_UNCLASSIFIED",
    "ALLOW_DECLARED_ORIGIN_ON_SHARED",
    "ALLOW_DEDICATED_RELEVANT",
    "ALLOW_IN_SCOPE_EVIDENCED",
    "ALLOW_IN_SCOPE_UNKNOWN_HOSTING",
    "ALLOW_NETWORK_RELEVANT",
    "ALLOW_PARAMETER_EVIDENCE",
    "ALLOW_RESOLUTION",
    "ALLOW_URL_CANDIDATE",
    "AssetEvidence",
    "Eligibility",
    "EscalationPolicy",
    "EXPANDABLE_RELEVANCE",
    "HOSTING_DEDICATED",
    "HOSTING_SHARED_CLOUD",
    "HOSTING_SHARED_EDGE",
    "HOSTING_UNCLASSIFIED",
    "HOSTING_UNKNOWN",
    "OPERATIONS",
    "OPERATION_DNS_RESOLUTION",
    "OPERATION_NETWORK_EXPANSION",
    "OPERATION_PARAMETER_EXTRACTION",
    "OPERATION_PORT_SCAN",
    "OPERATION_SERVICE_INSPECTION",
    "OPERATION_URL_VALIDATION",
    "RELEVANCE_ACTIVE_CANDIDATE",
    "RELEVANCE_DISCOVERED",
    "RELEVANCE_HOST_DISCOVERED",
    "RELEVANCE_ORDER",
    "RELEVANCE_OWNERSHIP_VERIFIED",
    "RELEVANCE_RELEVANT",
    "REFUSAL_ALREADY_ATTEMPTED",
    "REFUSAL_ALREADY_VALIDATED",
    "REFUSAL_HOSTING_UNCLASSIFIED",
    "REFUSAL_NEEDS_REVIEW",
    "REFUSAL_NEEDS_REVIEW_UNLINKED",
    "REFUSAL_NETWORK_RELEVANCE",
    "REFUSAL_NETWORK_SHARED",
    "REFUSAL_NO_PARAMETER_EVIDENCE",
    "REFUSAL_NO_SCOPE_VERDICT",
    "REFUSAL_OUT_OF_SCOPE",
    "REFUSAL_SCORE_BELOW_FLOOR",
    "REFUSAL_SERVICE_EVIDENCE",
    "REFUSAL_SHARED_INFRASTRUCTURE",
    "REFUSAL_URL_DEAD",
    "Relevance",
    "SCANNABLE_HOSTING",
    "URL_HOST_DEAD",
    "URL_HOST_UNKNOWN",
    "URL_HOST_VERIFIED",
    "UrlPriority",
    "decide",
    "hosting_class",
    "is_shared",
    "network_relevance",
    "plan",
    "summarise",
    "url_validation_priority",
]
