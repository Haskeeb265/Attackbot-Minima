"""S2 — the scoring engine: how much attention does an asset deserve?

Pure math, no I/O, no clock: the same asset always scores the same, and the
audit trail shows *why*.  The weights come from ``recon.md`` §4 ("Scoring
matrix", hard signals 100 → weak signals 10) and encode one idea: evidence
closer to a contract with the organisation outweighs evidence that merely
coexists with it on the internet.

Score composition::

    score = round(
        max(base_weight, strongest single signal)   # a floor, not a sum
        + 0.1 * (sum of remaining signal weights)   # corroboration nudges
        - penalties                                  # takedowns, dead hosts
    )

Signals are *added* as evidence accumulates; the strongest one sets the
floor.  Corroboration (many weak signals) can lift an asset above its best
single signal but never double-counts its way to certainty — which is the
difference between "eight sources agree" and "one source echoed eight times".

Two refinements make the number answer the question triage actually asks
("which assets deserve active validation next?") rather than "how many passive
sources mentioned this?":

* **Corroboration is tier-aware.**  A second *weak or medium* signal is worth
  25 % of its weight, not 10 %.  Weak evidence is only meaningful in aggregate -
  one archived URL mention is a rumour, two independent archives agreeing is
  evidence, three is strong - whereas a second *strong* signal (a live response,
  a certificate) is already near-certain, so it corroborates at 10 % to keep the
  ceiling meaningful.  The two factors are named, not inline numbers.
* **Live confirmation has its own weight.**  ``W_LIVE_CONFIRMATION`` (85) sits
  between our DNS resolution (90) and a scanned service (80), so a URL that
  actually answered now is *never* comparable to one an archive mentioned in
  2019 (40) - which was the point of separating discovery from validation.

The engine is deliberately dumb about *what* an asset is: it scores
:class:`ScoredAsset` records built by callers (the graph writers, the
pipelines' report paths), keeping this module pure and independently
testable.  It also renders one *categorical* judgement the number cannot carry -
:func:`evidence_state` - because "score 44" says nothing about whether the
claim was verified today or found in a crawl a decade ago.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# Signal weights (recon.md §4)
# --------------------------------------------------------------------------- #

#: Hard signals — immediate high confidence (weight 100).
W_EXACT_DOMAIN_MATCH = 100
W_ASN_CIDR_OWNERSHIP = 100
W_AUTHENTICATED_SOURCE = 100

#: Strong signals (weight 70–90).
W_ACTIVE_DNS_RESOLUTION = 90
#: A URL (or host) we asked, and which answered, in this run.  Deliberately
#: below our own DNS resolution and above a scanned service: it is a live
#: confirmation of the *asset*, not of the address behind it, but it is a
#: current measurement rather than a historical claim - which is exactly the
#: distinction the URL pipeline's validation stage exists to make.
W_LIVE_CONFIRMATION = 85
W_CERTIFICATE_SAN = 80
W_SERVICE_RESPONSE = 80
W_WILDCARD_NEGATIVE = 70

#: Medium signals (40–60).
W_PASSIVE_DNS = 60
W_CRT_LOG = 50
W_ARCHIVE_MENTION = 40
W_THIRD_PARTY_DATASET = 40

#: Weak signals (weight 10–20).
W_NAME_SIMILARITY = 20
W_WORDLIST_DERIVATION = 10
W_PERMUTATION_ONLY = 10

#: A source the engine has no weight for.  It lands in the weakest tier rather
#: than being given confidence it did not earn — and the audit *says* it was
#: unknown, because a caller that misspells a source key would otherwise get a
#: plausible-looking number and no way to notice (see ``signal_for_source``).
UNKNOWN_SOURCE_WEIGHT = W_THIRD_PARTY_DATASET // 4

#: Penalties.
P_TAKEDOWN_NOTICE = -60
P_WILDCARD_MATCH = -40
P_DEAD_HOST = -30
P_SHARED_INFRASTRUCTURE = -15

#: Corroboration: each additional distinct signal adds a fraction of its weight.
#: Strong evidence corroborates at 10 % (it is already near-certain, so a second
#: one must not buy its way to the ceiling); weak/medium evidence at 25 %, because
#: a single weak signal is a rumour and agreement between independent weak signals
#: is the whole of what it can ever tell us.
CORROBORATION_FACTOR = 0.1
PASSIVE_CORROBORATION_FACTOR = 0.25

#: Above this weight a signal is "strong" for the purpose of the factor above.
STRONG_SIGNAL_WEIGHT = W_WILDCARD_NEGATIVE


def corroboration_factor(weight: int) -> float:
    """The fraction a confirming signal of *weight* adds to the floor."""
    return CORROBORATION_FACTOR if weight >= STRONG_SIGNAL_WEIGHT else PASSIVE_CORROBORATION_FACTOR

#: Score bands — how the report talks about a score.
BAND_CORE = "core"                # 90+
BAND_HIGH = "high"                # 70–89
BAND_MEDIUM = "medium"            # 40–69
BAND_LOW = "low"                  # < 40

# --------------------------------------------------------------------------- #
# Evidence state — the categorical half of "how much attention?"
# --------------------------------------------------------------------------- #

#: Our own measurement confirms the asset answers now.
EVIDENCE_ACTIVELY_VERIFIED = "actively_verified"
#: Claimed by evidence, never measured.  The candidates active validation is for.
EVIDENCE_UNVERIFIED = "unverified"
#: Third-party OSINT/CT datasets name it; nobody has asked it anything.
EVIDENCE_PASSIVE = "passive"
#: Only historical archives mention it (Wayback/gau): it existed, maybe not now.
EVIDENCE_HISTORICAL = "historical"
#: Measured, and it did not answer.
EVIDENCE_DEAD = "dead"
#: Not ours to decide: outside declared scope, or discovered and unreviewed.
EVIDENCE_NEEDS_REVIEW = "needs_review"

#: How a triage queue orders the states (lower = look at it sooner).  A verified
#: asset moves on to exploitation; an unverified claim is the next thing to
#: validate; a dead one is kept for the record and looked at last.
EVIDENCE_ORDER: tuple[str, ...] = (
    EVIDENCE_ACTIVELY_VERIFIED,
    EVIDENCE_NEEDS_REVIEW,
    EVIDENCE_UNVERIFIED,
    EVIDENCE_PASSIVE,
    EVIDENCE_HISTORICAL,
    EVIDENCE_DEAD,
)


def evidence_state_rank(state: str) -> int:
    """Position of *state* in :data:`EVIDENCE_ORDER` (unknown states last)."""
    try:
        return EVIDENCE_ORDER.index(state)
    except ValueError:
        return len(EVIDENCE_ORDER)


def evidence_state(
    *,
    verified_alive: bool = False,
    verified_dead: bool = False,
    active: bool = False,
    historical: bool = False,
    passive: bool = False,
    needs_review: bool = False,
) -> str:
    """The categorical state of the evidence behind an asset.

    The order of the checks *is* the policy, and it is deliberately:

    1. **a live measurement wins.**  ``verified_alive`` describes the asset now,
       whatever a 2019 archive said about it;
    2. **a negative measurement is still a measurement** - ``dead`` outranks
       anything nobody has checked;
    3. **needs_review** is a scope verdict, and outranks provenance because an
       asset we may not touch should be seen for that reason, not for how it was
       found;
    4. then provenance, strongest first: our own active evidence, third-party
       datasets, historical archives, and finally a claim nothing supports yet.
    """
    if verified_alive:
        return EVIDENCE_ACTIVELY_VERIFIED
    if verified_dead:
        return EVIDENCE_DEAD
    if needs_review:
        return EVIDENCE_NEEDS_REVIEW
    if active:
        return EVIDENCE_ACTIVELY_VERIFIED
    if historical:
        return EVIDENCE_HISTORICAL
    if passive:
        return EVIDENCE_PASSIVE
    return EVIDENCE_UNVERIFIED


@dataclass(frozen=True)
class Signal:
    """One piece of evidence about an asset."""

    weight: int
    reason: str
    #: Distinguishes independently-sourced evidence from echoes of the same
    #: source; only distinct ``kind`` values count as corroboration.
    kind: str = ""

    def to_dict(self) -> dict[str, object]:
        return {"weight": self.weight, "reason": self.reason, "kind": self.kind}


@dataclass
class ScoredAsset:
    """An asset plus its evidence, ready to score."""

    asset_type: str
    canonical_value: str
    signals: list[Signal] = field(default_factory=list)
    penalties: list[Signal] = field(default_factory=list)

    def add_signal(self, weight: int, reason: str, kind: str = "") -> None:
        self.signals.append(Signal(weight=weight, reason=reason, kind=kind))

    def add_penalty(self, weight: int, reason: str, kind: str = "") -> None:
        self.penalties.append(Signal(weight=weight, reason=reason, kind=kind))

    @property
    def evidence_kinds(self) -> set[str]:
        return {signal.kind for signal in self.signals if signal.kind}

    def to_dict(self) -> dict[str, object]:
        return {
            "asset_type": self.asset_type,
            "canonical_value": self.canonical_value,
            "signals": [signal.to_dict() for signal in self.signals],
            "penalties": [penalty.to_dict() for penalty in self.penalties],
        }


@dataclass(frozen=True)
class ScoreResult:
    """The score and the audit trail that produced it."""

    score: int
    band: str
    floor_signal: Signal | None
    corroboration_bonus: int
    penalty_total: int
    audit: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "score": self.score,
            "band": self.band,
            "floor_signal": self.floor_signal.to_dict() if self.floor_signal else None,
            "corroboration_bonus": self.corroboration_bonus,
            "penalty_total": self.penalty_total,
            "audit": list(self.audit),
        }


def band_for(score: int) -> str:
    """The report's name for a score's range."""
    if score >= 90:
        return BAND_CORE
    if score >= 70:
        return BAND_HIGH
    if score >= 40:
        return BAND_MEDIUM
    return BAND_LOW


def score(asset: ScoredAsset) -> ScoreResult:
    """Score one asset, with a line-by-line audit of every point.

    Rules:

    * no evidence → score 0, band ``low`` — an asset without provenance has no
      place in a triage queue;
    * the strongest single signal is the **floor**;
    * every *distinct additional* evidence kind adds 10% of its weight — the
      same kind repeating adds nothing (echo, not corroboration);
    * penalties always subtract, and a penalised asset can go to 0 but never
      negative (a dead host is not less than no host for reporting purposes).
    """
    audit: list[str] = []
    if not asset.signals:
        return ScoreResult(
            score=0,
            band=band_for(0),
            floor_signal=None,
            corroboration_bonus=0,
            penalty_total=0,
            audit=["no signals - score 0 by definition"],
        )

    floor = max(asset.signals, key=lambda signal: signal.weight)
    audit.append(
        f"floor: {floor.weight} ({floor.reason})" if floor.kind else f"floor: {floor.weight}"
    )

    # The floor's own kind is already counted: it *is* the claim.  Seeding the
    # set with it is what makes "the same kind repeating adds nothing" true when
    # the repeat happens to be the strongest signal (two artifacts of one kind
    # at the top weight would otherwise buy themselves a bonus).
    seen_kinds: set[str] = {floor.kind} if floor.kind else set()
    bonus = 0
    for signal in sorted(asset.signals, key=lambda s: s.weight, reverse=True):
        if signal is floor:
            continue
        kind = signal.kind or f"anon:{id(signal)}"
        if kind in seen_kinds:
            audit.append(f"echo ignored: {signal.weight} ({signal.reason})")
            continue
        seen_kinds.add(kind)
        contribution = round(signal.weight * corroboration_factor(signal.weight))
        bonus += contribution
        audit.append(f"corroboration +{contribution}: {signal.reason}")

    penalty_total = sum(penalty.weight for penalty in asset.penalties)
    for penalty in asset.penalties:
        audit.append(f"penalty {penalty.weight}: {penalty.reason}")

    raw = floor.weight + bonus + penalty_total
    final = max(0, min(100, raw))
    if raw != final:
        audit.append(f"clamped {raw} -> {final} (scores live in [0, 100])")
    audit.append(f"total: {final} ({band_for(final)})")

    return ScoreResult(
        score=final,
        band=band_for(final),
        floor_signal=floor,
        corroboration_bonus=bonus,
        penalty_total=penalty_total,
        audit=audit,
    )


def score_many(assets: list[ScoredAsset]) -> list[tuple[ScoredAsset, ScoreResult]]:
    """Score a batch, sorted best-first — the triage queue's ordering."""
    pairs = [(asset, score(asset)) for asset in assets]
    pairs.sort(key=lambda pair: pair[1].score, reverse=True)
    return pairs


# --------------------------------------------------------------------------- #
# Convenience builders for the evidence the pipelines actually emit
# --------------------------------------------------------------------------- #


def signal_for_source(source: str) -> Signal:
    """Map a pipeline's source name to its §4 weight.

    Callers pass the source string their provenance already carries; unknown
    sources default to the weakest tier rather than inventing confidence.
    """
    mapping: dict[str, int] = {
        # hard
        "scope-declared": W_AUTHENTICATED_SOURCE,
        "rdap": W_ASN_CIDR_OWNERSHIP,
        "ripestat": W_ASN_CIDR_OWNERSHIP,
        # strong
        "active-resolve": W_ACTIVE_DNS_RESOLUTION,
        "puredns": W_ACTIVE_DNS_RESOLUTION,
        "dnsx": W_ACTIVE_DNS_RESOLUTION,
        "httpx": W_SERVICE_RESPONSE,
        "naabu": W_SERVICE_RESPONSE,
        "nmap": W_SERVICE_RESPONSE,
        # strong — our own live confirmation of the asset itself
        "validate": W_LIVE_CONFIRMATION,
        "url-validated-live": W_LIVE_CONFIRMATION,
        "active-url-validation": W_LIVE_CONFIRMATION,
        # medium
        "crtsh": W_CRT_LOG,
        "certspotter": W_CRT_LOG,
        "internetdb": W_THIRD_PARTY_DATASET,
        "wayback": W_ARCHIVE_MENTION,
        "commoncrawl": W_ARCHIVE_MENTION,
        "urlscan": W_ARCHIVE_MENTION,
        "gau": W_ARCHIVE_MENTION,
        "amass": W_PASSIVE_DNS,
        "subfinder": W_PASSIVE_DNS,
        "assetfinder": W_PASSIVE_DNS,
        "findomain": W_PASSIVE_DNS,
        "chaos": W_PASSIVE_DNS,
        # weak
        "dnsgen": W_PERMUTATION_ONLY,
        "wordlist": W_WORDLIST_DERIVATION,
    }
    weight = mapping.get(source)
    if weight is None:
        return Signal(
            weight=UNKNOWN_SOURCE_WEIGHT,
            reason=f"unknown source, weakest tier: {source}",
            kind=f"source:{source}",
        )
    return Signal(weight=weight, reason=f"source: {source}", kind=f"source:{source}")


def penalty_for_takedown() -> Signal:
    return Signal(weight=P_TAKEDOWN_NOTICE, reason="takedown notice", kind="takedown")


def penalty_for_wildcard() -> Signal:
    return Signal(weight=P_WILDCARD_MATCH, reason="wildcard match", kind="wildcard")


def penalty_for_dead_host(detail: str = "a live re-check did not find it serving") -> Signal:
    """The measurement penalty: someone looked, and it was not there.

    *detail* is the caller's own words for *how* that was established (a 404 from
    a URL validation, an NXDOMAIN from a DNS re-check), so the audit line states
    the evidence rather than a mechanism the caller may not have used.
    """
    return Signal(weight=P_DEAD_HOST, reason=f"dead host ({detail})", kind="dead")


def penalty_for_shared_infra() -> Signal:
    return Signal(
        weight=P_SHARED_INFRASTRUCTURE,
        reason="shared infrastructure (CDN/cloud edge)",
        kind="shared",
    )
