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

The engine is deliberately dumb about *what* an asset is: it scores
:class:`ScoredAsset` records built by callers (the graph writers, the
pipelines' report paths), keeping this module pure and independently
testable.
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

#: Corroboration: each additional distinct signal adds 10% of its weight.
CORROBORATION_FACTOR = 0.1

#: Score bands — how the report talks about a score.
BAND_CORE = "core"                # 90+
BAND_HIGH = "high"                # 70–89
BAND_MEDIUM = "medium"            # 40–69
BAND_LOW = "low"                  # < 40


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
        contribution = round(signal.weight * CORROBORATION_FACTOR)
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


def penalty_for_dead_host() -> Signal:
    return Signal(weight=P_DEAD_HOST, reason="dead host (NXDOMAIN on re-check)", kind="dead")


def penalty_for_shared_infra() -> Signal:
    return Signal(
        weight=P_SHARED_INFRASTRUCTURE,
        reason="shared infrastructure (CDN/cloud edge)",
        kind="shared",
    )
