"""
DNS wildcard detection and wildcard-flood suppression.

Why this module exists
----------------------
Passive enumeration sources happily return names that only resolve because the
target publishes a wildcard DNS record (``*.example.com``).  Those names are not
real assets — they are the same answer served for every label, and left
unfiltered they flood the graph with thousands of false positives:

    recon.md §2 — "Robust wildcard detection (consistent NXDOMAIN / response
    fingerprinting) is mandatory to avoid false-positive floods."

The pipeline therefore probes suspicious parents with random labels and, when a
parent answers identically for labels that cannot exist, marks it as a wildcard
and suppresses the names that are explained by it.

Design notes
------------
* **Sampling, not exhaustion.** A parent is only probed when it has at least
  ``min_children`` discovered children (``settings.WILDCARD_MIN_CHILDREN``) plus
  the apex itself.  Random labels make a false positive vanishingly unlikely;
  the number of queries stays bounded by the number of high-fan-out parents.
* **Conservative suppression.** A name is suppressed only when its *immediate*
  parent is a confirmed wildcard, it carries no independent evidence (fewer than
  ``corroboration_threshold`` distinct sources), and it resolves to exactly the
  wildcard's answer set.  Anything unresolved, contested, or corroborated is
  kept, so nothing real is silently dropped — and every suppressed name is also
  written to ``wildcard_suppressed.txt`` for review.
* **Injectable resolver, graceful degradation.** All DNS access goes through a
  ``resolve(name) -> frozenset[str]`` callable.  Tests inject a fake; production
  uses the dnspython-backed default.  If dnspython is missing or the network is
  unreachable the default returns empty answers, no wildcard is detected, and no
  name is suppressed — the stage degrades instead of failing.
"""

from __future__ import annotations

import logging
import random
import string
import time
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field

from .normalize import parent_of
from .settings import (
    DNS_QUERY_TIMEOUT,
    WILDCARD_MAX_QUERIES,
    WILDCARD_MAX_SECONDS,
    WILDCARD_MIN_CHILDREN,
    WILDCARD_SAMPLES,
)

log = logging.getLogger("passive.wildcard")

#: ``name -> set of answer strings`` (A/AAAA addresses, CNAME targets, ...).
Resolver = Callable[[str], frozenset[str]]

_dnspython_warned = False


# --------------------------------------------------------------------------- #
# Default resolver
# --------------------------------------------------------------------------- #


def dnspython_resolver(name: str, *, timeout: float = DNS_QUERY_TIMEOUT) -> frozenset[str]:
    """Resolve *name* to its A/AAAA addresses and CNAME targets via dnspython.

    Every failure mode (missing dependency, NXDOMAIN, timeout, SERVFAIL)
    degrades to an empty answer set — callers treat "no answers" as "not
    evidence of a wildcard", which is the safe direction.
    """
    global _dnspython_warned

    try:
        import dns.exception
        import dns.resolver
    except ImportError:  # pragma: no cover - dependency is declared
        if not _dnspython_warned:
            log.warning(
                "dnspython is not installed - wildcard detection is disabled "
                "(no names will be suppressed). Install it to enable probing."
            )
            _dnspython_warned = True
        return frozenset()

    answers: set[str] = set()
    for record_type in ("A", "AAAA", "CNAME"):
        try:
            response = dns.resolver.resolve(name, record_type, lifetime=timeout)
        except Exception:  # dns.exception.DNSException, OSError, ...
            continue
        for record in response:
            answers.add(str(record).rstrip(".").lower())
    return frozenset(answers)


class _CachingResolver:
    """Memoize resolver calls and enforce the query + time budget.

    This is the single choke point for DNS access, so both guards live here: a
    query cap (a pathological target cannot trigger an unbounded sweep) and a
    wall-clock deadline (a slow or blackholed resolver cannot stretch a bounded
    number of queries into hours).  Once either is hit, further lookups return
    "no answers" — the direction that suppresses nothing and detects nothing.
    """

    def __init__(
        self,
        resolve: Resolver,
        limit: int = WILDCARD_MAX_QUERIES,
        max_seconds: float = WILDCARD_MAX_SECONDS,
    ):
        self._resolve = resolve
        self._cache: dict[str, frozenset[str]] = {}
        self._limit = limit
        self._deadline = time.monotonic() + max_seconds if max_seconds else None
        self.queries = 0
        #: Set once the query cap or the deadline stopped further lookups.
        self.exhausted = False

    def __call__(self, name: str) -> frozenset[str]:
        if name not in self._cache:
            if self.queries >= self._limit:
                self.exhausted = True
                return frozenset()
            if self._deadline is not None and time.monotonic() >= self._deadline:
                self.exhausted = True
                return frozenset()
            self.queries += 1
            self._cache[name] = self._resolve(name)
        return self._cache[name]


# --------------------------------------------------------------------------- #
# Verdicts
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class WildcardVerdict:
    """Result of probing one candidate parent for a wildcard record."""

    parent: str
    is_wildcard: bool
    #: Answer set observed for each random sample (empty tuple = no answer).
    sampled: tuple[tuple[str, ...], ...] = ()

    @property
    def pattern(self) -> str:
        """The wildcard record this verdict describes, e.g. ``*.example.com``."""
        return f"*.{self.parent}"

    @property
    def answers(self) -> frozenset[str]:
        """The shared answer set, or empty for a negative verdict."""
        return frozenset(self.sampled[0]) if self.is_wildcard else frozenset()


def _random_label(rng: random.Random, length: int = 16) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(rng.choice(alphabet) for _ in range(length))


def candidate_parents(
    names: Iterable[str],
    apex: str,
    *,
    min_children: int = WILDCARD_MIN_CHILDREN,
) -> list[str]:
    """Parents worth probing: the apex, plus any parent with enough children."""
    counts = Counter(parent for parent in (parent_of(n) for n in names) if parent)
    parents = [p for p, count in counts.items() if count >= min_children]
    if apex not in parents:
        parents.append(apex)
    return sorted(set(parents))


def detect_wildcards(
    apex: str,
    names: Iterable[str],
    *,
    resolver: Resolver | None = None,
    samples: int = WILDCARD_SAMPLES,
    min_children: int = WILDCARD_MIN_CHILDREN,
    seed: int = 0,
) -> list[WildcardVerdict]:
    """Probe candidate parents and return the confirmed wildcards.

    A parent is a wildcard when every randomly-named label under it resolves —
    and all of them resolve to the *same* answer set.  Random 16-character
    labels make an accidental hit effectively impossible.
    """
    apex = apex.lower().rstrip(".")
    names = list(names)
    if not names:
        return []

    resolve = _CachingResolver(resolver or dnspython_resolver)
    rng = random.Random(seed)
    confirmed: list[WildcardVerdict] = []

    for parent in candidate_parents(names, apex, min_children=min_children):
        sampled: list[tuple[str, ...]] = []
        for _ in range(samples):
            answer = resolve(f"{_random_label(rng)}.{parent}")
            sampled.append(tuple(sorted(answer)))

        # Confirmed only when every sample answered and they all agreed.
        first = sampled[0]
        is_wildcard = bool(first) and all(sample == first for sample in sampled)
        if is_wildcard:
            confirmed.append(
                WildcardVerdict(parent=parent, is_wildcard=True, sampled=tuple(sampled))
            )

    probed = len(candidate_parents(names, apex, min_children=min_children))
    if confirmed:
        log.info(
            "Wildcard DNS detected: %s (probed %d candidate parent(s), %d queries)",
            ", ".join(v.pattern for v in confirmed),
            probed,
            resolve.queries,
        )
    else:
        log.info(
            "No wildcard DNS detected (probed %d candidate parent(s), %d queries)",
            probed,
            resolve.queries,
        )
    if resolve.exhausted:
        log.warning(
            "wildcard probe budget exhausted after %d query(ies) - remaining "
            "parents were not probed; no verdict means nothing is suppressed",
            resolve.queries,
        )
    return confirmed


# --------------------------------------------------------------------------- #
# Suppression
# --------------------------------------------------------------------------- #


@dataclass
class WildcardFilterResult:
    """Outcome of removing wildcard-explained noise from the merged pool."""

    #: ``{name: sources}`` with wildcard noise removed.
    kept: dict[str, set[str]] = field(default_factory=dict)
    #: ``{name: wildcard pattern}`` for names suppressed as wildcard noise.
    suppressed: dict[str, str] = field(default_factory=dict)
    #: The verdicts that drove the decision.
    verdicts: list[WildcardVerdict] = field(default_factory=list)


def filter_wildcard_noise(
    observations: Mapping[str, set[str]],
    verdicts: Iterable[WildcardVerdict],
    *,
    resolver: Resolver | None = None,
    corroboration_threshold: int = 2,
) -> WildcardFilterResult:
    """Drop names that are merely the wildcard answering, keep everything else.

    A name is suppressed only when **all** of these hold:

    1. its immediate parent is a confirmed wildcard,
    2. it is reported by fewer than *corroboration_threshold* sources
       (single-source names are the ones a wildcard alone could have invented),
    3. it resolves, and its answers are a subset of the wildcard's answers —
       i.e. nothing distinguishes it from a random label.

    Unresolved names are kept (they are *not* wildcard answers), as are
    corroborated names and names outside any wildcard's immediate children.
    """
    wildcards = {v.parent: v for v in verdicts if v.is_wildcard}
    result = WildcardFilterResult(verdicts=sorted(wildcards.values(), key=lambda v: v.parent))

    if not wildcards:
        result.kept = {name: set(sources) for name, sources in observations.items()}
        return result

    resolve = _CachingResolver(resolver or dnspython_resolver)

    for name, sources in observations.items():
        parent = parent_of(name)
        verdict = wildcards.get(parent) if parent else None

        if verdict is None or len(sources) >= corroboration_threshold:
            result.kept[name] = set(sources)
            continue

        answers = resolve(name)
        if answers and answers <= verdict.answers:
            result.suppressed[name] = verdict.pattern
        else:
            result.kept[name] = set(sources)

    if result.suppressed:
        log.warning(
            "Suppressed %d name(s) explained by wildcard DNS (%s); see "
            "wildcard_suppressed.txt - names also seen by %d+ sources were kept",
            len(result.suppressed),
            ", ".join(sorted({p for p in result.suppressed.values()})),
            corroboration_threshold,
        )
    if resolve.exhausted:
        log.warning(
            "wildcard filter budget exhausted after %d query(ies) - names that "
            "could not be checked were kept (fail-open)",
            resolve.queries,
        )
    return result
