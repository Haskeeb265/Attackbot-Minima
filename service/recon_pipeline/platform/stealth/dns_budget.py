"""DNS volume budgeting: keep the *count* of names per resolver under detection.

The quantified constraint
-------------------------
Published detection analytics for subdomain brute force trigger on volume, not
on fingerprints: one client resolving more than roughly 75 unique names of the
same base domain within an hour, *compounded* by a high NXDOMAIN share — which a
wordlist pass unavoidably produces, because most candidate labels do not exist.
(The reference rule for a Windows DNS sensor flags ``SubdomainCount > 75`` with
``NxdomainRate > 40``; see the stealth README for the citation.)

Recursive resolvers are therefore the sensitive resource, and the arithmetic is
simple: a wordlist of ``N`` labels fanned across ``R`` validated resolvers puts
``N / R`` unique names on each one.  That ratio — not the query rate — is what
decides whether a run looks like enumeration:

* 755 labels over 38 resolvers ≈ 20 names each: comfortably quiet;
* 8,000 labels over the same 38 resolvers ≈ 210 names each: clearly not, and
  running it *faster* changes nothing, because the count per resolver is fixed
  by the fan-out.  Only a wider pool, a smaller wordlist, or spreading the work
  across separate hourly windows fixes it.

So this module plans, before any query is sent: how many names each resolver
will see, whether that fits the budget, and what it would take to fit.  Two more
things happen here and nowhere else:

* **Order is shuffled.**  A wordlist's order is a fingerprint in itself: it is
  stable across targets and reveals which list is in use.  Shuffling is keyed
  on a seed (derived from the target when none is set), so it is reproducible
  for the operator and unguessable to everyone else — and it also spreads a
  given list's names across the resolver pool instead of sending an alphabetical
  run to whichever resolver happens to be first.
* **Resolver usage rotates per batch.**  Each batch draws a rotated window of
  the pool rather than always the same head of the list, so no small subset
  accumulates the whole run's load.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field

from .pacing import jittered


@dataclass(frozen=True)
class DnsBudget:
    """Volume and burst limits for DNS work."""

    #: Unique names any single resolver may see inside one hourly window.
    names_per_resolver_hour: int = 60
    #: Total query rate across the whole pool (0 = unlimited).
    qps: float = 100.0
    #: Names per batch sent to one resolver window.
    batch_size: int = 500
    #: Seconds between batches, jittered, so a large list is not one burst.
    batch_spacing: float = 20.0
    jitter: float = 0.35
    shuffle: bool = True
    seed: str = ""
    #: When true, labels beyond the budget are dropped instead of merely reported.
    strict: bool = False
    #: Reservoir of labels an operator is willing to skip if the pool is too small.
    min_resolvers: int = 4

    def __post_init__(self) -> None:
        if self.names_per_resolver_hour <= 0:
            raise ValueError("names_per_resolver_hour must be positive")
        if self.batch_size <= 0:
            raise ValueError("batch_size must be positive")


@dataclass
class Batch:
    """One resolver window's worth of names."""

    index: int
    labels: tuple[str, ...]
    resolvers: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "labels": len(self.labels),
            "resolvers": list(self.resolvers),
        }


@dataclass
class DnsPlan:
    """What the runner is about to send, and whether it fits the budget."""

    labels: tuple[str, ...] = ()
    batches: tuple[Batch, ...] = ()
    per_resolver: dict[str, int] = field(default_factory=dict)
    within_budget: bool = True
    hours_needed: int = 1
    required_resolvers: int = 0
    dropped: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    seed: str = ""

    @property
    def max_per_resolver(self) -> int:
        return max(self.per_resolver.values(), default=0)

    @property
    def resolver_count(self) -> int:
        return len(self.per_resolver)

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "names": len(self.labels),
            "resolvers": self.resolver_count,
            "per_resolver_max": self.max_per_resolver,
            "within_budget": self.within_budget,
            "hours_needed": self.hours_needed,
            "required_resolvers": self.required_resolvers,
            "batches": len(self.batches),
            "seed": self.seed,
        }
        if self.dropped:
            payload["dropped"] = len(self.dropped)
        if self.notes:
            payload["notes"] = list(self.notes)
        return payload

    def runs(self, label_limit: int) -> tuple[tuple[str, ...], ...]:
        """Batches as plain label tuples, for callers that just want the chunks."""
        return tuple(batch.labels for batch in self.batches[: max(1, label_limit)])


def shuffle_names(names: list[str], *, seed: str) -> list[str]:
    """Deterministic shuffle keyed on *seed*.

    Keyed on a digest rather than :mod:`random` so the order is identical across
    processes and Python versions — a re-run resolves the same names in the same
    order, which is what makes the plan reproducible and the report honest.
    """
    return sorted(names, key=lambda name: hashlib.blake2b(f"{seed}|{name}".encode(), digest_size=8).digest())


def rotate(resolvers: list[str], *, seed: str, index: int) -> list[str]:
    """A rotated window of the pool, so each batch starts somewhere else."""
    if not resolvers:
        return []
    offset = int.from_bytes(hashlib.blake2b(f"{seed}|{index}".encode(), digest_size=4).digest(), "big")
    start = offset % len(resolvers)
    return resolvers[start:] + resolvers[:start]


def plan(
    labels: list[str],
    resolvers: list[str],
    *,
    budget: DnsBudget | None = None,
    seed: str = "",
) -> DnsPlan:
    """Work out the batch/rotation plan and whether it fits the volume budget.

    Never silently weakens coverage: when the pool is too small to keep every
    name under budget, the plan says so (``within_budget`` false, with how many
    hourly windows it would need and how many resolvers would make it fit) and,
    only in ``strict`` mode, drops the excess.
    """
    budget = budget or DnsBudget()
    pool = list(dict.fromkeys(resolvers))
    names = list(dict.fromkeys(labels))
    resolved_seed = seed or budget.seed or "dnsseed"

    if not names:
        return DnsPlan(seed=resolved_seed)
    if not pool:
        return DnsPlan(
            labels=tuple(names),
            within_budget=False,
            notes=("no resolvers available",),
            seed=resolved_seed,
        )

    ordered = shuffle_names(names, seed=resolved_seed) if budget.shuffle else names

    # How many names can one window carry while respecting the per-resolver cap?
    names_per_window = max(len(pool), budget.names_per_resolver_hour * len(pool))
    window_size = max(1, min(budget.batch_size, names_per_window))
    dropped: tuple[str, ...] = ()
    if budget.strict and len(ordered) > names_per_window:
        dropped = tuple(ordered[names_per_window:])
        ordered = ordered[:names_per_window]

    batches: list[Batch] = []
    per_resolver: dict[str, int] = {}
    for index, start in enumerate(range(0, len(ordered), window_size)):
        chunk = ordered[start : start + window_size]
        window = rotate(pool, seed=resolved_seed, index=index)
        # A window only needs as many resolvers as the chunk's cap requires,
        # but it always draws the *rotated* head so load moves around the pool.
        needed = max(budget.min_resolvers, math.ceil(len(chunk) / budget.names_per_resolver_hour))
        window = window[: max(1, min(needed, len(window)))]
        batches.append(Batch(index=index, labels=tuple(chunk), resolvers=tuple(window)))
        for offset, label in enumerate(chunk):
            resolver = window[offset % len(window)]
            per_resolver[resolver] = per_resolver.get(resolver, 0) + 1

    max_load = max(per_resolver.values(), default=0)
    required = math.ceil(len(names) / budget.names_per_resolver_hour)
    hours = max(1, math.ceil(max_load / budget.names_per_resolver_hour))
    notes: list[str] = []
    if hours > 1:
        notes.append(
            f"{len(names)} names over {len(pool)} resolver(s) puts up to {max_load} names on one "
            f"resolver: spread across {hours} hourly window(s), or widen the pool to "
            f"{required} resolvers"
        )
    if dropped:
        notes.append(f"strict budget dropped {len(dropped)} name(s) that did not fit")

    return DnsPlan(
        labels=tuple(ordered),
        batches=tuple(batches),
        per_resolver=per_resolver,
        within_budget=max_load <= budget.names_per_resolver_hour,
        hours_needed=hours,
        required_resolvers=required,
        dropped=dropped,
        notes=tuple(notes),
        seed=resolved_seed,
    )


def batch_delay(index: int, *, budget: DnsBudget | None = None, random_value: float = 0.5) -> float:
    """Jittered pause before batch *index* (0 for the first batch)."""
    budget = budget or DnsBudget()
    if index <= 0 or budget.batch_spacing <= 0:
        return 0.0
    return jittered(budget.batch_spacing, budget.jitter, random_value)


def rate_limit_arg(*, budget: DnsBudget | None = None, resolver_count: int = 0) -> int:
    """``--rate-limit`` value for the resolver tools (0 means unlimited).

    Capped by the per-resolver volume budget so a burst cannot outrun the window
    the plan was built around; the *count* limit is enforced by rotation.
    """
    budget = budget or DnsBudget()
    if budget.qps <= 0:
        return 0
    qps = budget.qps
    if resolver_count > 0:
        qps = min(qps, budget.names_per_resolver_hour * resolver_count / 3600.0 * 60.0)
    return max(1, int(qps))
