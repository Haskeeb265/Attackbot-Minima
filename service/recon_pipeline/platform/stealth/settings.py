"""Tunable settings for the stealth layer, read once from the environment.

The stealth layer sits *below* the asset pipelines so every active stage shares
one implementation of traffic shaping, pacing and quarantine.  It therefore
cannot import a stage's settings module; it owns its own ``STEALTH_*`` knobs and
stages pass explicit values in when they want something different.

Environment overrides
---------------------
========================================== ==========================================
``STEALTH_IDENTITY``                       pin one browser profile by name
``STEALTH_IDENTITY_SALT``                  seed for stable per-host profile choice
``STEALTH_HOST_QPS``                       sustained requests/second per host (2)
``STEALTH_HOST_BURST``                     per-host burst allowance (4)
``STEALTH_JITTER``                         timing jitter as a fraction, 0-1 (0.35)
``STEALTH_BACKOFF_BASE``                   first backoff delay in seconds (1.0)
``STEALTH_BACKOFF_MAX``                    backoff ceiling in seconds (60)
``STEALTH_MAX_RETRIES``                    retries per request (2)
``STEALTH_TLS_IMPERSONATE``                ``httpx -tlsi`` profile (derived from identity)
``STEALTH_DNS_NAMES_PER_RESOLVER_HOUR``    per-resolver unique-name budget (60)
``STEALTH_DNS_QPS``                        total queries/second across the pool (100)
``STEALTH_DNS_BATCH_SIZE``                 names per resolver window (500)
``STEALTH_DNS_BATCH_SPACING``              jittered seconds between batches (20)
``STEALTH_DNS_SHUFFLE``                    ``0`` keeps candidate order, else shuffle
``STEALTH_DNS_SEED``                       seed for the shuffle (target-derived)
``STEALTH_QUARANTINE_FILE``                quarantine store path (``None`` = memory only)
``STEALTH_QUARANTINE_TTL``                 seconds a quarantined scope stays out (3600)
``STEALTH_QUARANTINE_FAILURES``            failures before a scope is quarantined (3)
``STEALTH_PASSIVE_ONLY``                   ``1`` forces the whole run passive-only
========================================== ==========================================

The defaults are not arbitrary; they are set *below* published detection
thresholds rather than at the fastest setting that still works.  See
``service/recon_pipeline/platform/stealth/README.md`` for the sources and the measured
basis of each number.
"""

from __future__ import annotations

import os
from pathlib import Path

def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


# --------------------------------------------------------------------------- #
# Identity
# --------------------------------------------------------------------------- #

#: Pin a single browser profile (empty = pick per host from the pool).
IDENTITY = os.getenv("STEALTH_IDENTITY", "").strip()

#: Stable-but-not-guessable seed for per-host profile selection.  Empty means
#: derive the seed from the target so a run is reproducible from the CLI alone.
IDENTITY_SALT = os.getenv("STEALTH_IDENTITY_SALT", "").strip()


# --------------------------------------------------------------------------- #
# Pacing
# --------------------------------------------------------------------------- #

#: Sustained requests per second against a single host.  A human browsing a site
#: issues a handful of requests per page load, not hundreds per second; the
#: ceiling here is deliberately far below httpx's own default of 150/s.
HOST_QPS = _env_float("STEALTH_HOST_QPS", 2.0)

#: Burst allowance, so a page's subresources do not each cost a full interval.
HOST_BURST = _env_int("STEALTH_HOST_BURST", 4)

#: Random proportion of each interval added as timing jitter.  Perfectly even
#: spacing is itself a machine signature, so delays are spread rather than fixed.
JITTER = _env_float("STEALTH_JITTER", 0.35)

BACKOFF_BASE = _env_float("STEALTH_BACKOFF_BASE", 1.0)
BACKOFF_MAX = _env_float("STEALTH_BACKOFF_MAX", 60.0)
MAX_RETRIES = _env_int("STEALTH_MAX_RETRIES", 2)


# --------------------------------------------------------------------------- #
# DNS shaping
# --------------------------------------------------------------------------- #

#: Unique names sent to any *single* recursive resolver within an hour.
#:
#: Published detection analytics flag subdomain brute force at more than ~75
#: unique names per base domain per hour from one client, compounded by a high
#: NXDOMAIN share (which a wordlist pass unavoidably has).  Staying under that
#: volume per resolver is the one lever we control without weakening the recon
#: itself, so the budget is enforced by rotation instead of by query rate.
DNS_NAMES_PER_RESOLVER_HOUR = _env_int("STEALTH_DNS_NAMES_PER_RESOLVER_HOUR", 60)

#: Total query rate the resolver tools are allowed, across the whole pool
#: (0 = unlimited).  This bounds the *burst* the target's nameservers see; the
#: per-resolver unique-name count is bounded separately, by rotation.
DNS_QPS = _env_float("STEALTH_DNS_QPS", 100.0)

#: Names per batch.  Each batch is a separate invocation of the resolver tool,
#: so this is also the granularity at which wall-clock time is traded for a
#: smaller per-resolver footprint.  Measured cost on a 1,378-name run: three
#: batches added ~48 seconds of deliberate waiting, and the run took 193s where
#: an unbatched run took ~64s.
DNS_BATCH_SIZE = _env_int("STEALTH_DNS_BATCH_SIZE", 500)

#: Jittered pause between batches.  This does not change the per-resolver name
#: *count* (batching does that); it spreads the payload rate out so the target's
#: authoritative nameservers do not see one blast.
DNS_BATCH_SPACING = _env_float("STEALTH_DNS_BATCH_SPACING", 20.0)

#: Candidate order is shuffled before resolution by default.  Wordlist order is
#: a fingerprint in itself (it is stable across targets and reveals the list),
#: and shuffling also spreads any given file's names across resolvers.
DNS_SHUFFLE = _env_flag("STEALTH_DNS_SHUFFLE", True)

#: Seed for the shuffle; empty derives one from the target (reproducible, but
#: not a fixed constant an observer can precompute).
DNS_SEED = os.getenv("STEALTH_DNS_SEED", "").strip()


# --------------------------------------------------------------------------- #
# Quarantine
# --------------------------------------------------------------------------- #

#: Where quarantine state persists between runs.  ``None`` keeps it in memory.
QUARANTINE_FILE: Path | None = (
    Path(os.getenv("STEALTH_QUARANTINE_FILE")).expanduser()
    if os.getenv("STEALTH_QUARANTINE_FILE", "").strip()
    else None
)

QUARANTINE_TTL = _env_int("STEALTH_QUARANTINE_TTL", 3600)
QUARANTINE_FAILURES = _env_int("STEALTH_QUARANTINE_FAILURES", 3)

#: Hard operator override: refuse every active technique, regardless of state.
PASSIVE_ONLY = _env_flag("STEALTH_PASSIVE_ONLY", False)
