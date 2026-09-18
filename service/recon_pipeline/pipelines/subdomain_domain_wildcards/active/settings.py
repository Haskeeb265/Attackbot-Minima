"""Tunable settings and paths for the active (DNS resolution + bruteforce) stage.

Kept in the same shape as :mod:`..passive.settings` so the three stages of
``subdomain_domain_wildcards`` are configured the same way, and so the wildcard
layer can be reused rather than re-tuned:

* every path is derived from ``__file__`` exactly once, here;
* every knob reads an ``ACTIVE_*`` environment variable with a documented
  default, so a run is reproducible from the CLI alone.

The wildcard knobs are **imported from the passive stage on purpose** - the two
stages must agree on what a wildcard is, otherwise the active stage would
"rediscover" every wildcard the passive stage already recorded (or worse,
disagree about which names it explains).

Environment overrides
---------------------
====================================== ==========================================
``ACTIVE_TIMEOUT``                     seconds one tool may run (default 900)
``ACTIVE_BRUTEFORCE``                  ``0`` disables wordlist bruteforce
``ACTIVE_RECURSION``                   ``0`` disables recursive bruteforce
``ACTIVE_RECURSION_MAX_DEPTH``         how many label levels deep to recurse (2)
``ACTIVE_RECURSION_MAX_PARENTS``       ceiling on recursive brute-force runs (25)
``ACTIVE_RECURSION_WORD_LIMIT``        words used per recursive run (250)
``ACTIVE_AXFR``                        ``0`` disables zone-transfer attempts
``ACTIVE_AXFR_MAX_NAMESERVERS``        nameservers tried per zone (6)
``ACTIVE_HTTP``                        ``1`` enables the opt-in HTTP probe
``ACTIVE_HTTP_RATE_LIMIT``             requests/second for the HTTP probe (2)
``ACTIVE_HTTP_THREADS``                concurrency for the HTTP probe (5)
``ACTIVE_STEALTH``                     ``0`` disables the stealth layer (1)
``ACTIVE_HTTP_IMPERSONATE``            ``0`` stops TLS impersonation (1)
``ACTIVE_SHUFFLE_CANDIDATES``          ``0`` keeps candidate order (1)
``ACTIVE_AXFR_SPACING``                seconds between AXFR attempts (5)
``ACTIVE_RESOLVER_QUERY_TIMEOUT``      seconds per resolver validation query (3)
``ACTIVE_RESOLVER_WORKERS``            parallel resolver probes (16)
``ACTIVE_RESOLVER_MIN_VALID``          abort threshold (3 valid resolvers)
``ACTIVE_PUREDNS_WILDCARD_TESTS``      puredns ``--wildcard-tests`` (3)
``ACTIVE_PUREDNS_RATE_LIMIT``          puredns public-resolver qps (0 = unlimited)
``SUBDW_IMAGE``                        all-in-one tool image tag
====================================== ==========================================
"""

from __future__ import annotations

import os
from pathlib import Path

from ....platform.stealth import settings as stealth_settings
from service.recon_pipeline.platform.common.env import env_flag, env_int

# Reused verbatim: the active stage must apply the *same* wildcard definition the
# passive stage used, so imported rather than re-implemented.
from ..passive.settings import (  # noqa: F401  (re-exported for the stage)
    DNS_QUERY_TIMEOUT,
    PASSIVE_DIR,
    WILDCARD_ENABLED,
    WILDCARD_MAX_QUERIES,
    WILDCARD_MAX_SECONDS,
    WILDCARD_MIN_CHILDREN,
    WILDCARD_SAMPLES,
)

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #

ACTIVE_DIR = Path(__file__).resolve().parent

#: Raw tool output, derived lists, validated resolvers and the run report.
OUTPUT_DIR = ACTIVE_DIR / "output"

#: Bundled wordlists (``generic.txt`` is the built-in default).
WORDLIST_DIR = ACTIVE_DIR / "wordlists"

#: Curated resolver seeds — candidates, not truth: every entry is probed at run
#: time because the well-known public-resolver lists rot fast (see the README).
RESOLVER_DIR = ACTIVE_DIR / "resolvers"

#: The built-in generic wordlist.
GENERIC_WORDLIST = WORDLIST_DIR / "generic.txt"

#: All public resolver candidates probed for the working pool.
PUBLIC_RESOLVERS_FILE = RESOLVER_DIR / "public.txt"

#: The high-trust subset used for puredns' poisoning validation.
TRUSTED_RESOLVERS_FILE = RESOLVER_DIR / "trusted.txt"

#: The passive stage's normalized output is this stage's candidate source.
PASSIVE_SUBDOMAINS_FILE = PASSIVE_DIR / "output" / "subdomains.txt"

#: Container mount point for everything the tools read and write.
CONTAINER_WORKDIR = "/work"


# --------------------------------------------------------------------------- #
# Run limits
# --------------------------------------------------------------------------- #

#: Wall-clock cap for one tool invocation (Docker container).
DEFAULT_SOURCE_TIMEOUT = env_int("ACTIVE_TIMEOUT", 900)

#: Wordlist bruteforce is on by default — it is the only technique that finds
#: names which were never published anywhere (see the stage README).
BRUTEFORCE_ENABLED = env_flag("ACTIVE_BRUTEFORCE", True)

#: Recursive bruteforce: brute under hosts that already resolved, to catch
#: ``api.dev.example.com`` when only ``dev.example.com`` is known.
RECURSION_ENABLED = env_flag("ACTIVE_RECURSION", True)

#: Label levels below the apex that recursion may descend to.
RECURSION_MAX_DEPTH = env_int("ACTIVE_RECURSION_MAX_DEPTH", 2)

#: Hard ceiling on recursive brute-force passes, so a wildcard-ish target
#: cannot turn recursion into an unbounded sweep.
RECURSION_MAX_PARENTS = env_int("ACTIVE_RECURSION_MAX_PARENTS", 25)

#: Words used per recursive pass (a shortlist of the main wordlist).
RECURSION_WORD_LIMIT = env_int("ACTIVE_RECURSION_WORD_LIMIT", 250)

#: Zone transfer attempts cost one query per nameserver and occasionally hand
#: over an entire zone, so they are cheap enough to leave on.
AXFR_ENABLED = env_flag("ACTIVE_AXFR", True)

#: Nameservers tried per zone (a zone usually has 2-4).
AXFR_MAX_NAMESERVERS = env_int("ACTIVE_AXFR_MAX_NAMESERVERS", 6)

#: Seconds allowed for one AXFR attempt — transfers can trickle.
AXFR_QUERY_TIMEOUT = env_int("ACTIVE_AXFR_QUERY_TIMEOUT", 30)

#: Resolver validation: a resolver must answer a name that exists and must
#: *not* answer a name that cannot (``<random>.invalid``).  Timeout per query.
RESOLVER_QUERY_TIMEOUT = float(env_int("ACTIVE_RESOLVER_QUERY_TIMEOUT", 3))

#: Resolvers probed in parallel.
RESOLVER_WORKERS = env_int("ACTIVE_RESOLVER_WORKERS", 16)

#: Below this many working resolvers the stage aborts instead of producing a
#: half-resolved candidate list that looks complete.
RESOLVER_MIN_VALID = env_int("ACTIVE_RESOLVER_MIN_VALID", 3)

#: puredns' own wildcard heuristics.  ``--wildcard-tests`` is the number of
#: random probes used to detect load-balancing; 3 is puredns' default.
PUREDNS_WILDCARD_TESTS = env_int("ACTIVE_PUREDNS_WILDCARD_TESTS", 3)

#: Queries/second against public resolvers (0 = unlimited).  Left unlimited by
#: default to keep bruteforce wall-clock reasonable on large wordlists.
PUREDNS_RATE_LIMIT = env_int("ACTIVE_PUREDNS_RATE_LIMIT", 0)

#: HTTP probing is off by default: it is the one step that sends application
#: traffic to the target's hosts rather than DNS queries. See the README.
HTTP_ENABLED = env_flag("ACTIVE_HTTP", False)

#: Requests/second for the whole HTTP probe.  The default follows the shared
#: stealth pacing (2/s) rather than httpx's own default of 150/s: a person
#: browsing a site issues a handful of requests per page load, and a burst rate
#: is one of the few signals a target can measure without any fingerprinting.
HTTP_RATE_LIMIT = env_int("ACTIVE_HTTP_RATE_LIMIT", max(1, int(stealth_settings.HOST_QPS)))

#: Concurrency.  Kept low on purpose: the rate limit is what matters, and a deep
#: queue of parallel connections looks nothing like a browser.
HTTP_THREADS = env_int("ACTIVE_HTTP_THREADS", 5)

# --------------------------------------------------------------------------- #
# Stealth (spec §5.1) — see ``service/recon_pipeline/platform/stealth/``
# --------------------------------------------------------------------------- #

#: The stealth layer (identity, pacing, detection, quarantine, DNS budget) is on
#: by default; ``0`` falls back to the previous unshaped behaviour.
STEALTH_ENABLED = env_flag("ACTIVE_STEALTH", True)

#: Ask the HTTP probe to impersonate this identity's TLS ClientHello
#: (``httpx -tlsi``).  Verified to produce the real Chrome JA4.
HTTP_IMPERSONATE = env_flag("ACTIVE_HTTP_IMPERSONATE", True)

#: Shuffle candidate order before resolving, so the order does not advertise the
#: wordlist/source layout and load spreads across resolvers.
SHUFFLE_CANDIDATES = env_flag("ACTIVE_SHUFFLE_CANDIDATES", True)

#: Seconds between zone-transfer attempts.  AXFR is one query per nameserver, so
#: a handful of nameservers fired back-to-back look like a scanner sweep.
AXFR_SPACING = float(env_int("ACTIVE_AXFR_SPACING", 5))

#: Where quarantine state persists, so a cooldown triggered in one stage (or run)
#: is respected by the next.  ``STEALTH_QUARANTINE_FILE`` overrides this.
QUARANTINE_FILE = stealth_settings.QUARANTINE_FILE or (OUTPUT_DIR / "quarantine.json")

#: Hard operator override (shared with the stealth layer).
PASSIVE_ONLY = stealth_settings.PASSIVE_ONLY

#: The all-in-one image built from the stage's Dockerfile.  Unlike the passive
#: stage (which pulls upstream images), the active tools are only co-packaged
#: there — massdns, puredns and dnsgen share one image.
IMAGE = os.getenv("SUBDW_IMAGE", "subdomain_domain_wildcards_image")
