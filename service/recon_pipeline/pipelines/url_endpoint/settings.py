"""Tunable settings and paths for the URLs / endpoints pipeline.

Kept in the same shape as the two sibling stages, so the whole recon pipeline is
configured one way:

* every path is derived from ``__file__`` exactly once, here;
* every knob reads a ``URL_*`` environment variable with a documented default,
  so a run is reproducible from the CLI alone.

One thing is *imported* rather than re-implemented, deliberately:
:func:`env_int` / :func:`env_flag` from the sibling names stage — the
environment-parsing semantics (a typo falls back to the default; ``0`` /
``false`` / ``no`` / ``off`` mean off) must not drift between stages.

Environment overrides
---------------------
========================================== ==========================================
``URL_TIMEOUT``                            seconds one source may run (600)
``URL_WAYBACK_LIMIT``                      CDX rows requested (50000)
``URL_COMMONCRAWL_LIMIT``                  Common Crawl rows requested (10000)
``URL_COMMONCRAWL_INDEX``                  pin a CC index id (default: newest)
``URL_URLSCAN_LIMIT``                      urlscan search results requested (1000)
``URL_URLSCAN_KEY``                        optional urlscan API key (higher quota)
``URL_GAU_IMAGE``                          the bundled gau image
``URL_MAX_URLS``                           cap on the union (0 = no cap)
``URL_HTTP_MAX_BYTES``                     per-response read cap (64 MiB)
``URL_HTTP_RETRIES``                       transient retries per request (3)
``URL_VALIDATE``                           run the live validation stage (on)
``URL_VALIDATE_MAX_URLS``                  candidates validated per run (200)
``URL_VALIDATE_MAX_PER_HOST``             candidates validated per host (25)
``URL_VALIDATE_TTL``                       reuse window for a measurement, s (86400)
``URL_VALIDATE_RATE_LIMIT``                requests/second handed to httpx (5)
``URL_VALIDATE_THREADS``                   concurrent httpx workers (10)
``URL_HTTPX_IMAGE``                        image carrying httpx (port_service_host_image)
========================================== ==========================================
"""

from __future__ import annotations

import os
from pathlib import Path

from service.recon_pipeline.platform.common.env import env_flag, env_int

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #

URL_DIR = Path(__file__).resolve().parent

#: The passive stage's own directory and raw output (one file per source).
PASSIVE_DIR = URL_DIR / "passive"
PASSIVE_OUTPUT_DIR = PASSIVE_DIR / "output"

#: The pipeline's derived artifacts (endpoints, parameters, js, interesting).
OUTPUT_DIR = URL_DIR / "output"

#: Container mount point for the tools image (the URL sources are keyless
#: HTTP/Python, so this is only needed by the optional Docker source).
CONTAINER_WORKDIR = "/work"


# --------------------------------------------------------------------------- #
# Source limits
# --------------------------------------------------------------------------- #

#: Wall-clock cap for one source (HTTP harvest or Docker container).
DEFAULT_SOURCE_TIMEOUT = env_int("URL_TIMEOUT", 600)

#: Rows requested from the Wayback CDX API.  CDX is ordered by capture time, not
#: by path, so on a large target the tail of a huge limit is mostly the apex and
#: ``www`` — the sibling names stage's measured caveat.  Larger than a host-only
#: harvest needs, because here every distinct *path* is the point.
WAYBACK_LIMIT = env_int("URL_WAYBACK_LIMIT", 50_000)

#: Rows requested from the Common Crawl index.
COMMONCRAWL_LIMIT = env_int("URL_COMMONCRAWL_LIMIT", 10_000)

#: Pin a Common Crawl index id (e.g. ``CC-MAIN-2026-05``).  Empty means "ask
#: collinfo.json for the newest", which is one extra request but never stale.
COMMONCRAWL_INDEX = os.getenv("URL_COMMONCRAWL_INDEX", "").strip()

#: Results requested from the urlscan.io search API (its documented maximum is
#: 10 000; unauthenticated search is heavily rate-limited, so the default stays
#: modest and a key raises the ceiling).
URLSCAN_LIMIT = env_int("URL_URLSCAN_LIMIT", 1_000)

#: Optional urlscan API key.  Without it the search endpoint still answers, but
#: with a much smaller quota — the source degrades to "fewer results", never to
#: an error (see ``passive/urlscan.py``).
URLSCAN_KEY = os.getenv("URL_URLSCAN_KEY", "").strip()

#: The all-in-one image built from this stage's Dockerfile.  Only the ``gau``
#: source uses it; the HTTP sources are keyless Python and need no image.
IMAGE = os.getenv("URL_GAU_IMAGE", "url_endpoint_image")


# --------------------------------------------------------------------------- #
# HTTP behaviour (shared by the keyless sources)
# --------------------------------------------------------------------------- #

#: Cap on how many bytes one HTTP response may contribute.
HTTP_MAX_BYTES = env_int("URL_HTTP_MAX_BYTES", 64 * 1024 * 1024)

#: Retries per request for the statuses that are genuinely transient.
HTTP_RETRIES = env_int("URL_HTTP_RETRIES", 3)

#: Seconds allowed for one HTTP lookup (connect, read).
HTTP_TIMEOUT = float(env_int("URL_HTTP_TIMEOUT", 60))

#: Connect timeout, kept separately from the read timeout so a blackholed host
#: fails fast instead of consuming the whole per-source budget.
HTTP_CONNECT_TIMEOUT = float(env_int("URL_HTTP_CONNECT_TIMEOUT", 10))


# --------------------------------------------------------------------------- #
# Union limits
# --------------------------------------------------------------------------- #

#: Head-count cap on the URL union, applied after dedup.  A protection against a
#: target whose historical surface is millions of near-duplicate URLs; 0 means
#: no cap.  When a cap bites, the report says so instead of silently truncating.
MAX_URLS = env_int("URL_MAX_URLS", 0)


# --------------------------------------------------------------------------- #
# Live validation (the pipeline's one active stage)
# --------------------------------------------------------------------------- #

#: Run the validation stage.  Off means the pipeline is exactly as passive as it
#: was before the stage existed: no candidate is selected and no packet is sent,
#: and the report says which way it went.
VALIDATE_ENABLED = env_flag("URL_VALIDATE", True)

#: Candidates validated per run, applied *after* the policy gate and priority
#: ordering — so the cap keeps the most interesting URLs, not the first 200
#: alphabetically.  0 means no cap.
VALIDATE_MAX_URLS = env_int("URL_VALIDATE_MAX_URLS", 200)

#: Per-host cap, so one chatty host cannot consume a whole run's budget.  The
#: cap is a volume control, not a judgement: the escalation policy allows a
#: single archived URL to be checked because that is precisely what validation is
#: for (see ``platform.escalation``).
VALIDATE_MAX_PER_HOST = env_int("URL_VALIDATE_MAX_PER_HOST", 25)

#: Seconds a previous measurement stays reusable.  Re-running the stage within
#: this window validates only what changed — the operation-state half of
#: idempotency.  ``0`` forces a full re-check.
VALIDATE_TTL = env_int("URL_VALIDATE_TTL", 86_400)

#: Requests per second and worker count handed to httpx.  Deliberately lower
#: than the ports stage's probe: these requests go to the target's own hosts.
VALIDATE_RATE_LIMIT = env_int("URL_VALIDATE_RATE_LIMIT", 5)
VALIDATE_THREADS = env_int("URL_VALIDATE_THREADS", 10)

#: The image that carries ``httpx``.  Reusing the ports/services stage's image
#: rather than pulling a second one is deliberate (one httpx integration, one
#: version of the tool); ``projectdiscovery/httpx`` works too, since the argument
#: builder only uses flags both images accept.


# --------------------------------------------------------------------------- #
# S24 — JS bundle crawl (the stage's second active stage)
# --------------------------------------------------------------------------- #

#: Run the JS bundle crawl.  Off means no bundle is fetched and the stage writes
#: an ``enabled: false`` report — passive behaviour, stated rather than silent.
JSCRAWL_ENABLED = env_flag("URL_JSCRAWL", True)

#: Cap on bundles fetched per run (source maps count against the same budget).
#: This is the stage that turns the harvest's "where the JavaScript is" into
#: "what the JavaScript says" — the one remaining recall lever after convergence.
JSCRAWL_MAX_BUNDLES = env_int("URL_JSCRAWL_MAX_BUNDLES", 120)
HTTPX_IMAGE = os.getenv("URL_HTTPX_IMAGE", "port_service_host_image").strip() or "port_service_host_image"
