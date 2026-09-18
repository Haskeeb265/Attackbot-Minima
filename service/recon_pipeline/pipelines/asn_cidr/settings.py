"""Tunable settings and paths for the ASN / CIDR pipeline.

Same shape as the sibling stages, on purpose: every path is derived from
``__file__`` exactly once, and every knob reads an ``ASN_*`` environment variable
with a documented default, so a run is reproducible from the CLI alone.

``env_int`` / ``env_flag`` come from the sibling names stage for the same reason
they came from it into ``url_endpoint``: environment-parsing semantics must not
drift between stages.

Environment overrides
---------------------
========================================== ==========================================
``ASN_RIPESTAT_ENABLED``                   use the RIPEstat Data API (on)
``ASN_RDAP_ENABLED``                       use RDAP allocation records (on)
``ASN_MAX_PREFIXES_PER_ASN``               cap on prefixes kept per ASN (2048)
``ASN_MAX_RANGES_PER_ORG``                 cap on RDAP ranges kept per org (256)
``ASN_MIN_PREFIX_LEN``                     narrowest prefix kept (24 for v4, 0 disables)
``ASN_MAX_PREFIX_LEN``                     widest v4 prefix kept (16 = no /8 aggregates)
``ASN_HTTP_TIMEOUT``                       seconds one lookup may take (30)
``ASN_HTTP_RETRIES``                       transient retries per request (3)
========================================== ==========================================
"""

from __future__ import annotations

import os
from pathlib import Path

from service.recon_pipeline.platform.common.env import env_flag, env_int

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #

ASN_DIR = Path(__file__).resolve().parent

#: Where the pipeline's artifacts are written.
OUTPUT_DIR = ASN_DIR / "output"

# --------------------------------------------------------------------------- #
# Source behaviour
# --------------------------------------------------------------------------- #

#: The RIPEstat Data API: keyless, no auth, documented limit of 8 concurrent
#: requests per source IP.  It answers "which prefixes does this AS announce",
#: "which AS(es) announce this prefix" and "which ASes are peers of this one".
RIPESTAT_ENABLED = env_flag("ASN_RIPESTAT_ENABLED", True)
RIPESTAT_BASE = "https://stat.ripe.net/data"

#: RDAP (via the IANA-blessed ``rdap.org`` bootstrap redirector) answers the
#: allocation question: which organisation is responsible for which range.  This
#: is the claim that is close to ownership; the ports stage's seed builder
#: already consumes RDAP-shaped facts for exactly that reason.
RDAP_ENABLED = env_flag("ASN_RDAP_ENABLED", True)
RDAP_URL = "https://rdap.org/ip/"
RDAP_DOMAIN_URL = "https://rdap.org/domain/"

#: ``sourceapp`` is RIPEstat's requested identification parameter; sending it is
#: the difference between "polite" and "anonymous load".
RIPESTAT_SOURCEAPP = os.getenv("ASN_RIPESTAT_SOURCEAPP", "attackbot-recon-asn-cidr").strip()

#: Wall-clock and retry behaviour for one HTTP lookup.  Kept separate from the
#: sibling stages' settings because the RIPEstat endpoints that explode a large
#: AS (announced-prefixes on a Tier-1) can legitimately take tens of seconds.
HTTP_TIMEOUT = float(env_int("ASN_HTTP_TIMEOUT", 30))
HTTP_RETRIES = env_int("ASN_HTTP_RETRIES", 3)
HTTP_CONNECT_TIMEOUT = float(env_int("ASN_HTTP_CONNECT_TIMEOUT", 10))

# --------------------------------------------------------------------------- #
# Result caps
# --------------------------------------------------------------------------- #

#: Cap on prefixes kept per ASN.  A Tier-1 AS announces tens of thousands of
#: prefixes; a target seeded onto such an AS would otherwise produce an
#: unreadable artifact set.  When the cap bites, the report says so.
MAX_PREFIXES_PER_ASN = env_int("ASN_MAX_PREFIXES_PER_ASN", 2_048)

#: Cap on RDAP ranges kept per organisation.
MAX_RANGES_PER_ORG = env_int("ASN_MAX_RANGES_PER_ORG", 256)

#: Narrowest prefix kept (v4).  /25s and longer inside a target's space are
#: usually announcements of single load-balancer VIPs; keeping them floods the
#: union with sub-split noise.  ``0`` disables the filter.
MIN_PREFIX_LEN = env_int("ASN_MIN_PREFIX_LEN", 24)

#: Widest v4 prefix kept.  A live run measured AS8075 announcing ``40.0.0.0/8``:
#: an aggregate that names 16 million addresses and contains one target address,
#: presenting them all as "discovered".  Aggregates are routing-table conveniences,
#: not footprint facts, so the default wall is /16 — anything wider is refused
#: and counted.  ``0`` disables the filter.
MAX_PREFIX_LEN = env_int("ASN_MAX_PREFIX_LEN", 16)
