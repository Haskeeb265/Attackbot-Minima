"""Tunable settings and paths for the cloud-resource pipeline.

Same shape as the sibling stages, on purpose: every path is derived from
``__file__`` exactly once, and every knob reads a ``CLOUD_*`` environment
variable with a documented default, so a run is reproducible from the CLI alone.

``env_int`` / ``env_flag`` come from the platform's common env module — the same
place the siblings import them from — so environment-parsing semantics (a typo
falls back to the default; ``0``/``false``/``no``/``off`` mean off) cannot drift
between stages.

Environment overrides
---------------------
========================================== ==========================================
``CLOUD_S3_ENABLED``                       probe AWS S3 (on)
``CLOUD_AZURE_ENABLED``                    probe Azure Blob (on)
``CLOUD_GCS_ENABLED``                      probe GCS (on)
``CLOUD_MAX_DERIVED``                      cap on brand×shape derived names (128)
``CLOUD_MAX_PROBES``                       cap on existence probes per run (512)
``CLOUD_HTTP_TIMEOUT``                     seconds one probe may take (15)
``CLOUD_HTTP_RETRIES``                     transient retries per probe (2)
========================================== ==========================================
"""

from __future__ import annotations

from pathlib import Path

from service.recon_pipeline.platform.common.env import env_flag, env_int

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #

CLOUD_DIR = Path(__file__).resolve().parent

#: The passive stage's own directory and its output (candidates).
PASSIVE_OUTPUT_DIR = CLOUD_DIR / "passive" / "output"

#: The probe stage's derived artifacts (verdicts, buckets, dangling).
OUTPUT_DIR = CLOUD_DIR / "output"


# --------------------------------------------------------------------------- #
# Probe behaviour
# --------------------------------------------------------------------------- #

#: One provider toggle per family, so a run can be narrowed without code.
S3_ENABLED = env_flag("CLOUD_S3_ENABLED", True)
AZURE_ENABLED = env_flag("CLOUD_AZURE_ENABLED", True)
GCS_ENABLED = env_flag("CLOUD_GCS_ENABLED", True)

#: Wall-clock and retry behaviour for one existence probe.  Kept deliberately
#: tighter than the sibling stages' budgets: a probe is one GET to a provider
#: edge, and the matrix (DESIGN.md §3) needs no slow endpoints.
HTTP_TIMEOUT = float(env_int("CLOUD_HTTP_TIMEOUT", 15))
HTTP_RETRIES = env_int("CLOUD_HTTP_RETRIES", 2)

#: Cap on the brand×name-shape vocabulary.  Derivation exists to suggest
#: plausible names for a brand the siblings saw, not to brute-force the
#: provider; when the cap bites the report says so (same honesty rule as
#: ``asn_cidr``'s prefix caps).
MAX_DERIVED = env_int("CLOUD_MAX_DERIVED", 128)

#: Cap on existence probes per run.  The probe loop is request-bounded by
#: design; a candidate set above the cap is probed first-come (sorted), and
#: the report carries the truncation.
MAX_PROBES = env_int("CLOUD_MAX_PROBES", 512)


# --------------------------------------------------------------------------- #
# Sibling artifacts (the passive stage's inputs)
# --------------------------------------------------------------------------- #

#: The names pipeline's root (its ``active/output/records.jsonl`` carries the
#: CNAME answers, its ``output/live_hosts.txt`` the brand tokens).
NAMES_DIR = CLOUD_DIR.parent / "subdomain_domain_wildcards"

#: The takeover policy gate (S25): what a vulnerable finding *does*.  Until S4
#: program ingestion decides it from real metadata, this is the operator's
#: hand — ``informational`` records findings without a scoring signal,
#: ``enforced`` promotes them.  The report always names which way the gate was
#: set, so an informational finding is never mistaken for a scored one.
TAKEOVER_POLICY = "informational"

#: The URL pipeline's root (``output/urls.jsonl`` / ``javascript.txt`` /
#: ``endpoints.txt`` carry provider-hosted URLs and bucket-name strings).
URLS_DIR = CLOUD_DIR.parent / "url_endpoint"
