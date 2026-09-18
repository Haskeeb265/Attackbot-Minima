"""Tunable settings and paths for the graph-normalization pipeline.

Same shape as the sibling pipelines, on purpose: every path is derived from
``__file__`` exactly once, every knob reads a ``GN_*`` environment variable with
a documented default, and the sibling artifact directories are **settings, not
guesses**, so a run against a different checkout root is reproducible from the
environment alone.

Environment overrides
---------------------
=============================================== ==========================================
``GN_NAMES_DIR``                                sibling artifact dir for the names pipeline
``GN_PORTS_DIR``                                sibling artifact dir for the ports pipeline
``GN_URLS_DIR``                                 sibling artifact dir for the URL pipeline
``GN_NETWORKS_DIR``                             sibling artifact dir for the network pipeline
``GN_INCLUDE_NAMES``                             read the names artifacts (on)
``GN_INCLUDE_PORTS``                             read the ports artifacts (on)
``GN_INCLUDE_URLS``                              read the URL artifacts (on)
``GN_INCLUDE_NETWORKS``                          read the network artifacts (on)
``GN_MAX_NODES``                                 cap on emitted nodes (200 000)
``GN_MAX_EDGES``                                 cap on emitted edges (400 000)
``GN_MAX_EVIDENCE``                              evidence strings kept per node/edge (8)
``GN_MAX_ORPHANS``                               orphan ids listed in the report (50)
=============================================== ==========================================

The pipeline makes no network requests and reads no configuration beyond these
paths: its inputs are files the sibling pipelines already wrote.
"""

from __future__ import annotations

import os
from pathlib import Path

from service.recon_pipeline.platform.common.env import env_flag, env_int

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #

GN_DIR = Path(__file__).resolve().parent

#: Where this pipeline's own artifacts are written.
OUTPUT_DIR = GN_DIR / "output"

#: The siblings' artifact roots — read-only inputs.  ``parents[1]`` is
#: ``service/recon_pipeline/pipelines/``, which is where every pipeline folder
#: lives, so these track the tree layout without hardcoding an absolute path.
PIPELINES_DIR = GN_DIR.parent



def _dir_override(env_name: str, default: Path) -> Path:
    """Resolve one sibling artifact root from the environment, if it is set."""
    raw = os.getenv(env_name, "").strip()
    return Path(raw).expanduser() if raw else default


#: Sibling artifact roots.  Each is the pipeline folder, not its ``output/``.
NAMES_DIR = _dir_override("GN_NAMES_DIR", PIPELINES_DIR / "subdomain_domain_wildcards")
PORTS_DIR = _dir_override("GN_PORTS_DIR", PIPELINES_DIR / "port_service_host")
URLS_DIR = _dir_override("GN_URLS_DIR", PIPELINES_DIR / "url_endpoint")
NETWORKS_DIR = _dir_override("GN_NETWORKS_DIR", PIPELINES_DIR / "asn_cidr")

# --------------------------------------------------------------------------- #
# Which sibling artifacts feed the model
# --------------------------------------------------------------------------- #

#: Per-source switches.  Turning one off produces a smaller model and the report
#: says which sources were skipped — the opposite of quietly missing data.
INCLUDE_NAMES = env_flag("GN_INCLUDE_NAMES", True)
INCLUDE_PORTS = env_flag("GN_INCLUDE_PORTS", True)
INCLUDE_URLS = env_flag("GN_INCLUDE_URLS", True)
INCLUDE_NETWORKS = env_flag("GN_INCLUDE_NETWORKS", True)

# --------------------------------------------------------------------------- #
# Caps
# --------------------------------------------------------------------------- #

#: Caps on the emitted model.  A target whose URL harvest returns hundreds of
#: thousands of rows should produce a truncated-but-honest model (the report
#: carries ``truncated: true``), never an unbounded artifact set.
MAX_NODES = env_int("GN_MAX_NODES", 200_000)
MAX_EDGES = env_int("GN_MAX_EDGES", 400_000)

#: Evidence strings kept per node/edge.  Evidence is for a human reading one
#: node; the sources list is the compact form the machines use, so the cap costs
#: detail, not provenance.
MAX_EVIDENCE = env_int("GN_MAX_EVIDENCE", 8)

#: Orphan node ids listed in the report (the count is always complete).
MAX_ORPHANS = env_int("GN_MAX_ORPHANS", 50)

#: Wildcard-coverage edges emitted per wildcard suffix.  One wildcard answer for
#: ``*.example.com`` genuinely covers every host under it, which on a large
#: target is thousands of edges restating one fact.  The cap keeps the model
#: readable; the count of hosts a wildcard covers travels as a node property, so
#: the truncated detail is still available as a number.
MAX_WILDCARD_EDGES = env_int("GN_MAX_WILDCARD_EDGES", 100)

#: Scope string recorded on nodes whose kind poses no scope question (a URL, a
#: service identity, an ASN).  Omitted entirely when a scope engine is absent.
SCOPE_NOT_APPLICABLE = "not_applicable"
