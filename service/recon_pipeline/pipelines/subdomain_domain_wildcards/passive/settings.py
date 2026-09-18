"""Tunable settings and paths for the passive subdomain enumeration stage.

Keeping these in one module means the pipeline, the individual tool wrappers,
and the tests all agree on where output lands and how long a tool may run —
no module ever recomputes paths from ``__file__`` on its own.

Environment overrides
---------------------
``PASSIVE_TIMEOUT``          seconds a single source may run (default 900).
``PASSIVE_WILDCARD_PROBE``   set to ``0`` to disable wildcard probing.
"""

from __future__ import annotations

import os
from pathlib import Path

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #

PASSIVE_DIR = Path(__file__).resolve().parent

#: Raw per-source files, derived lists, and the JSON run report all land here.
OUTPUT_DIR = PASSIVE_DIR / "output"

#: amass entry config + API keys (gitignored — see the stage README).
CONFIG_DIR = PASSIVE_DIR / "config"


# --------------------------------------------------------------------------- #
# Run limits
# --------------------------------------------------------------------------- #


def _env_int(name: str, default: int) -> int:
    """Read a positive int from the environment, falling back to *default*."""
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


#: Wall-clock cap for a single source (Docker container or HTTP harvest).
DEFAULT_SOURCE_TIMEOUT = _env_int("PASSIVE_TIMEOUT", 900)

#: Network timeout for one DNS query used during wildcard probing.
DNS_QUERY_TIMEOUT = 3.0

#: Number of random labels sampled per candidate wildcard parent.
WILDCARD_SAMPLES = 3

#: Only parents with at least this many discovered children are probed for a
#: wildcard. Keeps probing off the long tail of one-off labels (which is where
#: a wildcard answer would be harmless noise anyway).
WILDCARD_MIN_CHILDREN = 4

#: Master switch for the DNS wildcard layer (see ``PASSIVE_WILDCARD_PROBE=0``).
WILDCARD_ENABLED = os.getenv("PASSIVE_WILDCARD_PROBE", "1") not in {"0", "false", "False"}

#: Hard ceiling on DNS queries per wildcard phase (detection / filtering).
WILDCARD_MAX_QUERIES = _env_int("PASSIVE_WILDCARD_MAX_QUERIES", 300)

#: Wall-clock budget for a wildcard phase, in seconds.  A query cap alone is not
#: enough: a slow or blackholed resolver would turn 300 queries into an hour.
WILDCARD_MAX_SECONDS = _env_int("PASSIVE_WILDCARD_MAX_SECONDS", 120)

#: amass's own ``-timeout`` (minutes). amass streams relations to stdout and
#: only flushes reliably on a clean exit, so it is given a self-imposed deadline
#: well inside the container timeout - otherwise a kill would discard the run.
AMASS_TIMEOUT_MINUTES = _env_int("PASSIVE_AMASS_TIMEOUT_MINUTES", 5)

#: Cap on how many bytes a single HTTP source (crt.sh / Wayback) will read.
HTTP_MAX_BYTES = 64 * 1024 * 1024

#: Retries per HTTP source request (transient 5xx / connection resets).
HTTP_RETRIES = 3
