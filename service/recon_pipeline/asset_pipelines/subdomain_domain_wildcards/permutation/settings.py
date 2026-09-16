"""Tunable settings and paths for the permutation stage.

The permutation stage is deliberately thin: it *generates* candidate hostnames
from the names the other two stages already found, and hands them to the active
stage's resolution engine.  So there is very little to configure here — one
generator, one cap, and the paths of the inputs it reads.

Environment overrides
---------------------
``PERMUTATION_TIMEOUT``          seconds dnsgen may run (default 900)
``PERMUTATION_MAX_KNOWN``        known hosts fed to the generator (100)
``PERMUTATION_MAX_CANDIDATES``   cap on generated candidates (100000)
``PERMUTATION_WORDLEN``          ``dnsgen --wordlen`` (0 = generator default)
``PERMUTATION_FAST``             ``1`` runs dnsgen in ``--fast`` mode
``PERMUTATION_REUSE_RESOLVERS``  ``0`` re-validates instead of reusing the
                                 active stage's validated pool
"""

from __future__ import annotations

from pathlib import Path

from ..active.settings import ACTIVE_DIR
from ..env import env_flag, env_int
from ..passive.settings import PASSIVE_DIR

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #

PERMUTATION_DIR = Path(__file__).resolve().parent

#: Generated candidates, resolved live hosts, and the run report.
OUTPUT_DIR = PERMUTATION_DIR / "output"

#: Inputs.  The active stage's resolved hosts are the richest source of
#: permutation material, because they are names that are *known* to exist; the
#: passive list is a fallback for a run that happens before the active stage.
ACTIVE_RESOLVED_FILE = ACTIVE_DIR / "output" / "resolved.txt"
PASSIVE_SUBDOMAINS_FILE = PASSIVE_DIR / "output" / "subdomains.txt"

#: The validated resolver pool (and trusted subset) the active stage wrote.
#: Reused so both stages resolve against exactly the same resolvers.
ACTIVE_RESOLVERS_FILE = ACTIVE_DIR / "output" / "resolvers.txt"
ACTIVE_TRUSTED_FILE = ACTIVE_DIR / "output" / "resolvers-trusted.txt"

#: Container mount point, shared with the active stage (same image, same tools).
CONTAINER_WORKDIR = "/work"


# --------------------------------------------------------------------------- #
# Run limits
# --------------------------------------------------------------------------- #

#: Wall-clock cap for the generator.
TIMEOUT = env_int("PERMUTATION_TIMEOUT", 900)

#: How many known hosts are fed to the generator.  dnsgen's output is
#: combinatorial in its input, and the value of a permutation is concentrated in
#: short names near the apex (``api-v2.example.com`` from ``api.example.com``), so
#: the known list is sorted shallowest-first and truncated rather than passed
#: whole.
#:
#: Measured on ``tesla.com`` (1,380 known hosts, shallowest first):
#:
#: =========== ============= =============== ========
#: inputs      dnsgen output unique names    seconds
#: =========== ============= =============== ========
#: 25             60,439         50,520          1
#: 50            138,755        110,502          3
#: 100           353,615        277,324          6
#: 300           794,815        552,194         20
#: 1,380      19,907,617            n/a       ~420
#: =========== ============= =============== ========
#:
#: Every value overshoots the candidate cap by more than an order of magnitude,
#: so additional inputs buy no extra *resolved* coverage under a fixed budget —
#: they only add generation time.  100 keeps a rich shared vocabulary (which is
#: what makes a permutation recognisable) while generating in a few seconds.
MAX_KNOWN = env_int("PERMUTATION_MAX_KNOWN", 100)

#: Hard ceiling on generated candidates — a safety valve, not a budget.
#:
#: It is set high enough that an ordinary run resolves the generator's *entire*
#: deterministic pool, because the pool is where the value is and the cost of
#: covering it is small.  Measured on ``tesla.com`` (the resolve step of the live
#: run recorded in the stage README):
#:
#: * generation of the full pool (111,613 raw names from 100 inputs) takes 4.1s;
#: * resolution runs at ~1,300 candidates/s, i.e. ~16s for 20,000 and ~83s for the
#:   whole 107,667-name pool.
#:
#: So a 20,000 cap discarded 82% of an already-computed pool to save ~67 seconds —
#: the wrong trade for a stage whose entire purpose is coverage.  Candidate order
#: is the generator's own confidence ordering and re-ranking it by heuristic was
#: tried and rejected: depth-first, distance-to-known-host and known-vocabulary
#: rankings *each* pushed live hits out of a 20,000-name budget, while the
#: generator's own order kept them.
#:
#: The cap still matters for pathological inputs: 1,380 known hosts produce ~19.9M
#: names, which is where ``MAX_KNOWN`` (above) does the real bounding.
MAX_CANDIDATES = env_int("PERMUTATION_MAX_CANDIDATES", 100_000)

#: ``dnsgen --wordlen``: minimum length of words extracted from input labels.
#: ``0`` (the default) leaves the generator's own default in place rather than
#: pinning behaviour to a version-specific constant.
WORDLEN = env_int("PERMUTATION_WORDLEN", 0)

#: ``dnsgen --fast`` trades coverage for speed.
FAST = env_flag("PERMUTATION_FAST", False)

#: Reuse the active stage's validated resolver pool when it exists.  Resolvers do
#: not rot within a session, and re-probing 45 of them costs ~10s per run, so the
#: default is to reuse and fall back to validating.
REUSE_RESOLVERS = env_flag("PERMUTATION_REUSE_RESOLVERS", True)
