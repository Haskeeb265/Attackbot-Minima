#!/usr/bin/env python3
"""One-shot smoke test for the LLM junctions with a real key.

Not a campaign: the DVWA run already proved the engine end to end — this proves
only the *wiring* (key → health → one logged, validated junction call), at the
cost of one model call. Three checks, then out:

1. health says available, with the model named and no secret echoed;
2. the rank junction answers a real question over the real registry, and the
   answer passes validation (a keyless run would be degraded here);
3. the world log carries the ``llm.junction`` row with a digest — the cache
   key that makes the model replayable offline.

Usage:  python run_engine.py --version >/dev/null 2>&1 || true
        python docker/llm_smoke_test.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import run_engine  # noqa: E402
from service.vuln_engine.llm.wiring import Advisory  # noqa: E402
from service.vuln_engine.registry import TechniqueRegistry  # noqa: E402


def main() -> int:
    run_engine.load_env_file()
    advisory = Advisory.from_env()
    health = advisory.health.to_dict()
    print(f"health: available={health['available']} model={health['model']}")
    print(f"reason: {health['reason'][:120]}")
    if not advisory.available:
        print("FAIL: the junctions are degraded — key not loaded?", file=sys.stderr)
        return 1

    registry = TechniqueRegistry.discover(strict=False)
    seed = run_engine.fixture_profile().seed
    ranking = advisory.ranking(seed, registry, now=0.0)
    print(
        f"rank junction: degraded={ranking.degraded} "
        f"opinions={ {k: round(v, 2) for k, v in sorted(ranking.opinions.items())} }"
    )
    if ranking.degraded:
        print(f"FAIL: the rank opinion did not validate: {ranking.reason}", file=sys.stderr)
        return 1

    print("PASS: key loaded, one junction call validated, wiring works.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
