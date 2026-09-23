"""The scheduler: what runs next, and never how a technique works.

Phase 1 is deliberately unintelligent. ``driver.py`` enumerates every eligible
``(technique × surface)`` pair from declared preconditions and runs the probes in
cost order — requests before browsers, and a browser only where a measured context
justified it. That is enough to prove the thesis, and it is *auditable*, which UCB
is not.

``replay.py`` is the other half of the same idea: because the loop's decisions are
pure functions of recorded observations, a run can be recomputed offline from its
own log. A scheduler whose decisions could not be re-derived would make the whole
"replayable" invariant a claim rather than a test.

Phase 2 replaces the enumeration with the attack tree and UCB over the same
receipts this driver already writes. Nothing in Phase 1 has to change for that:
the driver's interface is the registry, the gate and the log.
"""

from __future__ import annotations

__all__: list[str] = []
