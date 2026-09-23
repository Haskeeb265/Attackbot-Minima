"""The vulnerability engine: a deterministic harness whose thesis is one finding.

Phase 1 of ``docs/vuln_engine_docs/phase1_checklist.md`` — "one finding, provably".
The engine's claim is narrow and testable: it can produce a finding that is
independently verified, replayable, and gate-audited, with **zero LLM code**. Every
other capability in the design (UCB, attack tree, junctions, primitives) is parked
until that claim holds.

The three load-bearing properties, each with its own test:

1. **Generated is a lead; executed-and-observed is a finding.** A candidate only
   becomes a finding through a verifier using a *different* evidence class.
2. **One door to the network.** Everything that touches a target goes through
   :class:`..policy.gate.PolicyGate`, which wraps the recon platform's existing
   dispatcher rather than reimplementing it, and logs every decision with a reason.
3. **The log is the environment.** A run is an append-only JSONL event log, so it
   replays offline — no network, no clock, no model.

Layout (see the checklist §2 item 0):

``kernel/``       contracts only — evidence, exchanges, observations, manifests, verdicts
``transports/``   http1 · browser · oob, capability-reporting and swappable
``techniques/``   one folder per vuln class: manifest, hypothesis, probes, interpret
``verification/`` independent confirmation, always in a class the proposer did not use
``scheduler/``    deterministic enumeration in Phase 1 (UCB is Phase 2)
``world/``        append-only JSONL log, derived views, the observation layer
``policy/``       wraps ``platform.dispatch``; the sole caller of every transport
``llm/``          Phase 3: typed advisory junctions — no key means unchanged
                  behaviour, never silence (empty through Phases 1–2, by design)
"""

from __future__ import annotations

__all__: list[str] = []
