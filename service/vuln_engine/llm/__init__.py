"""The LLM junctions: typed, advisory, logged, cached, replayable.

Empty through Phase 1 and Phase 2 **by design** — Phase 1's claim was that the
engine can produce one independently verified, replayable, gate-audited finding
without a model, and a version that needed a key to demonstrate that would have
been demonstrating something else. The invariant test kept this package empty
until that claim held. It holds. Phase 3 arrives here, under the contract the
recon side set with ``platform/enrich.py``:

* **advisory** — every junction's output is an opinion a pure consumer may
  read. The selector still picks, the verifier still confirms, the report's
  canonical lines still derive from the log. No junction can decide anything;
* **no key means deterministic behaviour, never silence** —
  :attr:`LLMClient.available` is ``False`` without
  ``VULN_ENGINE_LLM_API_KEY`` + ``VULN_ENGINE_LLM_API_URL``, and every
  junction returns its degraded shape without touching the network or
  raising. Wiring the junctions is a no-op with no key configured;
* **typed** — junctions exchange plain dataclasses and dicts of typed fields,
  never prose-with-semantics. Model answers are validated against a fixed
  contract; a drifted answer is a degraded opinion with the complaint as its
  reason, not an exception;
* **logged and replayable** — every call is appended to the world log as an
  ``llm.junction`` row keyed by *input digest*. A replay of a run that once
  consulted the model finds the cached opinion in the log and reproduces the
  engagement offline with the key removed;
* **no free-form model output reaches the wire** — the synthesize junction's
  model chooses *within a grammar* (vector, quote style, tag closing); the
  engine constructs the payload. Generated is a lead; executed-and-observed is
  a finding — the rule Phase 1 built now covers model-generated probes too.

R&D grounding (``RnD_2026-09.md``): the three junctions and their scope are
§C2 (AWE's constraint-aware payload synthesis), §C3.4 (grammar-bounded
generation as the PoC-pollution answer), and §C8 (the OWASP quarantined-LLM
pattern — the model reads typed structural fields, never target response
bodies, so there is no channel for a target to speak through).

Modules: :mod:`.client` (the one door, key-gated, injectable) ·
:mod:`.rank` / :mod:`.synthesize` / :mod:`.write` (pure halves: inputs,
prompts, validators) · :mod:`.runtime` (the ask→validate→construct sequence
for the synthesize junction) · :mod:`.wiring` (advisory plumbing the driver,
campaign and CLI read through).
"""

from __future__ import annotations

from .client import EVENT_LLM_JUNCTION, Health, LLMClient, ModelCaller, Opinion, opinion_digest
from .rank import PRIOR_CEILING, PRIOR_TOTAL, Ranking
from .runtime import SynthesisJunction, SynthesisResult
from .write import Draft

__all__ = [
    "EVENT_LLM_JUNCTION",
    "Draft",
    "Health",
    "LLMClient",
    "ModelCaller",
    "Opinion",
    "PRIOR_CEILING",
    "PRIOR_TOTAL",
    "Ranking",
    "SynthesisJunction",
    "SynthesisResult",
    "opinion_digest",
]
