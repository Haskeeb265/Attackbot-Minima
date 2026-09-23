"""The vuln engine's kernel: contracts only, no logic.

Phase 1 is "one finding, provably" (``docs/vuln_engine_docs/phase1_checklist.md``).
Everything in this package is a *data shape* the rest of the engine agrees on —
nothing here decides anything, imports a transport, or reads a clock. That is
deliberate: the contracts are what every other module is tested against, so a
contract that contained behaviour would be the one thing that could not be
replaced without touching the rest of the engine.

The six contracts of ``engine_principles.md`` §1.1 are spread across three
modules' worth of shapes:

``evidence``
    How we came to believe something, and which classes a *finding* may rest on.
``exchange``
    What an Effect actually brought back — raw bytes, DOM facts, OOB interaction
    records. Raw bytes live here and nowhere else: the observation layer parses
    them and then discards them, so no other module can ever treat them as truth.
``observation``
    What the observation layer read out of an exchange. Typed fields, never text
    blobs, because "the response text" cannot be reasoned over, remembered, or
    verified.
``manifest``
    What a technique declares about itself: preconditions, postconditions, the
    evidence classes it produces, and what it costs in visibility.
``verdict``
    The verifier's narrow answer, plus the one check that makes independent
    verification structural rather than aspirational.
"""

from __future__ import annotations

__all__: list[str] = []
