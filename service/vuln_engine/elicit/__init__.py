"""The elicitor corpus: measured capability claims, one folder per capability.

An elicitor is a verifier with the candidate removed (``RND_dynamic_preconditions.md``
§2): it asks a cheap, low-noise question of a surface — *does this parameter
reflect? does a fetch of our URL arrive? does the delay track the dose?* — and
records the answer as a :class:`kernel.capability.CapabilityFact` instead of
proposing a candidate. The fact is a **fact about the surface**, never a finding:
it opens the eligibility door for the technique whose precondition it names, and
that technique still pays the full propose → verify pipeline before anything
becomes a finding.

Discovery mirrors the techniques registry: a folder with ``MANIFEST`` and
``ELICITOR`` is an elicitor; anything else is skipped, loudly or silently exactly
as the techniques registry behaves. The manifest is the techniques' own
``TechniqueManifest`` shape — the ``vuln_class`` field is deliberately unused
by elicitors (it is filled with ``capability-elicitation``), and ``preconditions``
is read as *the capability this elicitor establishes*.

The honesty rules, in one place:

* an elicitor's evidence is the class its probe produces (``reflection`` for a
  canary, ``oob`` for the collaborator, ``differential`` for the dose-response
  and two-session measurements) — carried on the fact, readable in the log;
* an elicitor never re-runs within one run for the same surface once it has an
  answer (the world log's own rows are the dedup, exactly as for techniques);
* elicitation is traffic, so it goes through the ordinary PolicyGate and
  receipts rules — nothing about it bypasses scope, budget or etiquette.
"""

from __future__ import annotations

from .common import Elicitation  # noqa: F401

__all__ = ["Elicitation"]
