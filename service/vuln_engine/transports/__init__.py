"""Transports: the only code that touches a wire, and it decides nothing.

Each module here is one capability, reports what it can do, and returns a raw
exchange for the observation layer to parse:

``http1``    one HTTP round trip (``httpx``)
``browser``  an instrumented browser — script execution, dialogs, DOM mutation
``oob``      our own collaborator, and the interaction records it saw

Two rules keep this package from leaking into the rest of the engine:

* **nothing here imports policy.** The gate calls a transport, never the reverse,
  so "the only path to the network goes through the gate" is a property of the
  import graph rather than a convention;
* **nothing here knows what a vulnerability is.** A transport that could decide a
  finding would be a second place where truth is produced.

``tests/vuln_engine/test_invariants.py`` asserts that no module outside ``policy/``
imports any of these.
"""

from __future__ import annotations

__all__: list[str] = []
