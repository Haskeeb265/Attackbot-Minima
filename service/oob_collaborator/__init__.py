"""The out-of-band collaborator: our own listener, and the records it keeps.

A separate service rather than a module inside the engine, for one reason: it must
be reachable *by the target*, and the engine must not be. A component that both
receives a target's traffic and decides what to do about it would be the one place
where an inbound request could influence the engine's behaviour — and the correct
amount of that influence is exactly none.

What it does: record an inbound request against the per-probe id in its path, answer
with a probe-specific token, and serve the records back to the verifier over a
different interface (``/interactions``) than the one the target used (``/oob/<id>``).

What it deliberately is not: authenticated, DNS-capable, or clever. See
``app.py`` for the two stated limitations.
"""

from __future__ import annotations

__all__: list[str] = []
