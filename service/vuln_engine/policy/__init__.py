"""The policy layer: the only door to the network, and the only caller of a transport.

``gate.py`` wraps the recon platform's existing decision — scope, score floor,
escalation eligibility, budgets, cooldowns — rather than rebuilding any part of
it. That is the design's chokepoint made structural: a technique cannot reach the
wire, because a technique has no transport and the gate does not hand one out. It
takes a description of an effect and returns an outcome.

Everything here is auditable by construction: ``ALLOW``, ``DEFER`` and ``DENY`` all
land in the world log with their reason, and ``world.views.gate_audit`` computes
the number the chokepoint exists to produce — effects that ran without a clearance.
"""

from __future__ import annotations

__all__: list[str] = []
