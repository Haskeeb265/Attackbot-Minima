"""Ports, services and hosts stage of the recon pipeline.

Answers the question the DNS stages only set up: **what is listening, on which
address, speaking what protocol?**  A ``dev.`` subdomain is a name;
``dev.example.com -> 203.0.113.7:8443 -> "Jetty 9.4 on an admin API"`` is attack
surface.

Public entry point::

    from service.recon_pipeline.pipelines.port_service_host import (
        run_port_service_host_stage,
    )

    report = run_port_service_host_stage("example.com")

Design and research: ``DESIGN.md`` in this directory.  The stage runs under the
shared stealth layer (``service/recon_pipeline/platform/stealth/``), refuses to run
active technique in passive-only mode, and reuses the sibling stage's Docker
plumbing rather than growing a second copy of it.

Heavy modules (Docker tooling, HTTP clients) are imported lazily on attribute
access, so ``import ...port_service_host.normalize`` stays cheap and
side-effect-free.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

__all__ = ["run_port_service_host_stage"]

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .pipeline import run_port_service_host_stage as run_port_service_host_stage


def __getattr__(name: str):
    if name == "run_port_service_host_stage":
        from .pipeline import run_port_service_host_stage

        return run_port_service_host_stage
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
