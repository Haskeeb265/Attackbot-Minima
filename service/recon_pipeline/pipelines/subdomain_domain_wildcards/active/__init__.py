"""
Active DNS stage of the ``subdomain_domain_wildcards`` asset pipeline.

Turns candidate names — the passive stage's subdomains, a wordlist, and the
permutation stage's output — into live hosts, with wildcard filtering, DNS record
enrichment, and zone-transfer attempts.

Public entry point::

    from service.recon_pipeline.pipelines.subdomain_domain_wildcards.active import (
        run_active_stage,
    )

    report = run_active_stage("example.com")

Heavy modules (Docker plumbing, tool wrappers) are imported lazily on attribute
access, so ``import ...active.resolve`` stays cheap and side-effect-free.  The
curated resolver seeds and the bundled wordlist are data files, not imports.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

__all__ = ["run_active_stage"]

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .pipeline import run_active_stage as run_active_stage


def __getattr__(name: str):
    if name == "run_active_stage":
        from .pipeline import run_active_stage

        return run_active_stage
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
