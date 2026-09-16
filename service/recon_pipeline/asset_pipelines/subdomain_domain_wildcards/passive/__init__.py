"""
Passive subdomain enumeration stage of the ``subdomain_domain_wildcards``
asset pipeline.

Public entry point::

    from service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.passive import (
        run_passive_stage,
    )

    report = run_passive_stage("example.com")

The heavy modules (HTTP sources, Docker plumbing) are imported lazily on first
attribute access, so ``import ...passive.normalize`` stays cheap and
side-effect-free.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

__all__ = ["run_passive_stage"]

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .pipeline import run_passive_stage as run_passive_stage


def __getattr__(name: str):
    if name == "run_passive_stage":
        from .pipeline import run_passive_stage

        return run_passive_stage
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
