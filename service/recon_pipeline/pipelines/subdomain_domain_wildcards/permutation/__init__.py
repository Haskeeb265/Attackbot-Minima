"""
Permutation stage of the ``subdomain_domain_wildcards`` asset pipeline.

Derives candidate hostnames from names that already exist (``api.example.com`` ->
``api-v2.example.com``) and resolves them through the active stage's engine.

Public entry point::

    from service.recon_pipeline.pipelines.subdomain_domain_wildcards.permutation import (
        run_permutation_stage,
    )

    report = run_permutation_stage("example.com")

Heavy modules (the generator wrapper, Docker plumbing) are imported lazily on
attribute access, so ``import ...permutation.generate`` stays cheap.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

__all__ = ["run_permutation_stage"]

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .pipeline import run_permutation_stage as run_permutation_stage


def __getattr__(name: str):
    if name == "run_permutation_stage":
        from .pipeline import run_permutation_stage

        return run_permutation_stage
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
