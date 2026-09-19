"""Pipeline contract module — the only registration point for this pipeline."""

from __future__ import annotations

from typing import Any

from service.recon_pipeline.platform.contract import BasePipeline, Manifest, RunContext, Stage

MANIFEST = Manifest(
    name="subdomain_domain_wildcards",
    title="Names pipeline — domains, subdomains, wildcards",
    asset_types=("Domain", "Subdomain", "Wildcard"),
    description=(
        "Passive source union -> active resolution -> permutation, producing "
        "the live-host list every other pipeline consumes."
    ),
    provides=("Domain", "Subdomain", "Wildcard"),
    consumes=(),
    stages=(
        Stage("passive", "passive source union (CT logs, datasets, Docker tools)"),
        Stage("active", "resolver-validated DNS resolution"),
        Stage("permutation", "capped name permutation and re-resolution"),
    ),
    passive_only=False,
    #: What the names pipeline puts *on the table*: the names that resolved.  The
    #: convergence driver canonicalises these after every round to answer whether
    #: the surface is still growing.
    frontier_artifacts=(
        "output/live_hosts.txt",
        "active/output/resolved.txt",
        "permutation/output/resolved.txt",
    ),
    #: ``passive`` is deliberately absent, and that is an empirical finding, not a
    #: preference: its seven sources are **subtree queries** (crt.sh is asked for
    #: ``%.<apex>``, Wayback with ``matchType=domain``, pinned by
    #: ``tests/recon/test_passive_sources.py``), so one call already returns every
    #: depth and a repeat would re-query a subset of a set we hold.
    #: ``active``/``permutation`` are the generators: bruteforce under
    #: newly-resolved parents, permutations of newly-known names.
    repeat_stages=("active", "permutation"),
    #: A repeat is worth its DNS queries only when *names* appeared: permutation
    #: generates from newly-known names, and ``active``'s recursion bruteforces
    #: under newly-resolved parents.  A round that added only addresses or URLs
    #: would re-resolve the same names — the requests the ledger exists to save.
    repeat_on=("host",),
)


class NamesPipeline(BasePipeline):
    """Adapter: platform contract -> the names pipeline's main module."""

    def run(self, stage: str, context: RunContext) -> dict[str, Any]:
        from .main import run_pipeline

        summary = run_pipeline(context.target, stages=[stage])
        return {
            "ok": bool(summary.ok),
            "counts": dict(summary.counts),
            "seconds": summary.seconds,
            "outputs": {k: str(v) for k, v in summary.outputs.items()},
        }


PIPELINE = NamesPipeline()
