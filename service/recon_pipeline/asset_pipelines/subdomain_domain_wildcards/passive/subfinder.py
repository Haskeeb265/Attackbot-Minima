"""
subfinder — 30+ passive sources (ProjectDiscovery).

Thin facade over the registry in :mod:`..sources`, which owns the image tag and
container arguments.  See the stage README for observed runtimes and yields.

    python -m service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.passive.subfinder
"""

from __future__ import annotations

from pathlib import Path

from service.recon_pipeline.asset_pipelines.config import TARGET

from .sources import run_source_checked

NAME = "subfinder"


def run(domain: str = TARGET) -> Path:
    """Enumerate *domain* with subfinder; return the raw output file path."""
    return run_source_checked(NAME, domain)


if __name__ == "__main__":
    print(f"subfinder results saved to: {run()}")
