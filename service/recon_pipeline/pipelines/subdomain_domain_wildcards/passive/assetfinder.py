"""
assetfinder — 7 certificate-transparency / web sources.

Runs with ``--subs-only`` so the apex is excluded from the raw list (the
normalizer drops it either way; this keeps the file clean).

    python -m service.recon_pipeline.pipelines.subdomain_domain_wildcards.passive.assetfinder
"""

from __future__ import annotations

from pathlib import Path

from service.recon_pipeline.platform.common.config import TARGET

from .sources import run_source_checked

NAME = "assetfinder"


def run(domain: str = TARGET) -> Path:
    """Enumerate *domain* with assetfinder; return the raw output file path."""
    return run_source_checked(NAME, domain)


if __name__ == "__main__":
    print(f"assetfinder results saved to: {run()}")
