"""
findomain — 54 certificate-transparency / API sources, queried in parallel.

Runs in quiet mode (``-q``) so stdout is a plain host list.  Includes the apex;
the normalizer drops it.

    python -m service.recon_pipeline.pipelines.subdomain_domain_wildcards.passive.findomain
"""

from __future__ import annotations

from pathlib import Path

from service.recon_pipeline.platform.common.config import TARGET

from .sources import run_source_checked

NAME = "findomain"


def run(domain: str = TARGET) -> Path:
    """Enumerate *domain* with findomain; return the raw output file path."""
    return run_source_checked(NAME, domain)


if __name__ == "__main__":
    print(f"findomain results saved to: {run()}")
