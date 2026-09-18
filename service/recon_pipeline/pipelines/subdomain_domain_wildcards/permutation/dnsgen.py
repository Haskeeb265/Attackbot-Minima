"""
dnsgen — hostname permutation generation, run out of the stage image.

This module is a thin facade: the mechanics live in :mod:`..generate` (the
registry, normalisation and caps) and :mod:`..pipeline` (generation plus
resolution).  It exists because "generate permutations for a target" is a useful
one-liner on its own, and because the previous stub of this name was the
documented entry point for the tool.

    python -m service.recon_pipeline.pipelines.subdomain_domain_wildcards.permutation.dnsgen

Generates candidates only — nothing here resolves anything.  Run the pipeline
module to also resolve them.
"""

from __future__ import annotations

from pathlib import Path

import shared.colorlog as colorlog

from service.recon_pipeline.platform.common.config import TARGET

from ..active.resolve import write_list_file
from .generate import CANDIDATES_FILE, generate
from .pipeline import load_known_hosts
from .settings import MAX_CANDIDATES, OUTPUT_DIR, TIMEOUT

NAME = "dnsgen"


def run(
    target: str = TARGET,
    *,
    output_dir: Path | str = OUTPUT_DIR,
    max_candidates: int = MAX_CANDIDATES,
    timeout: float = TIMEOUT,
    **options: object,
) -> Path:
    """Generate permutations for *target*; return the candidates file path.

    Known hosts come from the active stage's ``resolved.txt`` and the passive
    stage's ``subdomains.txt`` — whichever exist.

    Raises
    ------
    ValueError
        If *target* is not a valid domain, or no known hosts were found.
    RuntimeError
        If the generator itself failed (image missing, generator error).
    """
    from ..passive.normalize import canonicalize_host

    apex = canonicalize_host(target)
    if apex is None:
        raise ValueError(f"target {target!r} is not a valid domain")

    sources = load_known_hosts(apex)
    known = set().union(*sources.values()) if sources else set()
    if not known:
        raise ValueError(
            "no known hosts to permute - run the passive and/or active stage first"
        )

    # The *whole* known set goes in: ``generate`` caps what it hands to the
    # generator, but it needs every known host to decide what is genuinely new.
    result = generate(
        known,
        apex=apex,
        output_dir=output_dir,
        timeout=timeout,
        limit=max_candidates,
        **options,
    )
    if not result.ok:
        raise RuntimeError(f"dnsgen failed for {target}: {result.error}")

    return write_list_file(Path(output_dir) / CANDIDATES_FILE, result.candidates)


if __name__ == "__main__":
    try:
        candidates_path = run()
    except (ValueError, RuntimeError) as exc:
        colorlog.log.failed(str(exc))
        raise SystemExit(2) from exc
    colorlog.log.success(f"permutation candidates written to {candidates_path}")
    raise SystemExit(0)
