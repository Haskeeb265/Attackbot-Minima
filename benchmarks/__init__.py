"""The VWA benchmark: cases, runner, scorer.

Consumes only artifacts the engine emits (world logs, report JSONs); ground
truth never reaches the engine's runtime — see
``docs/vuln_engine_docs/vwa_benchmark_proposal.md``. The import direction is
one-way and test-enforced: this package may import engine modules; no engine
module may reference this package.
"""
