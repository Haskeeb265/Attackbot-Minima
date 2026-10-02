"""The Attackbot operator UI: one local web app over the artifacts the repo already writes.

Read-only by design — every panel is a view of program rows in PostgreSQL,
recon artifacts, ``graph_state.json``, the vuln engine's ``world.jsonl`` ledger
and its ``report.json``. See ``service/ui/README.md``.
"""
