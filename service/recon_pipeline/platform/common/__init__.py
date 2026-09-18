"""Shared, asset-agnostic primitives every pipeline consumes from the platform.

Extracted from the old per-pipeline copies so the semantics cannot drift:

- :mod:`.config`       — the single ``.env`` loader + ``TARGET`` default
- :mod:`.env`          — ``env_int`` / ``env_flag`` (malformed → default)
- :mod:`.normalize`    — host/IP canonicalization + subdomain arithmetic
- :mod:`.io`           — deterministic ``write_lines`` / ``write_jsonl`` /
                         ``write_json`` / ``read_text`` (atomic tmp+rename)
- :mod:`.docker_tool`  — the Docker runner for bundled tool images
- :mod:`.httpjson`     — status-preserving HTTP GET ("no data" ≠ "no answer")

Rules for what belongs here: pure, asset-agnostic, and needed by more than one
pipeline.  Anything asset-specific stays in the pipeline folder.
"""

from __future__ import annotations

__all__ = ["config", "env", "normalize", "io", "docker_tool", "httpjson"]
