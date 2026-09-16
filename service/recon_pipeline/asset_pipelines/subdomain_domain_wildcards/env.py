"""
Shared environment-variable parsing for the stage's settings modules.

Each stage exposes its knobs as ``STAGE_*`` environment variables with documented
defaults, and every one of them needs the same two behaviours:

* a malformed or out-of-range value falls back to the **default** rather than
  raising — a typo in one optional knob must not make the stage unrunnable;
* a boolean accepts the spellings operators actually type (``0``/``false``/
  ``no``/``off``), because ``STAGE_X=0`` meaning "enabled" is a classic surprise.

They live here rather than duplicated per stage so the semantics cannot drift
between the active and permutation stages.
"""

from __future__ import annotations

import os

_FALSEY = {"0", "false", "no", "off"}


def env_int(name: str, default: int, *, minimum: int = 0) -> int:
    """Read an int from the environment, falling back to *default*.

    Values below *minimum* (or unparseable ones) yield *default*.
    """
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value >= minimum else default


def env_flag(name: str, default: bool) -> bool:
    """Read a boolean flag from the environment (see :data:`_FALSEY`)."""
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() not in _FALSEY
