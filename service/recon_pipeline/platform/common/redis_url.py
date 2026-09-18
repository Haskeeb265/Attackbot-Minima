"""Shared Redis URL parsing for the S8 hot cache and the S9 queue.

One parser, so the two services cannot drift on how ``REDIS_URL`` is read
(defaults, database selection, timeouts).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit


def connection_kwargs(url: str) -> dict[str, Any]:
    """``redis.Redis(**kwargs)`` arguments for *url*, with safe defaults."""
    parts = urlsplit(url)
    path = str(parts.path or "/0")
    return {
        "host": str(parts.hostname or "localhost"),
        "port": int(parts.port or 6379),
        "db": int(path.lstrip("/")) or 0,
        "socket_connect_timeout": 2,
        "socket_timeout": 2,
    }
