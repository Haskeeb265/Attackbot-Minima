"""Host/IP canonicalization and subdomain arithmetic — the shared identity layer.

Extracted verbatim from the names pipeline's ``passive/normalize.py`` (where
these rules were built and measured) so every pipeline — names, ports, URLs,
network ownership — normalizes the same way.  A host here and a subdomain
there cannot disagree, and an IP cannot have two spellings.

The pipeline-local copy keeps its own additions (domain extraction, wildcard
helpers); this module is the subset every consumer needs:

- :func:`canonicalize_host` — lowercased, IDNA, trailing dot stripped, or None
- :func:`is_subdomain_of`   — scope arithmetic
- :func:`is_ip_literal`     — host-shaped-but-really-an-address detection
- :func:`canonicalize_ip`   — IPv4/IPv6 text to canonical form, or None
- :func:`is_scannable`      — globally-routable check used by the scope gate
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

_HOST_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def canonicalize_host(value: str) -> str | None:
    """Canonical text for a hostname, or ``None`` when it is not one.

    Lowercases, strips one trailing dot, validates label shapes, and accepts
    IP literals unchanged (lowercased) — callers that need hostname-only
    semantics check :func:`is_ip_literal` afterwards.
    """
    raw = (value or "").strip().rstrip(".").lower()
    if not raw or len(raw) > 253:
        return None
    if is_ip_literal(raw):
        return raw
    labels = raw.split(".")
    if any(not _HOST_LABEL.match(label) for label in labels):
        return None
    if all(label.isdigit() for label in labels) and len(labels) == 4:
        return None  # looks like a dotted quad but failed ip validation
    return raw


def is_ip_literal(host: str) -> bool:
    """True when *host* is an IPv4 dotted quad or bracketed/plain IPv6."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if host.startswith("[") and host.endswith("]"):
        try:
            ipaddress.ip_address(host[1:-1])
            return True
        except ValueError:
            return False
    return False


def is_subdomain_of(host: str, apex: str) -> bool:
    """True when *host* equals *apex* or lives underneath it.

    Both are canonicalized first; a dot-prefixed match is required so
    ``notexample.com`` is not ``example.com``.
    """
    canonical_host = canonicalize_host(host)
    canonical_apex = canonicalize_host(apex)
    if canonical_host is None or canonical_apex is None:
        return False
    return canonical_host == canonical_apex or canonical_host.endswith(
        f".{canonical_apex}"
    )


def canonicalize_ip(value: str) -> str | None:
    """Canonical text for an IPv4/IPv6 address, or ``None``."""
    raw = (value or "").strip()
    if not raw:
        return None
    raw = raw.strip("[]")
    if raw.startswith("http"):
        try:
            raw = urlsplit(raw).hostname or ""
        except ValueError:
            return None
    if not raw:
        return None
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return None


def is_scannable(value: str) -> bool:
    """True for globally-routable unicast addresses (the scope gate's floor)."""
    canonical = canonicalize_ip(value)
    if canonical is None:
        return False
    address = ipaddress.ip_address(canonical)
    if not address.is_global:
        return False
    return not (
        address.is_multicast
        or address.is_reserved
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
    )
