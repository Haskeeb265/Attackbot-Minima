"""The provider registry: the three host patterns, and who verifies what.

One row per cloud-storage family.  A *claim* is any string a sibling artifact
produced that matches one of these host patterns; a *probe* is the single GET
:mod:`verify` sends to settle whether the name exists.  The pattern set is the
whole passive-phase detection surface, so it is data, not code: adding a
provider means adding a row, and the tests assert the registry stays
self-consistent.

The verdict semantics live in :mod:`verify`; this module only knows shapes.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

# --------------------------------------------------------------------------- #
# Provider families
# --------------------------------------------------------------------------- #

PROVIDER_S3 = "s3"
PROVIDER_AZURE = "azure"
PROVIDER_GCS = "gcs"

#: All providers, in probe order (S3 first: the most claims, the oldest quirk).
ALL_PROVIDERS: tuple[str, ...] = (PROVIDER_S3, PROVIDER_AZURE, PROVIDER_GCS)


@dataclass(frozen=True)
class Provider:
    """One cloud-storage family: its claim patterns and its probe URL shape."""

    name: str
    #: Host patterns a sibling artifact's host/CNAME/URL can match.  Each ``*``
    #: matches one label; the FIRST ``*`` is the bucket/account capture.
    #: Matched case-insensitively; trailing dots are ignored (CNAME form).
    patterns: tuple[str, ...]
    #: ``{name}`` is substituted with the candidate to build the probe URL.
    probe_template: str
    #: Whether dotted names are legal for this family (S3: yes; Azure/GCS: no).
    dots_allowed: bool = False

    def probe_url(self, name: str) -> str:
        return self.probe_template.format(name=name)


#: The registry.  Pattern notes:
#:
#: * S3 — the legacy global endpoint (``s3.amazonaws.com``) plus the
#:   region-style spelling (``s3.<region>.amazonaws.com``), which CNAMEs and
#:   URLs both carry.  The first ``*`` captures the bucket name in both.
#: * Azure — the account-shaped host; the container is not modelled in P1
#:   (DESIGN.md §7).
#: * GCS — the one canonical host.
PROVIDERS: dict[str, Provider] = {
    PROVIDER_S3: Provider(
        name=PROVIDER_S3,
        patterns=(
            "*.s3.amazonaws.com",
            "*.s3.*.amazonaws.com",
        ),
        probe_template="https://{name}.s3.amazonaws.com/",
    ),
    PROVIDER_AZURE: Provider(
        name=PROVIDER_AZURE,
        patterns=("*.blob.core.windows.net",),
        probe_template="https://{name}.blob.core.windows.net/",
    ),
    PROVIDER_GCS: Provider(
        name=PROVIDER_GCS,
        patterns=("*.storage.googleapis.com",),
        probe_template="https://{name}.storage.googleapis.com/",
    ),
}


def _host_of(value: str) -> str:
    """The host of a URL, or the value itself when it is a bare host/CNAME."""
    value = (value or "").strip().lower().rstrip(".")
    if "://" in value:
        host = urlparse(value).hostname or ""
        return host.rstrip(".")
    if "/" in value:
        value = value.split("/", 1)[0]
    if "@" in value:  # userinfo paranoia — never a bucket name
        value = value.rsplit("@", 1)[1]
    return value.strip()


def _pattern_name(pattern: str, host: str) -> str | None:
    """The first-``*`` capture of *host* against *pattern*, or ``None``.

    Every ``*`` in the pattern matches exactly one label, so the capture is
    itself one label: ``acme.s3.eu-west-1.amazonaws.com`` captures ``acme``
    against ``*.s3.*.amazonaws.com``; ``a.b.s3.amazonaws.com`` claims nothing.
    """
    pattern = pattern.lower().rstrip(".")
    parts = pattern.split("*")
    if len(parts) < 2:
        return None
    head, tail = parts[0], parts[-1]
    mids = parts[1:-1]
    if len(host) <= len(head) + len(tail):
        return None
    if not host.startswith(head) or not host.endswith(tail):
        return None
    remainder = host[len(head): len(host) - len(tail) if tail else len(host)]
    # Consume the interior segments from the right, leaving the first gap as
    # the capture (the bucket/account label).
    for mid in reversed(mids):
        if not mid:
            continue
        index = remainder.rfind(mid)
        if index == -1:
            return None
        remainder = remainder[:index]
    if not remainder or "." in remainder:
        return None
    return remainder


def match_provider(value: str) -> list[tuple[str, str]]:
    """Every ``(provider, name)`` claim inside *value*.

    *value* may be a bare host (``acme.s3.amazonaws.com``), a CNAME target, or
    a full URL (``https://acme.storage.googleapis.com/…``).  At most one claim
    per provider — a value matching several of one family's patterns (global
    and region-style S3 hosts are mutually exclusive in practice, but a
    trailing-dot spelling would otherwise double-report) yields one claim.
    """
    host = _host_of(value)
    if not host or "*" in host:
        return []
    claims: list[tuple[str, str]] = []
    for provider in ALL_PROVIDERS:
        for pattern in PROVIDERS[provider].patterns:
            name = _pattern_name(pattern, host)
            if name:
                claims.append((provider, name))
                break  # one claim per provider family
    return claims


def is_provider_host(value: str) -> bool:
    """True when *value* is (or contains a URL whose host is) a provider host."""
    return bool(match_provider(value))
