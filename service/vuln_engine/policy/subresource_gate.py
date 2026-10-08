"""The subresource gate: no browser subrequest leaves without a scope check.

The chokepoint invariant (master ref §3) says every *packet* passes the gate.
Until now the gate decided the navigation URL, and once the page loaded it
could fire scripts, iframes, XHR, fonts and redirects to hosts no one had
decided on. This module closes that hole. Chosen over a full per-subresource
``EffectRequest`` round-trip: per-frame gate calls split one page's request
stream into pieces the log cannot reassemble and pay one dispatcher decision per
font. The strict allowlist here, scoped to the *already-decided* navigation
origin (plus companions the operator declared), is functionally identical for
every subrequest the gate would ALLOW anyway, and it turns every other
subrequest into a logged, abort-before-the-socket refusal — which is the
invariant's whole promise, kept without doubling the decision cost.

A companion host the operator declared beside the target is authorized on
purpose (for example an OOB collaborator the fixture's own pages reference);
everything else is refused with the declared reason, and the refusals land in
the run's own world log through the transport that owned the page.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from urllib.parse import urlsplit

#: The refusal the transport records for every subrequest the allowlist stops.
SUBRESOURCE_REFUSAL_REASON = (
    "subresource blocked: the page requested a resource on {host}, which the "
    "policy gate never decided on (browser subrequests stay on the navigation "
    "origin and its declared companions)"
)

#: The row type the run's own world log carries for each blocked request. The
#: ``policy.log`` module owns the ``EVENT_*`` namespace; this constant is
#: exported by it (see ``policy/__init__`` wiring) so this module need not
#: import a transport-side module to name the row.
EVENT_SUBRESOURCE_BLOCKED = "transport.subresource_blocked"

#: Re-exported alias, the spelling the policy log module pins (kept identical so
#: a row written here and a row asserted on in tests can never drift).
EVENT_SUBRESOURCE_BLOCKED_SENTINEL = EVENT_SUBRESOURCE_BLOCKED


def host_of(url: str) -> str:
    """The hostname of a request URL, lowercased, or \"\" for anything unparseable."""
    try:
        hostname = urlsplit(url.strip()).hostname
    except ValueError:
        return ""
    return (hostname or "").strip().lower()


def _normalize_host(value: Iterable[str] | str) -> set[str]:
    """One lowercase set from a host, a list of hosts, or an empty iterable."""
    if isinstance(value, str):
        candidates: list[str] = [value]
    else:
        candidates = [str(item) for item in value]
    hosts: set[str] = set()
    for candidate in candidates:
        candidate = candidate.strip().lower()
        if candidate:
            hosts.add(candidate)
    return hosts


class SubresourceGate:
    """Keeps browser subrequests on hosts the policy gate already decided on.

    ``navigation_origin`` is the target host of the page being loaded. It is
    always allowed. Companion hosts the operator declared beside the target are
    allowed too (the caller wires them explicitly). Everything else — scripts,
    iframes, XHR, fonts, redirects — is refused before it leaves the browser:
    the gate returns False, records the refusal through the injected ``log``
    callback (the transport's world-log handle), and counts it so a test can
    assert on the count without re-reading rows.
    """

    def __init__(
        self,
        navigation_origin: str | Iterable[str],
        *,
        allowed_companions: Iterable[str] | str = (),
        log: Callable[[str, dict], None] | None = None,
        now: Callable[[], str] | None = None,
    ) -> None:
        self._allowed = _normalize_host(navigation_origin)
        self._allowed |= _normalize_host(allowed_companions)
        self._log = log or (lambda _kind, _payload: None)
        self._now = now or self._iso_now
        # Counted per instance so a caller can assert on them without re-reading
        # rows (which the caller's own log handle owns).
        self.blocked: list[str] = []

    def decide(self, url: str) -> bool:
        """True when the page may send *url*; False (and logged) otherwise."""
        host = host_of(url)
        if host and host in self._allowed:
            return True
        self.blocked.append(url)
        self._log(
            EVENT_SUBRESOURCE_BLOCKED,
            {
                "url": url,
                "host": host,
                "reason": SUBRESOURCE_REFUSAL_REASON.format(host=host or "unparseable"),
                "at": self._now(),
            },
        )
        return False

    @property
    def blocked_urls(self) -> list[str]:
        return list(self.blocked)

    @staticmethod
    def _iso_now() -> str:
        import datetime

        return datetime.datetime.now(datetime.timezone.utc).isoformat()


__all__ = [
    "EVENT_SUBRESOURCE_BLOCKED",
    "EVENT_SUBRESOURCE_BLOCKED_SENTINEL",
    "SUBRESOURCE_REFUSAL_REASON",
    "SubresourceGate",
    "host_of",
]
