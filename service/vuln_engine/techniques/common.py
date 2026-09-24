"""Shared pure helpers for techniques — the folder's ``common``.

One function, and it is here rather than duplicated in each technique folder
because building a parameterised URL is the one piece of arithmetic every
parameterised technique needs, and two copies of it would eventually disagree
about encoding.

It is *not* a home for technique logic. Each technique still owns its own
hypotheses, probes and interpretation; if something here started to know what a
vulnerability is, the contract would be leaking.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

from ..kernel.technique import Surface


# --------------------------------------------------------------------------- #
# DOM placement markers (the xss_dom contract's shared spelling)
# --------------------------------------------------------------------------- #

#: Marker-name prefix that separates *placement* answers from *execution*
#: markers on the browser transport's one boolean channel. A placement marker is
#: named ``dom:<mark>:<question>`` and its answer is read as a **context name
#: string**, not a boolean; every other marker stays a plain boolean predicate.
#: The prefix exists so the observation layer can tell the two families apart by
#: name — the transport stays deliberately dumb and coercing.
DOM_MARKER_PREFIX = "dom:"

#: The questions a placement probe asks the DOM, as marker-name suffixes. Every
#: question is a **boolean predicate** — the transport's marker channel coerces
#: answers to bool, so a placement is established by which questions answer
#: true, never by a string the channel would have flattened. The probe grammar
#: and the observation layer agree on these strings; a renamed question is a
#: breaking change to both, which the invariant test pins.
DOM_Q_PRESENT = "present"
DOM_Q_TEXT = "text"
DOM_Q_ATTR = "attr"
DOM_Q_URLATTR = "urlattr"
DOM_Q_HTML = "html"
DOM_Q_SCRIPT = "script"


def dom_marker(mark: str, question: str) -> str:
    """The placement marker name for *mark*'s answer to *question*."""
    return f"{DOM_MARKER_PREFIX}{mark}:{question}"


def surface_id_prefix(name: str, surface: Surface) -> str:
    """The candidate/hypothesis id prefix for *name* on *surface*.

    ``name`` + host + path (+ query, when the surface carries a fixed one) +
    param — the host appears exactly once, so an id reads
    ``xss_reflected:127.0.0.1:/search:q`` instead of spelling the host twice.
    Every technique derives its ids through this one helper: a spelling this
    widespread is one drift away from two candidates sharing an id, which is
    the bug class the per-context suffixes already caught once.
    """
    parts = urlsplit(surface.url)
    tail = parts.path or "/"
    if parts.query:
        tail = f"{tail}?{parts.query}"
    return f"{name}:{surface.host}:{tail}:{surface.param}"


def with_parameter(url: str, param: str, value: str) -> str:
    """*url* with *param* set to *value*, replacing any existing value.

    The value is percent-encoded, which matters more than it looks: these payloads
    are deliberately full of quotes and angle brackets, and a payload that arrives
    mangled is indistinguishable from a target that sanitised it — the exact false
    lead the observation layer exists to prevent. The server decodes what we
    escaped, so the reflection still contains the raw characters we meant.
    """
    parts = urlsplit(url)
    pairs = [
        (key, item)
        for key, item in parse_qsl(parts.query, keep_blank_values=True)
        if key != param
    ]
    pairs.append((param, value))
    query = "&".join(f"{quote(key, safe='')}={quote(item, safe='')}" for key, item in pairs)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


__all__ = [
    "DOM_MARKER_PREFIX",
    "DOM_Q_ATTR",
    "DOM_Q_HTML",
    "DOM_Q_PRESENT",
    "DOM_Q_SCRIPT",
    "DOM_Q_TEXT",
    "DOM_Q_URLATTR",
    "dom_marker",
    "surface_id_prefix",
    "with_parameter",
]
