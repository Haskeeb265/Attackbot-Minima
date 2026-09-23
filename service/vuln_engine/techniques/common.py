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


__all__ = ["with_parameter"]
