"""The exposed-mode bearer token: an auth requirement, and none on loopback.

``--expose`` lifts the loopback-only bind, and everything on the other side of
the socket is then reachable by whoever can route to it — the UI starts jobs
with the host's authority, so exposing it without an identity check is a
remote code execution as a config option. This module is the check:

* the expected token is set once at startup (``UiHandler.auth_token``);
* every request is checked (read side too — the artifacts are the engagement's
  own data), via ``Authorization: Bearer <token>``;
* the comparison is ``hmac.compare_digest`` so timing cannot walk the token;
* no token configured means no check — which is the loopback default, and the
  server refuses to bind non-loopback without a token (see ``server.main``).
"""

from __future__ import annotations

import hmac
from http.server import BaseHTTPRequestHandler

AUTH_HEADER = "Authorization"
#: Error body/status a missing-or-wrong token gets; constant so tests can pin
#: the refusal shape.
AUTH_ERROR = "authentication required (an exposed UI needs --auth-token)"
AUTH_STATUS = 401


def extract_bearer(handler: BaseHTTPRequestHandler) -> str:
    """The request's ``Authorization: Bearer`` token, or ``""`` when absent."""
    header = handler.headers.get(AUTH_HEADER, "") if handler.headers else ""
    scheme, _, token = header.partition(" ")
    if scheme.strip().lower() != "bearer":
        return ""
    return token.strip()


def authorized(handler: BaseHTTPRequestHandler, expected: str) -> bool:
    """True when the bearer matches *expected* (constant-time)."""
    if not expected:
        return True  # no token configured: loopback mode, nothing to check
    return hmac.compare_digest(extract_bearer(handler), expected)


__all__ = ["AUTH_ERROR", "AUTH_HEADER", "AUTH_STATUS", "authorized", "extract_bearer"]
