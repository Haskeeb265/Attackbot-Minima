#!/usr/bin/env python3
"""A deliberately vulnerable fixture app, for Phase 1's evaluation harness.

Standard library only, on purpose: this is a *measuring instrument*, not a
product. It has no dependencies to drift, no framework to configure, and nothing
to explain beyond the two endpoints below. A fixture with a supply chain would be
a fixture that can fail for reasons unrelated to the engine.

Two vulnerabilities, one per Phase 1 technique, and one per Phase 2's:

``GET /search?q=``
    Reflects *q* unescaped into a **double-quoted attribute** value:
    ``<input type="text" name="q" value="{q}">``.  The reflection is deliberately
    singular and deliberately in one context, so the observation layer's answer is
    predictable and a failure is unambiguously a bug in the engine rather than
    ambiguity in the fixture. There is no CSP header: a real target's would be
    part of the finding, and a fixture that blocked execution would prove nothing.

``GET /fetch?url=``
    Fetches a caller-supplied URL server-side and returns the body.  This is the
    blind class: the *only* acceptable proof is our collaborator recording the
    request, because the response body can be produced by a cache, a proxy, or a
    reflection instead of an actual fetch.

``GET /delay?q=``
    Phase 2's blind SQLi stand-in: sleeps *SLEEP_MARKER* seconds when the
    parameter's value contains the marker substring. A stand-in on purpose — the
    technique's probe grammar is pure data and does not care whether the server
    slept because of SQL ``pg_sleep`` or a fixture branch; what it tests is the
    differential: the same surface answering on two populations, with the margin
    the verifier requires. The sleep is capped so a hostile value cannot pin a
    worker.

The app is only ever reachable from the compose network and the host. It is
scoped like any other target — see ``tests/vuln_engine/eval/test_phase1.py`` and
the note in ``docs/vuln_engine_docs/phase1_checklist.md`` item 12: the fixture is
in scope **because it is declared**, never because the gate was bypassed.
"""

from __future__ import annotations

import logging
import os
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PORT = int(os.getenv("FIXTURE_PORT", "8080"))
#: How long the fixture waits on a caller-supplied URL.  Real, so an unreachable
#: collaborator is a slow failure rather than a hang.
FETCH_TIMEOUT = float(os.getenv("FIXTURE_FETCH_TIMEOUT", "10"))

#: The ``/delay`` endpoint's marker and its ceiling.  The marker is deliberately
#: trivial to pass (a substring test, like a naive ``LIKE`` clause) and the sleep
#: is capped like a real target's statement timeout would be.
SLEEP_MARKER = os.getenv("FIXTURE_SLEEP_MARKER", "ve-sleep")
SLEEP_SECONDS = float(os.getenv("FIXTURE_SLEEP_SECONDS", "2.0"))
SLEEP_CEILING = 5.0

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("fixture_app")

#: The search page.  ``{q}`` is substituted with the raw parameter — this is the
#: whole vulnerability, and it is one line so nobody has to go looking for it.
PAGE = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Fixture app</title></head>
<body>
  <h1>Search</h1>
  <form action="/search" method="get">
    <input type="text" name="q" value="{q}">
    <button type="submit">Go</button>
  </form>
  <p>Nothing was searched; this page exists to reflect a parameter.</p>
</body>
</html>
"""


class FixtureHandler(BaseHTTPRequestHandler):
    """The two vulnerable endpoints plus a health check."""

    server_version = "fixture_app/0.1"
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's spelling
        parts = urlsplit(self.path)
        params = parse_qs(parts.query, keep_blank_values=True)
        if parts.path == "/healthz":
            self._send(200, b"ok", "text/plain; charset=utf-8")
            return
        if parts.path == "/search":
            self._search(params)
            return
        if parts.path == "/fetch":
            self._fetch(params)
            return
        if parts.path == "/delay":
            self._delay(params)
            return
        self._send(404, b"not found", "text/plain; charset=utf-8")

    def _search(self, params: dict[str, list[str]]) -> None:
        """Reflect *q* into the page, in a double-quoted attribute, unescaped."""
        value = params.get("q", [""])[0]
        body = PAGE.replace("{q}", value).encode("utf-8", errors="replace")
        log.info("search q=%r", value)
        self._send(200, body, "text/html; charset=utf-8")

    def _fetch(self, params: dict[str, list[str]]) -> None:
        """Fetch a caller-supplied URL server-side and return what came back."""
        target = params.get("url", [""])[0]
        if not target:
            self._send(400, b"url is required", "text/plain; charset=utf-8")
            return
        log.info("fetch url=%r", target)
        try:
            with urllib.request.urlopen(target, timeout=FETCH_TIMEOUT) as response:  # noqa: S310 - the vulnerability
                body = response.read(65536)
                status = response.status
        except urllib.error.HTTPError as error:
            body = f"upstream status {error.code}".encode("utf-8")
            status = 200
        except Exception as exc:  # noqa: BLE001 - report the failure, do not 500
            self._send(
                502,
                f"fetch failed: {type(exc).__name__}".encode("utf-8"),
                "text/plain; charset=utf-8",
            )
            return
        self._send(status, body, "text/plain; charset=utf-8")

    def _delay(self, params: dict[str, list[str]]) -> None:
        """Sleep when *q* carries the marker; answer fast when it does not.

        The two populations the timing differential compares, in one endpoint.
        The sleep happens *before* the response so the measured elapsed covers it
        exactly the way a slow query would.
        """
        import time as _time

        value = params.get("q", [""])[0]
        if SLEEP_MARKER in value:
            _time.sleep(min(SLEEP_SECONDS, SLEEP_CEILING))
        log.info("delay q=%r", value[:64])
        self._send(200, b"delayed-or-not", "text/plain; charset=utf-8")

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Quiet the default per-request line; the handler logs what matters."""
        return None


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), FixtureHandler)  # noqa: S104 - container-only
    log.info("fixture app listening on %d", PORT)
    server.serve_forever()


if __name__ == "__main__":
    main()
