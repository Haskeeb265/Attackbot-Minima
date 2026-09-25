#!/usr/bin/env python3
"""A deliberately vulnerable fixture app, for Phase 1's evaluation harness.

Standard library only, on purpose: this is a *measuring instrument*, not a
product. It has no dependencies to drift, no framework to configure, and nothing
to explain beyond the endpoints below. A fixture with a supply chain would be
a fixture that can fail for reasons unrelated to the engine.

One endpoint per technique, each the way a real target ships the bug:

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
    Phase 2's blind SQLi stand-in: simulates an injectable backend by *parsing*
    the parameter for a ``SLEEP(n)`` expression and sleeping ``n`` seconds
    (capped). The delay travels in the payload — the way a real SQL engine's
    ``SLEEP()`` works — so the endpoint answers a payload *family* rather than
    a magic substring: whatever SQL-shaped value arrives is interpreted on its
    own terms, and a value with no parseable expression returns fast. What the
    technique tests is the differential: the same surface answering on two
    populations, with the margin the verifier requires. The sleep is capped so
    a hostile value cannot pin a worker.

``GET /dom?q=``
    Phase 4's client-render fixture: the server reflects *nothing* (the wire
    lens must honestly see no reflection here) — the page's own JavaScript
    reads ``q`` from ``location.search`` and writes it into ``innerHTML`` after
    load. This is the SPA-shaped vulnerability the Juice Shop breadth test
    measured our lens blind to: the payload exists only in the DOM, so only the
    DOM placement lens (``techniques/xss_dom``) can propose, and only a browser
    run can confirm, a finding here.

``POST /comment`` + ``GET /comments``
    The stored-XSS pair: the POST *stores* ``text`` (ignoring the submission entirely when the form's
    ``sign`` companion field is absent — the way DVWA's guestbook ignores a POST without its submit button, which is why ``companions`` exists as a declared surface field); the GET *renders* every stored comment raw. The
    vulnerability is the two pages together: the store accepts anything, the
    read-back escapes nothing, and neither page alone is the bug. The store is
    in memory and dies with the process, which is correct for a fixture: each
    run starts empty, so a stale entry can never impersonate this round's
    evidence.

``GET /api/invoices/<id>``
    The IDOR fixture: an object whose access *should* depend on the session's
    role, and does not. Identity travels exactly as it does on a real target —
    the ``session`` cookie, resolved against a session store with two seeded
    identities (``a1b2c3d4e5f6`` = admin, ``9f8e7d6c5b4a`` = user). The access
    check verifies **authentication** only — it never asks whether the role
    may read an invoice — so the known low-privilege session reads the object
    it must not, the canonical confusion real authorization bugs ship with.
    Unknown sessions fail closed, so only a genuinely authenticated low-priv
    session can produce the differential. No body differences, no markers —
    the status code is the only signal, which is exactly the measurement
    ``idor_differential`` compares.

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

#: The ``/comment`` store's capacity ceiling. A fixture that accepted unbounded
#: submissions would let one noisy run pin its memory; a real target's storage
#: quota imposes the same shape of limit.
COMMENT_CAP = 64

#: The ``/delay`` endpoint's ceiling. The delay itself comes from the payload
#: (a ``SLEEP(n)`` expression, parsed like a backend would parse one), so a
#: heavier family does not need fixture changes — only the cap, which a real
#: target's statement timeout would impose too.
SLEEP_CEILING = float(os.getenv("FIXTURE_SLEEP_CEILING", "6.0"))

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("fixture_app")

#: The client-render page for ``/dom``: the server's bytes never contain the
#: parameter, and the page's script writes the raw parameter into innerHTML —
#: a sink, the way an SPA's search result container is.
DOM_PAGE = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Fixture DOM</title></head>
<body>
  <h1>Client-rendered search</h1>
  <div id="result"></div>
  <script>
    (function () {
      var q = new URLSearchParams(location.search).get("q") || "";
      document.getElementById("result").innerHTML = q;
    })();
  </script>
</body>
</html>
"""

#: The read-back page for stored comments. ``{entries}`` is substituted with
#: the raw concatenation of every stored comment — no escaping anywhere, which
#: is the vulnerability the stored technique proves.
COMMENTS_PAGE = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Fixture comments</title></head>
<body>
  <h1>Comments</h1>
  <ul id="comments">{entries}</ul>
</body>
</html>
"""

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
    """The vulnerable endpoints plus a health check."""

    server_version = "fixture_app/0.1"
    protocol_version = "HTTP/1.1"

    #: The stored comments. In memory, per process — see the module docstring
    #: for why per-process state is correct for a fixture.
    comments: list[str] = []

    #: The session store: session id -> role. Seeded with two identities, the
    #: way a demo deployment ships with its two test accounts. The "sessions"
    #: live here; the client carries only ``session=<id>``.
    sessions: dict[str, str] = {
        "a1b2c3d4e5f6": "admin",
        "9f8e7d6c5b4a": "user",
    }

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
        if parts.path == "/dom":
            self._dom()
            return
        if parts.path == "/comments":
            self._comments()
            return
        if parts.path.startswith("/api/invoices/"):
            self._invoice(parts.path)
            return
        self._send(404, b"not found", "text/plain; charset=utf-8")

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's spelling
        parts = urlsplit(self.path)
        if parts.path == "/comment":
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
            self._comment(parse_qs(body, keep_blank_values=True))
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
        """Sleep when *q* carries a parseable ``SLEEP(n)`` expression.

        The two populations the timing differential compares, in one endpoint:
        a value whose SQL the simulated backend parses delays the response by
        the delay *it asks for*; a value with no parseable expression returns
        fast. The delay travels in the payload, so this endpoint exercises the
        technique's payload family rather than a marker it was handed.
        """
        import re as _re
        import time as _time

        value = params.get("q", [""])[0]
        match = _re.search(r"SLEEP\((\d+(?:\.\d+)?)\)", value)
        if match:
            _time.sleep(min(float(match.group(1)), SLEEP_CEILING))
        log.info("delay q=%r", value[:64])
        self._send(200, b"delayed-or-not", "text/plain; charset=utf-8")

    def _dom(self) -> None:
        """Serve the client-render page: identical bytes for every ``q``.

        The server response is deliberately parameter-independent — the whole
        point of the endpoint is that the reflection the wire lens looks for
        does not exist. The vulnerability lives entirely in the page's
        client-side code, the way an SPA's does. The script runs on load, so a
        browser probe that waits for settle sees the rendered DOM.
        """
        log.info("dom page (parameter-independent response)")
        self._send(200, DOM_PAGE.encode("utf-8"), "text/html; charset=utf-8")

    def _comment(self, params: dict[str, list[str]]) -> None:
        """Store *text* when the submission speaks the form's protocol.

        The ``sign`` field is the form's submit button: a POST without it is
        ignored, exactly as DVWA's guestbook ignores one without ``btnSign``.
        That is the trap ``Surface.companions`` exists for — a technique that
        posted only its payload would read the silence as "nothing stored"
        when the truth is "nothing submitted". Stored raw, capped, no escaping:
        the escaping absence on the read-back page is the vulnerability.
        """
        if "sign" not in params:
            log.info("comment ignored (no sign field)")
            self._send(400, b"submission lacks the form's sign field", "text/plain; charset=utf-8")
            return
        text = params.get("text", [""])[0]
        if text:
            FixtureHandler.comments.append(text)
            del FixtureHandler.comments[:-COMMENT_CAP]
        log.info("comment stored (%d total)", len(FixtureHandler.comments))
        self._comments()

    def _comments(self) -> None:
        """Render every stored comment raw — the read-back half of the bug.

        One page, every entry, no escaping: the store is not the vulnerability,
        this rendering is, and keeping the two endpoints distinct is what makes
        the technique's two-page shape exercisable at all.
        """
        entries = "".join(
            f"<li>{comment}</li>" for comment in FixtureHandler.comments
        )
        body = COMMENTS_PAGE.replace("{entries}", entries).encode("utf-8", errors="replace")
        self._send(200, body, "text/html; charset=utf-8")

    def _invoice(self, path: str) -> None:
        """Answer an invoice read under the caller session's role.

        The identity travels the way it does on a real target — the ``session``
        cookie, resolved against the session store — and the check is broken
        the way real checks break: it verifies **authentication** (is the
        session known?) and never asks the **authorization** question (is this
        role allowed to read an invoice?). Both seeded identities pass, so the
        low-privilege session reads the object it must not. Unknown sessions
        fail closed (403), deliberately: a missing or typo'd session cookie
        can never fabricate the differential — only a genuinely authenticated
        low-priv session reading the object produces it. No body differences,
        no markers: the status code is the only signal, which is exactly the
        measurement ``idor_differential`` compares.
        """
        cookies: dict[str, str] = {}
        for pair in (self.headers.get("Cookie") or "").split(";"):
            name, _, value = pair.partition("=")
            if name.strip():
                cookies[name.strip()] = value.strip()
        invoice_id = path.rsplit("/", 1)[-1]
        role = self.sessions.get(cookies.get("session", ""))
        if role is not None:  # the bug: authenticated was mistaken for authorized
            log.info("invoice %s served to role=%r", invoice_id, role)
            body = (
                '{"invoice": "' + invoice_id + '", "owner": "alice", "total": 412.50}'
            ).encode("utf-8")
            self._send(200, body, "application/json")
            return
        log.info("invoice %s denied (role=%r)", invoice_id, role)
        self._send(403, b"{\"error\": \"forbidden\"}", "application/json")

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
