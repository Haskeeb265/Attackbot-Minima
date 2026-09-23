"""The browser transport, driven for real — against a local page and no internet.

This is the one test file in the engine that needs a browser, and it needs it
because the evidence class it produces cannot be faked honestly: "the script
actually ran" is a fact about a real engine, and a test that stubbed it would be
testing the stub. So a stdlib HTTP server serves two pages on loopback, and the
system Chrome (or Playwright's Chromium) is asked about them over CDP.

What it proves, in the engine's own vocabulary:

* a marker expression answering true *is* a script-execution fact;
* a dialog is observed and, crucially, **answered** — an unhandled ``confirm``
  freezes the renderer, so a runner that only watched dialogs would hang on exactly
  the payload it exists to verify;
* a page that runs nothing answers nothing, so the transport is not simply
  returning ``True`` for everything.

Skipped, loudly, when there is no browser at all — see the ``pytestmark``.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from service.vuln_engine.transports.browser import (
    BrowserEffect,
    find_chrome,
    playwright_available,
)

BROWSER_AVAILABLE = bool(find_chrome()) or playwright_available()

pytestmark = pytest.mark.skipif(
    not BROWSER_AVAILABLE,
    reason=(
        "no browser available: install playwright and its chromium, or set CHROME_PATH "
        "to a chrome/chromium binary"
    ),
)

QUIET_PAGE = "<!doctype html><html><body><p>nothing runs here</p></body></html>"
EXEC_PAGE = (
    "<!doctype html><html><body>"
    "<script>window.__ve_test = 1;confirm('vuln-engine-xss');</script>"
    "<p>ran</p></body></html>"
)
MARKER = "window.__ve_test === 1"


class _PageHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - the stdlib's spelling
        body = (EXEC_PAGE if self.path.startswith("/exec") else QUIET_PAGE).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return None


@pytest.fixture(scope="module")
def page_server():
    """A loopback page server for the duration of this module."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PageHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="module")
def effect() -> BrowserEffect:
    return BrowserEffect(timeout=30.0, settle=0.4)


def test_capabilities_name_the_driver_that_will_answer(effect: BrowserEffect) -> None:
    capabilities = effect.capabilities
    assert capabilities.available, capabilities.reason
    assert capabilities.driver in ("cdp", "playwright")
    assert set(capabilities.milestones) == {"script_executed", "dialogs", "dom_mutations"}


def test_a_running_script_is_observed(effect: BrowserEffect, page_server: str) -> None:
    run = effect.run(f"{page_server}/exec", markers={"test": MARKER})
    assert run.ok, run.error
    assert run.markers == {"test": True}
    assert run.driver in ("cdp", "playwright")


def test_the_dialog_is_observed_and_answered(effect: BrowserEffect, page_server: str) -> None:
    run = effect.run(f"{page_server}/exec", markers={"test": MARKER})
    assert ("confirm", "vuln-engine-xss") in run.dialogs


def test_a_page_that_runs_nothing_answers_nothing(effect: BrowserEffect, page_server: str) -> None:
    run = effect.run(f"{page_server}/quiet", markers={"test": MARKER})
    assert run.ok, run.error
    assert run.markers == {"test": False}
    assert run.dialogs == ()


def test_dom_mutations_are_counted(effect: BrowserEffect, page_server: str) -> None:
    run = effect.run(f"{page_server}/quiet", markers={})
    assert run.ok
    assert run.mutations >= 0


def test_an_unavailable_browser_is_a_reported_state_not_an_exception() -> None:
    missing = BrowserEffect(chrome_path="C:/definitely/not/here/chrome.exe", driver="cdp")
    capabilities = missing.capabilities
    run = missing.run("http://127.0.0.1:1/", markers={"m": "true"})
    if capabilities.available:  # a playwright install can still answer
        pytest.skip("playwright answered, so the cdp-only path cannot be exercised")
    assert capabilities.available is False
    assert "CHROME_PATH" in capabilities.reason
    assert run.ok is False
    assert run.error == capabilities.reason
