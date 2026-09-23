"""The instrumented browser: script execution, dialogs, DOM mutation — not pixels.

This is the Phase 1 evidence bar. "The string came back in the HTML" is a lead;
"the script ran and a dialog opened" is a finding, and only an instrumented
browser can tell the difference. Screenshot-level tooling cannot: it can show you
a picture of a dialog box, not record that it opened.

Two drivers, same three facts:

``playwright``
    The documented choice (D1 of the checklist). Uses Playwright's own Chromium
    and its CDP-level event stream. Selected whenever it is importable *and* has
    a browser installed.
``cdp``
    The system Chrome, driven directly over the DevTools Protocol with a
    WebSocket. No new dependency, no browser download, and the same events —
    ``Page.javascriptDialogOpening``, ``Runtime.exceptionThrown``,
    ``Runtime.evaluate`` for the named markers.

The capability report says which driver answered and why, so a run never silently
degrades: ``available: false`` with a reason is the contract, exactly like the
recon side's stealth transports and the LLM junctions.

What the caller gets is a :class:`RawBrowserRun` — dialogs, marker answers,
mutation count. Nothing here decides whether any of that constitutes a finding;
that is the verifier's job (``verification/browser_runner.py``), which never reads
the proposer's reasoning.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..kernel.exchange import RawBrowserRun

NAME = "browser"

DEFAULT_TIMEOUT = 20.0
#: How long the page is given to settle after load before its markers are read.
#: Long enough for an inline script and a queued fetch; short enough that a page
#: which never fires anything does not get paid for twice.
DEFAULT_SETTLE = 0.6

#: Installed before any page script runs, in both drivers, so a mutation during
#: parse is counted.  The engine injects nothing else: the payload under test does
#: its own work, and this only watches.
_MUTATION_INIT = (
    "window.__ve_mutations = 0;"
    "(function(){try{new MutationObserver(function(l){window.__ve_mutations += l.length;})"
    ".observe(document.documentElement||document,{childList:true,subtree:true,"
    "attributes:true,characterData:true});}catch(e){}})();"
)

_MUTATIONS_EXPRESSION = "window.__ve_mutations || 0"

_CANDIDATE_CHROME: tuple[str, ...] = (
    "/Program Files/Google/Chrome/Application/chrome.exe",
    "/Program Files (x86)/Google/Chrome/Application/chrome.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
    "chrome",
)


@dataclass(frozen=True)
class BrowserCapabilities:
    """Which driver will answer, and why."""

    name: str = NAME
    driver: str = ""
    available: bool = False
    reason: str = ""
    executable: str = ""
    #: The three facts this transport promises, named so a caller can see them.
    milestones: tuple[str, ...] = ("script_executed", "dialogs", "dom_mutations")

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "driver": self.driver,
            "available": self.available,
            "reason": self.reason,
            "executable": self.executable,
            "milestones": list(self.milestones),
        }


def find_chrome(explicit: str = "") -> str:
    """Locate a Chrome/Chromium executable; ``""`` when there is none.

    An explicit path wins, then ``CHROME_PATH``, then the usual install
    locations, then ``PATH``. A browser that is *there* beats a browser that must
    be downloaded, because a verification step that cannot run proves nothing.
    """
    if explicit:
        return explicit if Path(explicit).is_file() else ""
    from_env = os.getenv("CHROME_PATH", "")
    if from_env and Path(from_env).is_file():
        return from_env
    for candidate in _CANDIDATE_CHROME:
        if candidate.startswith("/"):
            if os.name == "nt":
                # A leading slash on Windows is *drive-root-relative*: Path.is_file()
                # would resolve it against the cwd (so the check only worked with the
                # project on C:), not against the drive root. Anchor it explicitly.
                local = Path.cwd().anchor + candidate.lstrip("/")
            else:
                local = candidate
            if Path(local).is_file():
                return str(local)
            continue
        found = shutil.which(candidate)
        if found:
            return found
    return ""


def playwright_available() -> bool:
    """True when Playwright can be imported *and* has a browser installed."""
    try:
        # An optional dependency by design (checklist D1): the CDP driver answers
        # when it is absent, so the import failure is a capability answer, not an
        # error.  mypy cannot see the package in this environment.
        from playwright.sync_api import sync_playwright  # type: ignore[import-not-found]
    except Exception:  # noqa: BLE001 - absent is a state, not an error
        return False
    try:
        with sync_playwright() as playwright:
            return Path(playwright.chromium.executable_path).is_file()
    except Exception:  # noqa: BLE001 - package installed, no browser binaries
        return False


# --------------------------------------------------------------------------- #
# driver 1 — Playwright
# --------------------------------------------------------------------------- #


def _run_playwright(
    *,
    url: str,
    markers: dict[str, str],
    headless: bool,
    timeout: float,
    settle: float,
) -> RawBrowserRun:
    """Load *url* in Playwright's Chromium and read the three facts."""
    from playwright.sync_api import sync_playwright

    started = time.monotonic()
    dialogs: list[tuple[str, str]] = []
    console_errors: list[str] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=headless)
        try:
            page = browser.new_page()
            page.add_init_script(_MUTATION_INIT)
            page.on("dialog", _playwright_dialog(dialogs))
            page.on("pageerror", lambda error: console_errors.append(str(error)))
            response = page.goto(url, wait_until="load", timeout=timeout * 1000)
            page.wait_for_timeout(int(settle * 1000))
            answers = {
                name: bool(page.evaluate(expression)) for name, expression in markers.items()
            }
            mutations = int(page.evaluate(_MUTATIONS_EXPRESSION) or 0)
            return RawBrowserRun(
                url=url,
                driver="playwright",
                ok=True,
                status=response.status if response is not None else None,
                final_url=page.url,
                dialogs=tuple(dialogs),
                markers=answers,
                mutations=mutations,
                console_errors=tuple(console_errors),
                elapsed=time.monotonic() - started,
            )
        except Exception as exc:  # noqa: BLE001 - a browser failure is a fact
            return RawBrowserRun(
                url=url,
                driver="playwright",
                ok=False,
                error=f"{type(exc).__name__}: {exc}",
                dialogs=tuple(dialogs),
                console_errors=tuple(console_errors),
                elapsed=time.monotonic() - started,
            )
        finally:
            browser.close()


def _playwright_dialog(dialogs: list[tuple[str, str]]) -> Any:
    """The dialog handler: record it, then accept it.

    Accepting is not politeness — an unanswered dialog freezes the page, so a
    runner that only *observed* dialogs would hang on exactly the payload it
    exists to verify.
    """

    def handle(dialog: Any) -> None:
        dialogs.append((str(dialog.type), str(dialog.message or "")))
        try:
            dialog.accept()
        except Exception:  # noqa: BLE001 - already dismissed
            pass

    return handle


# --------------------------------------------------------------------------- #
# driver 2 — system Chrome over CDP
# --------------------------------------------------------------------------- #


class _CdpConnection:
    """A minimal DevTools Protocol client: send by id, read events as they come.

    Intentionally small. It implements the commands this engine needs
    (``Page.enable``, ``Runtime.enable``, ``Page.navigate``,
    ``Runtime.evaluate``) and one event loop. A full CDP library would be another
    dependency; this is the protocol, not a framework.
    """

    def __init__(self, endpoint: str, timeout: float) -> None:
        from websockets.sync.client import connect

        self._socket = connect(endpoint, open_timeout=timeout, close_timeout=2)
        self._next_id = 1
        self.events: list[dict] = []

    def send(self, method: str, params: dict | None = None) -> int:
        message_id = self._next_id
        self._next_id += 1
        self._socket.send(
            json.dumps({"id": message_id, "method": method, "params": params or {}})
        )
        return message_id

    def pump(self, *, until: int | None = None, timeout: float = 0.5) -> dict | None:
        """Read until *until*'s reply arrives; buffer events as they are seen.

        Returns the reply, or ``None`` when the wait ran out — a quiet page is
        normal, not an error.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                raw = self._socket.recv(timeout=max(0.01, deadline - time.time()))
            except TimeoutError:
                return None
            except Exception as exc:  # noqa: BLE001 - a closed socket ends the wait
                raise ConnectionError(str(exc)) from exc
            try:
                message = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                continue
            if "method" in message:
                self.events.append(message)
                self._auto_answer(message)
                continue
            if until is None or message.get("id") == until:
                return message
        return None

    def drain(self, timeout: float = 0.4) -> None:
        """Read for a while, buffering whatever the page does."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                self.pump(timeout=max(0.01, deadline - time.time()))
            except ConnectionError:
                return

    def _auto_answer(self, message: dict) -> None:
        """Accept a dialog the moment it opens (see ``_playwright_dialog``)."""
        if message.get("method") != "Page.javascriptDialogOpening":
            return
        try:
            self.send("Page.handleJavaScriptDialog", {"accept": True})
        except Exception:  # noqa: BLE001 - the dialog is already gone
            pass

    def close(self) -> None:
        try:
            self._socket.close()
        except Exception:  # noqa: BLE001
            pass


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _http_json(url: str, *, method: str = "GET", timeout: float = 1.0) -> Any:
    """A DevTools HTTP call (``/json/version``, ``/json/new``, ``/json/list``)."""
    import httpx

    try:
        response = httpx.request(method, url, timeout=timeout)
    except Exception:  # noqa: BLE001 - still starting up
        return None
    if response.status_code >= 400:
        return None
    try:
        return response.json()
    except (json.JSONDecodeError, ValueError):
        return None


def _chrome_flags(port: int, profile: Path) -> list[str]:
    return [
        "--headless=new",
        f"--remote-debugging-port={port}",
        f"--user-data-dir={profile}",
        "--remote-allow-origins=*",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        "--disable-gpu",
        "--disable-background-networking",
        "--disable-sync",
        "--window-size=1280,900",
        "about:blank",
    ]


def _wait_for_target(port: int, timeout: float) -> str:
    """Open a fresh page target and return its WebSocket endpoint."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if isinstance(_http_json(f"http://127.0.0.1:{port}/json/version"), dict):
            created = _http_json(f"http://127.0.0.1:{port}/json/new?about:blank", method="PUT")
            endpoint = str(created.get("webSocketDebuggerUrl", "")) if isinstance(created, dict) else ""
            if not endpoint:
                targets = _http_json(f"http://127.0.0.1:{port}/json/list")
                if isinstance(targets, list):
                    for item in targets:
                        if isinstance(item, dict) and item.get("type") == "page":
                            endpoint = str(item.get("webSocketDebuggerUrl", ""))
                            break
            if endpoint:
                return endpoint
        time.sleep(0.15)
    return ""


def _stop(process: "subprocess.Popen[bytes]", profile: Path) -> None:
    """Terminate the browser and clean up the throwaway profile."""
    try:
        process.terminate()
        process.wait(timeout=5)
    except Exception:  # noqa: BLE001 - it may already be gone
        try:
            process.kill()
        except Exception:  # noqa: BLE001
            pass
    shutil.rmtree(profile, ignore_errors=True)


def _describe_exception(event: dict) -> str:
    details = event.get("params", {}).get("exceptionDetails", {})
    text = details.get("exception", {}).get("description") or details.get("text", "")
    return str(text or "exception")


def _run_cdp(
    *,
    url: str,
    markers: dict[str, str],
    executable: str,
    headless: bool,
    timeout: float,
    settle: float,
) -> RawBrowserRun:
    """Load *url* in the system Chrome and read the three facts over CDP."""
    started = time.monotonic()
    if not executable:
        return RawBrowserRun(url=url, driver="cdp", ok=False, error="no chrome executable")
    port = _free_port()
    profile = Path(tempfile.mkdtemp(prefix="vuln-engine-chrome-"))
    flags = _chrome_flags(port, profile)
    if not headless:
        flags = [flag for flag in flags if flag != "--headless=new"]
    process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        [executable, *flags],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    connection: _CdpConnection | None = None
    try:
        endpoint = _wait_for_target(port, timeout)
        if not endpoint:
            return RawBrowserRun(
                url=url,
                driver="cdp",
                ok=False,
                error="chrome did not expose a DevTools target in time",
                elapsed=time.monotonic() - started,
            )
        connection = _CdpConnection(endpoint, timeout)
        connection.send("Page.enable")
        connection.send("Runtime.enable")
        connection.send("Page.addScriptToEvaluateOnNewDocument", {"source": _MUTATION_INIT})
        navigate = connection.send("Page.navigate", {"url": url})
        # The page's own inline script runs during parse, so dialogs and markers
        # are read after the load event rather than after navigate's reply.
        _await_load(connection, navigate, timeout)
        connection.drain(settle)

        dialogs = tuple(
            (str(event["params"].get("type", "")), str(event["params"].get("message", "")))
            for event in connection.events
            if event.get("method") == "Page.javascriptDialogOpening"
        )
        console_errors = tuple(
            _describe_exception(event)
            for event in connection.events
            if event.get("method") == "Runtime.exceptionThrown"
        )
        answers = {name: _evaluate(connection, expression) for name, expression in markers.items()}
        final_url = ""
        for event in connection.events:
            if event.get("method") == "Page.frameNavigated":
                final_url = str(event.get("params", {}).get("frame", {}).get("url", "")) or final_url
        return RawBrowserRun(
            url=url,
            driver="cdp",
            ok=True,
            final_url=final_url,
            dialogs=dialogs,
            markers=answers,
            mutations=_evaluate_number(connection, _MUTATIONS_EXPRESSION),
            console_errors=console_errors,
            elapsed=time.monotonic() - started,
        )
    except Exception as exc:  # noqa: BLE001 - the browser failing is a fact
        return RawBrowserRun(
            url=url,
            driver="cdp",
            ok=False,
            error=f"{type(exc).__name__}: {exc}",
            elapsed=time.monotonic() - started,
        )
    finally:
        if connection is not None:
            connection.close()
        _stop(process, profile)


def _await_load(connection: _CdpConnection, navigate_id: int, timeout: float) -> None:
    """Wait for the load event, tolerating a page that never fires one."""
    deadline = time.time() + timeout
    loaded = False
    replied = False
    while time.time() < deadline and not (loaded and replied):
        try:
            message = connection.pump(timeout=0.25)
        except ConnectionError:
            break
        if message is not None and message.get("id") == navigate_id:
            replied = True
        if any(event.get("method") == "Page.loadEventFired" for event in connection.events):
            loaded = True


def _reply(connection: _CdpConnection, message_id: int, timeout: float = 5.0) -> dict | None:
    """The reply to *message_id*, pumping events while we wait."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            message = connection.pump(until=message_id, timeout=0.25)
        except ConnectionError:
            return None
        if message is not None and message.get("id") == message_id:
            return message
    return None


def _evaluate(connection: _CdpConnection, expression: str) -> bool:
    """Evaluate one marker expression; anything but a truthy answer is False."""
    try:
        reply = _reply(
            connection,
            connection.send(
                "Runtime.evaluate",
                {"expression": expression, "returnByValue": True, "awaitPromise": False},
            ),
        )
    except Exception:  # noqa: BLE001 - an unanswerable marker is not evidence
        return False
    if not reply:
        return False
    result = reply.get("result", {}).get("result", {})
    return bool(result.get("value"))


def _evaluate_number(connection: _CdpConnection, expression: str) -> int:
    try:
        reply = _reply(
            connection,
            connection.send(
                "Runtime.evaluate",
                {"expression": expression, "returnByValue": True, "awaitPromise": False},
            ),
        )
    except Exception:  # noqa: BLE001
        return 0
    if not reply:
        return 0
    try:
        return int(reply.get("result", {}).get("result", {}).get("value"))
    except (TypeError, ValueError):
        return 0


# --------------------------------------------------------------------------- #
# the effect
# --------------------------------------------------------------------------- #


@dataclass
class BrowserEffect:
    """The browser transport.  ``driver`` is ``auto`` | ``playwright`` | ``cdp``."""

    driver: str = "auto"
    chrome_path: str = ""
    headless: bool = True
    timeout: float = DEFAULT_TIMEOUT
    settle: float = DEFAULT_SETTLE
    _capabilities: BrowserCapabilities | None = None

    # ------------------------------------------------------------------ #
    # capability negotiation
    # ------------------------------------------------------------------ #

    @property
    def capabilities(self) -> BrowserCapabilities:
        if self._capabilities is None:
            self._capabilities = self._resolve()
        return self._capabilities

    def _resolve(self) -> BrowserCapabilities:
        wanted = (self.driver or "auto").lower()
        executable = find_chrome(self.chrome_path)
        if wanted in ("auto", "playwright") and playwright_available():
            return BrowserCapabilities(driver="playwright", available=True)
        if wanted == "playwright":
            return BrowserCapabilities(
                driver="playwright",
                available=False,
                reason=(
                    "playwright is not installed, or its chromium is missing "
                    "(python -m playwright install chromium)"
                ),
            )
        if not executable:
            return BrowserCapabilities(
                driver="cdp",
                available=False,
                reason=(
                    "no playwright and no system Chrome: install playwright, or set "
                    "CHROME_PATH to a chrome/chromium binary"
                ),
            )
        return BrowserCapabilities(
            driver="cdp",
            available=True,
            executable=executable,
            reason="system Chrome driven over the DevTools Protocol",
        )

    # ------------------------------------------------------------------ #
    # the one operation
    # ------------------------------------------------------------------ #

    def run(
        self,
        url: str,
        *,
        markers: dict[str, str] | None = None,
        at: float = 0.0,
    ) -> RawBrowserRun:
        """Load *url*, count mutations and dialogs, and answer each *marker*.

        *markers* maps a name to a JavaScript expression that must evaluate truthy
        for the marker to be true — ``{"xss:7f3a": "window.__ve_xss_7f3a === 1"}``.
        The runner asks, the page answers, the observation layer reads it.  *at* is
        accepted for call-signature parity with the other effects and is not used
        to timestamp anything: the world log's ``at`` comes from the scheduler.
        """
        capabilities = self.capabilities
        if not capabilities.available:
            return RawBrowserRun(
                url=url,
                driver=capabilities.driver,
                ok=False,
                error=capabilities.reason or "browser unavailable",
            )
        wanted = dict(markers or {})
        if capabilities.driver == "playwright":
            return _run_playwright(
                url=url,
                markers=wanted,
                headless=self.headless,
                timeout=self.timeout,
                settle=self.settle,
            )
        return _run_cdp(
            url=url,
            markers=wanted,
            executable=capabilities.executable,
            headless=self.headless,
            timeout=self.timeout,
            settle=self.settle,
        )

    def close(self) -> None:
        """Nothing is held open between runs; a browser per probe is the design."""
        return None


__all__ = [
    "BrowserCapabilities",
    "BrowserEffect",
    "DEFAULT_SETTLE",
    "DEFAULT_TIMEOUT",
    "NAME",
    "find_chrome",
    "playwright_available",
]
