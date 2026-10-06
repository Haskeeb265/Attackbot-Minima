"""Path components from operator strings: one allowlist, every join pinned.

The scar this pins: a target or run name travels from an operator's fingers
(a CLI ``-t``, a UI POST body) into a filesystem join —
``output/vuln_engine/<name>`` in three places. A traversal-shaped value
(``../.env``), an absolute path, or a separator hidden in the name walks the
run (and every artifact the engine writes into it) outside the output root.
So the allowlist lives once, in ``service/vuln_engine/paths.py``, and the
callers are pinned here the way the capability vocabulary is pinned in
``test_capability_vocabulary.py``: not because the current callers are wrong,
but because a *future* join that formats the name by hand would drift
silently. The grep test fails loudly the day someone writes a fourth join
that does not go through the allowlist.

Two layers are tested:

* the unit contract — what ``safe_component`` accepts (the names real
  targets and runs already use) and refuses (traversal, separators, absolute
  paths, empties, Windows device names), raising, never sanitizing;
* the boundary contract — the CLIs refuse a bad ``-t`` at argparse time,
  before any work; the UI's job launcher answers a traversal POST with 400.
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from service.ui import jobs as jobs_mod
from service.ui.server import UiHandler
from service.ui import server as server_mod
from service.vuln_engine.paths import MAX_COMPONENT_LEN, safe_component

REPO_ROOT = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------- #
# the unit contract
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "name",
    [
        "acme.test",                # a domain
        "10_0_0_1",                 # an address, separator-replaced by hand
        "127.0.0.1",                # a dotted quad
        "twogate-demo",             # a run name with a hyphen
        "dvwa_check",               # a run name with an underscore
        "a",                        # the shortest legal name
        "A.b_9-x.y",                # mixed case and punctuation
    ],
)
def test_a_legitimate_name_passes_through_unchanged(name: str) -> None:
    assert safe_component(name) == name


@pytest.mark.parametrize(
    "name",
    [
        "../env",                   # classic traversal
        "..",                       # the traversal component itself
        ".",                        # current directory — collapses the join
        "a/b",                      # forward separator
        "a\\b",                     # back separator
        "..\\..\\Windows",          # Windows traversal
        "/etc/passwd",              # absolute
        "C:/Windows",               # drive-absolute
        "C:\\Windows",              # drive-absolute, back separators
        "http://acme.test",         # a URL, colon included
        "acme.test/x?y=z",          # separators hiding in a URL shape
        "%2e%2e",                   # percent-encoding is not decoding
        "",                         # empty collapses the join to the root
        "   ",                      # whitespace is not a name
        "acme test",                # space is not in the allowlist
        "NUL",                      # Windows device
        "nul.txt",                  # device with an extension
        "CON",                      # the other classic
        "a" * (MAX_COMPONENT_LEN + 1),  # overlong
    ],
)
def test_an_unsafe_name_raises_it_is_never_sanitized(name: str) -> None:
    with pytest.raises(ValueError):
        safe_component(name)


# --------------------------------------------------------------------------- #
# the boundary: the CLIs
# --------------------------------------------------------------------------- #


def test_run_engine_refuses_a_traversal_target_at_argparse_time() -> None:
    # The error must come from the boundary check before the engine builds any
    # profile, graph or policy — a SystemExit with a message naming the target.
    proc = subprocess.run(
        [sys.executable, "-u", "run_engine.py", "-t", "../../x", "--json"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=60,
    )
    assert proc.returncode != 0
    assert "../../x" in (proc.stderr + proc.stdout)


def test_run_engine_accepts_a_legitimate_target_far_enough_to_fail_later() -> None:
    # A domain-shaped target gets PAST the boundary: the run may then fail for
    # unrelated reasons (no such host to resolve, no Docker) — what this pins
    # is that the name check is an allowlist, not a blanket refusal.
    proc = subprocess.run(
        [sys.executable, "-u", "run_engine.py", "-t", "example.test", "--json"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=60,
    )
    traversal_refusal = "refusing unsafe path component"
    assert traversal_refusal not in (proc.stderr + proc.stdout)


def test_run_twogate_refuses_a_traversal_target_at_argparse_time() -> None:
    proc = subprocess.run(
        [sys.executable, "-u", "run_twogate.py", "-t", "../escape"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=60,
    )
    assert proc.returncode != 0
    assert "../escape" in (proc.stderr + proc.stdout)


# --------------------------------------------------------------------------- #
# the boundary: the UI job launcher
# --------------------------------------------------------------------------- #


def test_the_ui_launcher_refuses_a_traversal_target() -> None:
    for kind in ("recon", "engine", "twogate"):
        with pytest.raises(ValueError):
            jobs_mod.build_command(kind, {"target": "../../x"})


def test_the_ui_launcher_refuses_a_traversal_output_dir() -> None:
    with pytest.raises(ValueError):
        jobs_mod.build_command("engine_fixture", {"output_dir": ".."})


def test_the_ui_launcher_still_accepts_legitimate_names() -> None:
    argv, _ = jobs_mod.build_command("engine", {"target": "acme.test", "output_dir": "dvwa_check"})
    assert "-t" in argv and "acme.test" in argv
    assert "output/vuln_engine/dvwa_check" in argv


# --------------------------------------------------------------------------- #
# the pinning test: every name→path join routes through the allowlist
# --------------------------------------------------------------------------- #


_JOIN_SITES = {
    # Callers that must validate names with safe_component *and* must not
    # re-implement the join with ad-hoc string surgery.
    "run_engine.py": 2,
    "run_twogate.py": 2,
    "service/ui/jobs.py": 3,
}
#: The three ad-hoc shapes a hand-rolled join takes; none may reappear.
_FORBIDDEN_PATTERNS = (
    r'replace\(":", "_"\)',          # target.replace(":", "_")
    r"_OUTPUT_DIR_RE",               # a private regex allowlist
)


def _module_calls(module_path: Path) -> list[ast.Call]:
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "safe_component"
    ]


def test_every_target_to_path_call_site_goes_through_the_allowlist() -> None:
    for rel_path, min_calls in _JOIN_SITES.items():
        calls = _module_calls(REPO_ROOT / rel_path)
        assert len(calls) >= min_calls, (
            f"{rel_path}: expected at least {min_calls} safe_component call(s), "
            f"found {len(calls)} — a name→path join stopped using the allowlist?"
        )


def test_no_call_site_reimports_the_old_ad_hoc_guards() -> None:
    for rel_path in _JOIN_SITES:
        source = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
        for pattern in _FORBIDDEN_PATTERNS:
            assert not re.search(pattern, source), (
                f"{rel_path} still contains {pattern!r} — the ad-hoc join or "
                f"private allowlist came back; route through safe_component"
            )


def test_the_allowlist_module_defines_the_contract_the_tests_pin() -> None:
    # Guard against the pinning test passing vacuously: the owner must still
    # exist, raise, and hold the documented limits.
    assert MAX_COMPONENT_LEN == 120
    with pytest.raises(ValueError):
        safe_component("../env")


# --------------------------------------------------------------------------- #
# the HTTP boundary: a traversal POST through the real handler
# --------------------------------------------------------------------------- #


@pytest.fixture()
def ui_server(monkeypatch):
    """The real handler over real HTTP on an ephemeral port, no artifacts."""
    monkeypatch.setattr(jobs_mod, "ROOT", Path(REPO_ROOT))
    monkeypatch.setattr(jobs_mod, "JOBS_ROOT", Path(REPO_ROOT) / "output" / "ui_jobs_test")
    handler = type("H", (UiHandler,), {})
    from http.server import ThreadingHTTPServer

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def _post(url: str, payload: dict) -> tuple[int, dict]:
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Requested-With": "vuln-engine",  # the app's write-side guard
        }, method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as res:
            return res.status, json.loads(res.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def test_a_traversal_target_through_the_http_run_api_is_a_400(ui_server) -> None:
    status, payload = _post(
        ui_server + "/api/run", {"kind": "engine", "params": {"target": "../../x"}}
    )
    assert status == 400
    assert "unsafe path component" in payload["error"]
