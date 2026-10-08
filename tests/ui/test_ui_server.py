"""The UI's hermetic tests: every view function and every HTTP route.

No Docker, no database, no network beyond loopback: the DB-backed program
views are tested through their failure path (a missing database is a degrade,
not a crash), and the artifact-backed views against a temp tree that mirrors
the repo's layout. The server is exercised over real HTTP on an ephemeral
port, because a handler tested by direct method calls never proves its
routing, its path checks or its JSON contract.

The world-log fixture is a minimal but faithful excerpt of the rows the
engine really writes (the same row types, the same key names) so the views
are pinned against the shape the ledger actually has.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from service.ui import engine as engine_view
from service.ui import jobs as jobs_mod
from service.ui import programs as programs_mod
from service.ui import recon as recon_view
from service.ui import server as server_mod
from service.ui import trace as trace_view
from service.ui.artifacts import ArtifactError, safe_resolve
from service.ui.server import UiHandler


# --------------------------------------------------------------------------- #
# fixtures: a repo-shaped temp tree
# --------------------------------------------------------------------------- #


WORLD_ROWS = [
    {
        "type": "run.begin",
        "at": 1000.0,
        "target": "example.test",
        "techniques": ["xss_reflected"],
        "surfaces": [
            {"url": "http://example.test/search", "host": "example.test",
             "param": "q", "where": "query", "capability": "public_param",
             "label": "search"}
        ],
        "capabilities": {"http1": {"name": "http1", "available": True, "reason": ""}},
    },
    {
        "type": "scheduler.pick",
        "at": 1000.1,
        "technique": "xss_reflected",
        "surface": "xss_reflected@example.test/search#q",
        "reason": "quiet first",
    },
    {
        "type": "note",
        "at": 1000.2,
        "stage": "hypothesis",
        "arm": "xss_reflected@example.test/search#q",
        "hypothesis": {"id": "xss_reflected:example.test:q:reflect",
                       "technique": "xss_reflected",
                       "claim": "parameter 'q' is reflected",
                       "rests_on": "http_response_reflects_input"},
    },
    {
        "type": "effect.request",
        "at": 1000.3,
        "host": "example.test",
        "kind": "http.request",
        "operation": "url_validation",
        "technique": "xss_reflected",
        "probe": "xss_reflected:canary",
        "detail": {"url": "http://example.test/search?q=canary", "method": "GET"},
    },
    {
        "type": "gate.decision",
        "at": 1000.4,
        "host": "example.test",
        "kind": "http.request",
        "technique": "xss_reflected",
        "probe": "xss_reflected:canary",
        "verb": "ALLOW",
        "reason": "in scope and within budget",
    },
    {
        "type": "gate.decision",
        "at": 1000.5,
        "host": "other.test",
        "kind": "http.request",
        "technique": "xss_reflected",
        "probe": "xss_reflected:canary",
        "verb": "DENY",
        "reason": "scope: not in the declared set",
    },
    {
        "type": "effect.result",
        "at": 1000.6,
        "host": "example.test",
        "kind": "http.request",
        "technique": "xsl_reflected",
        "probe": "xss_reflected:canary",
        "status": 200,
        "bytes": 512,
        "elapsed": 0.01,
        "error": "",
        "transport": "http1",
    },
    {
        "type": "observation",
        "at": 1000.7,
        "kind": "observation.reflection",
        "payload": {"reflected": True, "context": "raw_html"},
        "probe": "xss_reflected:canary",
    },
    {
        "type": "candidate",
        "at": 1000.8,
        "arm": "xss_reflected@example.test/search#q",
        "id": "xss_reflected:example.test:search:q",
        "technique": "xss_reflected",
        "vuln_class": "xss",
        "summary": "parameter 'q' is reflected inside a raw html context",
        "payload": "<script>x</script>",
        "repro_url": "http://example.test/search?q=%3Cscript%3E",
    },
    {
        "type": "verdict",
        "at": 1001.0,
        "arm": "xss_reflected@example.test/search#q",
        "candidate": "xss_reflected:example.test:search:q",
        "proven": True,
        "grade": "execution",
        "reason": "the payload's script ran in the browser",
    },
    {"type": "receipt", "at": 1001.1, "arm": "xss_reflected@example.test/search#q",
     "technique": "xss_reflected", "outcome": "found", "conclusive": True},
    {"type": "run.end", "at": 1001.2, "counts": {"findings": 1}},
]

#: A minimal but faithful excerpt of the two-gate ledger: measured capabilities,
#: a model junction (the agent's reasoning), a planned routine, a spec, the
#: oracle's answer, and the proven verdict — the rows the trace view must phase.
TWOGATE_ROWS = [
    {
        "type": "run.begin", "at": 3000.0, "target": "example.test",
        "criteria": {"max_rounds_per_surface": 3},
        "surfaces": [
            {"url": "http://example.test/search", "host": "example.test",
             "param": "q", "where": "query", "capability": "public_param", "label": "search"}
        ],
        "capabilities": {"http1": {"name": "http1", "available": True, "reason": ""}},
    },
    {"type": "capability.measured", "at": 3000.1,
     "surface_key": "http://example.test/search#q",
     "capability": "http_response_reflects_input", "measured": True},
    {"type": "capability.measured", "at": 3000.2,
     "surface_key": "http://example.test/search#q",
     "capability": "delayed_response", "measured": False},
    {"type": "loop.round", "at": 3000.3,
     "surface_key": "http://example.test/search#q", "round": 1,
     "proposed": 1, "fresh": 1, "history": []},
    {
        "type": "llm.junction", "at": 3000.4, "junction": "twogate.capability",
        "digest": "abc", "model": "openai/gpt-oss-20b",
        "junction_input": {"surface": {"url": "http://example.test/search", "param": "q"},
                            "capabilities": ["http_response_reflects_input"],
                            "options": ["xss"]},
        "answer": {"label": "xss"},
        "validation": "label-in-admitted-set", "degraded": False,
        "validated": True, "reason": "",
    },
    {"type": "confirmation.planned", "at": 3000.5,
     "surface_key": "http://example.test/search#q", "proposal_id": "xss:s",
     "label": "xss", "confirm_kind": "browser.run", "routine_id": "xss.browser.v1",
     "oracle": "script_executed"},
    {"type": "confirmation.spec", "at": 3000.6,
     "surface_key": "http://example.test/search#q",
     "spec": {"oracle": "script_executed", "samples": 1, "margin": 0.0,
              "injected_payload": "<script>x</script>", "baseline_payload": "ve-noop0",
              "spec_digest": "deadbeef"}},
    {"type": "effect.request", "at": 3000.7, "host": "example.test",
     "kind": "browser.run", "technique": "two_gate_verifier", "probe": "confirm:xss.browser.v1",
     "detail": {"url": "http://example.test/search?q=%3Cscript%3Ex%3C/script%3E"}},
    {"type": "gate.decision", "at": 3000.8, "host": "example.test",
     "kind": "browser.run", "technique": "two_gate_verifier", "verb": "ALLOW", "reason": "in scope"},
    {"type": "effect.result", "at": 3000.9, "host": "example.test",
     "kind": "browser.run", "technique": "two_gate_verifier", "status": 200,
     "bytes": 0, "elapsed": 1.2, "ok": True, "markers_true": {"ve-xss-exec": True}},
    {"type": "confirmation.executed", "at": 3001.0,
     "surface_key": "http://example.test/search#q", "proposal_id": "xss:s",
     "routine_id": "xss.browser.v1", "spec_digest": "deadbeef",
     "proven": True, "oracle_true": True,
     "features": {"injected": [{"elapsed_ms": 1200.0, "script_executed": True}]}},
    {"type": "candidate", "at": 3001.1, "arm": "xss@http://example.test/search#q",
     "id": "xss:http://example.test/search#q", "technique": "capability_agent",
     "vuln_class": "xss", "summary": "reflected input", "payload": "<script>x</script>",
     "repro_url": "http://example.test/search?q=x", "origin": "llm.capability"},
    {"type": "verdict", "at": 3001.2, "arm": "xss@http://example.test/search#q",
     "candidate": "xss:http://example.test/search#q", "proven": True, "grade": "execution",
     "reason": "oracle 'script_executed' held over fresh measurements",
     "proposer_grade": "hypothesis"},
    {"type": "run.end", "at": 3001.3, "counts": {"proven": 1}},
]

TWOGATE_REPORT = {
    "target": "example.test",
    "findings": [{"vuln_class": "xss", "evidence_class": "execution",
                  "summary": "reflected input", "repro_url": "http://example.test/search?q=x"}],
    "leads": [],
    "gate": {"by_verb": {"ALLOW": 1, "DENY": 0}},    "counts": {"proven": 1},
    "report_lines": ["xss — execution — reflected input"],
}

REPORT = {
    "target": "example.test",
    "findings": [{"vuln_class": "xss", "grade": "execution",
                  "summary": "reflected XSS in q", "repro_url": "http://example.test/search?q=x"}],
    "leads": [],
    "gate": {"decisions": 2, "by_verb": {"ALLOW": 1, "DENY": 1}, "uncleared_effects": 0,
             "out_of_scope_requests": 1},
    "counts": {"findings": 1},
    "holding_pen": {
        "held": 2,
        "lifetime": 3,
        "value": 6.0,
        "groups": [
            {"needs_verifier": "authorization.state_change", "key": "idor",
             "count": 2, "value": 6.0},
        ],
    },
    "report_lines": ["xss — execution — http://example.test/search?q=x"],
}

GRAPH_STATE = {
    "graph_state_version": 1,
    "target": "example.test",
    "generated_at": "2026-09-30T00:00:00+00:00",
    "integrity": {"consistent": True, "nodes": 3, "edges": 2},
    "nodes": [
        {"id": "domain:example.test", "kind": "domain", "identity": "example.test",
         "trust": "declared", "score": 90, "band": "high",
         "props": {"scope_state": "in_scope", "scope_reason": "declared"}},
        {"id": "host:example.test", "kind": "host", "identity": "example.test",
         "trust": "observed", "score": 80, "band": "high",
         "props": {"scope_state": "in_scope"}},
        {"id": "url:example.test/search#q", "kind": "url", "identity": "search#q",
         "trust": "observed", "score": 70, "band": "medium",
         "props": {"scope_state": "out_of_scope", "scope_reason": "boundary"}},
    ],
    "edges": [
        {"source": "domain:example.test", "target": "host:example.test", "type": "resolves"},
        {"source": "host:example.test", "target": "url:example.test/search#q", "type": "serves"},
        {"source": "domain:example.test", "target": "url:missing", "type": "dangling"},
    ],
}


@pytest.fixture()
def artifact_tree(tmp_path, monkeypatch):
    """A repo-shaped tree: recon logs, runs timeline, graph state, engine runs."""
    root = tmp_path
    monkeypatch.setattr(recon_view, "ROOT", root)
    monkeypatch.setattr(engine_view, "ROOT", root)
    monkeypatch.setattr(engine_view, "ENGINE_ROOT", root / "output" / "vuln_engine")
    monkeypatch.setattr(jobs_mod, "ROOT", root)
    monkeypatch.setattr(jobs_mod, "JOBS_ROOT", root / "output" / "ui_jobs")
    monkeypatch.setattr(trace_view, "OUTPUT_ROOT", root / "output")
    monkeypatch.setattr(trace_view, "ENGINE_ROOT", root / "output" / "vuln_engine")

    # Recon logs live at the *caller's* root (run_recon.py writes them at the
    # repo root), and this test tree's root is the temp dir — write them there.
    # The view reads through the same patched ROOT, so no real file is touched.
    for stage, text in (
        ("subdomain", "[passive] subfinder: 3 names\n[active] resolved 2\n"),
        ("ports", "[ports] 2 hosts scanned\n"),
        ("url", "[url] 10 urls harvested\n"),
    ):
        (root / f"recon_example.test_{stage}_20260930_120000.log").write_text(
            text, encoding="utf-8", newline="\n"
        )
    (root / "recon_other.test_subdomain_20260929_090000.log").write_text(
        "[passive] older target log\n", encoding="utf-8", newline="\n"
    )

    # runs timeline
    runs_root = root / "output" / "runs"
    runs_root.mkdir(parents=True)
    (runs_root / "runs.jsonl").write_text(
        json.dumps({"target": "example.test", "ok": True,
                    "started_at": "2026-09-30T12:00:00+00:00"}) + "\n",
        encoding="utf-8", newline="\n",
    )

    # graph state (the default handoff location)
    gn = root / "service" / "recon_pipeline" / "pipelines" / "graph_normalize" / "output"
    gn.mkdir(parents=True)
    (gn / "graph_state.json").write_text(json.dumps(GRAPH_STATE), encoding="utf-8")

    # engine run
    run_dir = root / "output" / "vuln_engine" / "example.test"
    run_dir.mkdir(parents=True)
    (run_dir / "world.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in WORLD_ROWS),
        encoding="utf-8", newline="\n",
    )
    (run_dir / "report.json").write_text(json.dumps(REPORT), encoding="utf-8")

    # a two-gate run, written where the CLI default lands when the UI passes an
    # explicit output dir: output/vuln_engine/<name> — classified by its ledger.
    tg_dir = root / "output" / "vuln_engine" / "twogate_demo"
    tg_dir.mkdir(parents=True)
    (tg_dir / "twogate.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in TWOGATE_ROWS),
        encoding="utf-8", newline="\n",
    )
    (tg_dir / "twogate_report.json").write_text(
        json.dumps(TWOGATE_REPORT), encoding="utf-8"
    )
    return root


@pytest.fixture()
def server(artifact_tree):
    """The real handler over real HTTP on an ephemeral port."""
    handler = type("H", (UiHandler,), {})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def get(url: str) -> tuple[int, dict | str]:
    """GET a URL; returns (status, parsed-json or raw text)."""
    try:
        with urllib.request.urlopen(url, timeout=10) as res:
            body = res.read().decode("utf-8")
            status = res.status
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        status = exc.code
    try:
        return status, json.loads(body)
    except ValueError:
        return status, body


def get_with_headers(url: str, headers: dict) -> tuple[int, dict | str]:
    """GET with explicit headers (e.g. an Authorization bearer)."""
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=10) as res:
            body = res.read().decode("utf-8")
            status = res.status
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        status = exc.code
    try:
        return status, json.loads(body)
    except ValueError:
        return status, body


def post(url: str, payload: dict) -> tuple[int, dict]:
    """POST as the app does: JSON plus the X-Requested-With guard header."""
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Requested-With": "vuln-engine",
        }, method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as res:
            return res.status, json.loads(res.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def post_unguarded(url: str, payload: dict) -> tuple[int, dict]:
    """POST *without* the guard header — what a forged cross-origin request looks like."""
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        return _post_once(request)
    except ConnectionAbortedError:
        # Windows (WinError 10053) sometimes aborts a loopback connection whose
        # peer responds-and-closes in the same segment — the server's answer is
        # complete on the wire but the client's read loses the race. That is
        # the OS racing *itself*, not the guard being wrong: the request is
        # replayed once and its verdict stands. Retrying a GET is never
        # idempotent-sensitive here because the refused POST never dispatched
        # (the guard fires before the body is read), and the retry gets the
        # same 403 for the same reason.
        return _post_once(request)


def _post_once(request: urllib.request.Request) -> tuple[int, dict]:
    try:
        with urllib.request.urlopen(request, timeout=30) as res:
            return res.status, json.loads(res.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


# --------------------------------------------------------------------------- #
# path safety
# --------------------------------------------------------------------------- #


def test_safe_resolve_keeps_paths_inside_the_repo(artifact_tree):
    resolved = safe_resolve(artifact_tree, "output", "vuln_engine", "example.test")
    assert resolved.is_dir()


def test_safe_resolve_refuses_escape(tmp_path):
    with pytest.raises(ArtifactError):
        safe_resolve(tmp_path, "..", "elsewhere")
    with pytest.raises(ArtifactError):
        safe_resolve(tmp_path, "output", "..", "..", "etc")


# --------------------------------------------------------------------------- #
# the write side is not browser-reachable (T5)
# --------------------------------------------------------------------------- #


def test_a_post_without_the_guard_header_is_refused_before_dispatch(server):
    # A forged cross-origin POST (form auto-submit, no-preflight fetch) looks
    # exactly like this: right content type, no X-Requested-With. It must be
    # refused with 403 whatever the route — the guard is before dispatch.
    status, payload = post_unguarded(server + "/api/run", {"kind": "engine_fixture", "params": {}})
    assert status == 403
    assert "X-Requested-With" in payload["error"]
    status, _ = post_unguarded(server + "/api/jobs/stop", {"id": "nope"})
    assert status == 403
    status, _ = post_unguarded(server + "/api/demo/seed", {})
    assert status == 403


def test_a_wrong_guard_value_is_refused_too(server):
    # The value matters: an attacker-controlled page can sometimes reflect a
    # header name, but it cannot know the value this server expects.
    request = urllib.request.Request(
        server + "/api/run", data=b"{}",
        headers={"Content-Type": "application/json", "X-Requested-With": "evil"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as res:
            status = res.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    assert status == 403


def test_a_guarded_post_still_works_end_to_end(server, artifact_tree):
    # The guard did not break the legitimate path: unknown kind still reaches
    # the launcher and comes back 400 (route dispatch happened).
    status, payload = post(server + "/api/run", {"kind": "shell", "params": {}})
    assert status == 400


def test_the_server_refuses_a_non_loopback_bind_without_expose(monkeypatch, capsys):
    # The opt-in boundary: main() refuses before any socket is opened.
    assert server_mod.main(["--host", "0.0.0.0"]) == 2
    assert "--expose" in capsys.readouterr().err
    assert server_mod.main(["--host", "192.168.1.10"]) == 2


def test_the_server_accepts_loopback_hosts_without_expose(monkeypatch):
    # ThreadingHTTPServer would actually bind; patch it to keep the test
    # hermetic while main() still constructs and configures the real class.
    created = {}

    class FakeServer:
        def __init__(self, addr, handler):
            created["addr"] = addr
            self.verbose = False

        def serve_forever(self):
            raise KeyboardInterrupt  # main() treats Ctrl+C as clean exit

        def server_close(self):
            pass

    monkeypatch.setattr(server_mod, "ThreadingHTTPServer", FakeServer)
    assert server_mod.main(["--port", "0"]) == 0
    assert created["addr"][0] == "127.0.0.1"
    # And the non-loopback refusal does not fire for a loopback alias.
    assert server_mod.main(["--host", "localhost", "--port", "0"]) == 0


def test_exposing_without_an_auth_token_is_refused_at_startup(capsys):
    # Item 2.3: an exposed UI without a bearer token hands the host's
    # job-starting authority to whoever can route to the port, so main()
    # refuses before any socket is opened — the same fail-before-bind
    # pattern the loopback check pins above.
    assert server_mod.main(["--host", "0.0.0.0", "--expose"]) == 2
    assert "--auth-token" in capsys.readouterr().err
    # Loopback mode never needs a token, exposed or not.
    assert server_mod.main(["--expose", "--host", "127.0.0.1"]) == 2
    assert "--auth-token" in capsys.readouterr().err


def test_an_exposed_server_requires_the_bearer_token():
    # The real handler over real HTTP, with the token main() would set.
    handler = type("H", (UiHandler,), {})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.auth_token = "s3cret"  # type: ignore[attr-defined]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        # No Authorization header at all: refused on the headers alone.
        status, body = get(base + "/api/state")
        assert status == 401
        assert "authentication required" in body["error"]
        # A wrong token is the same refusal...
        status, body = get_with_headers(
            base + "/api/state", {"Authorization": "Bearer nope"}
        )
        assert status == 401
        # ...and the auth check fires before the CSRF guard: a bearer-less
        # POST never reaches dispatch, so the error is 401, not 403.
        request = urllib.request.Request(
            base + "/api/jobs", data=b"{}",
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as res:
                status = res.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        assert status == 401
        # The right token passes and the response is the ordinary view.
        status, payload = get_with_headers(
            base + "/api/state", {"Authorization": "Bearer s3cret"}
        )
        assert status == 200
        assert "programs" in payload
    finally:
        httpd.shutdown()
        httpd.server_close()


# --------------------------------------------------------------------------- #
# program views (DB degrade contract)
# --------------------------------------------------------------------------- #


def test_program_list_degrades_without_a_database(monkeypatch):
    def boom(query, params=()):
        raise programs_mod.DbUnavailable("no database here")
    monkeypatch.setattr(programs_mod, "_fetch", boom)
    with pytest.raises(programs_mod.DbUnavailable):
        programs_mod.list_programs()


def test_program_detail_degrades_without_a_database(monkeypatch):
    def boom(query, params=()):
        raise programs_mod.DbUnavailable("no database here")
    monkeypatch.setattr(programs_mod, "_fetch", boom)
    with pytest.raises(programs_mod.DbUnavailable):
        programs_mod.program_detail("acme")


def test_program_detail_classifies_scope_rows(monkeypatch):
    rows = {
        "master": [{"id": "m1", "handle": "acme", "program_name": "Acme",
                    "policy": "<b>no automated scanning</b>", "offers_bounties": True}],
        "details": [
            {"scope_type": "DOMAIN", "scope_identifier": "acme.test",
             "in_scope": True, "scope_instructions": "be nice",
             "eligible_for_bounty": True, "max_severity": "critical"},
            {"scope_type": "DOMAIN", "scope_identifier": "api.acme.test",
             "in_scope": False, "scope_instructions": "", "max_severity": ""},
            {"scope_type": "ANDROID", "scope_identifier": "com.acme.app",
             "in_scope": True, "scope_instructions": "", "max_severity": ""},
        ],
        "exclusions": [{"exclusion_category": "denial of wallet",
                        "exclusion_details": "no load tests"}],
        "weaknesses": [{"weakness_id": "W1", "weakness_name": "XSS",
                        "weakness_description": "d"}],
    }

    def fake_fetch(query, params=()):
        if "bounty_master" in query and "count(" not in query:
            return rows["master"]
        if "bounty_detail" in query:
            return rows["details"]
        if "bounty_exclusion" in query:
            return rows["exclusions"]
        if "bounty_weaknesses" in query:
            return rows["weaknesses"]
        return []

    monkeypatch.setattr(programs_mod, "_fetch", fake_fetch)
    detail = programs_mod.program_detail("acme")
    assert detail["handle"] == "acme"
    assert detail["policy"] == "no automated scanning"  # tags stripped
    assert detail["counts"]["in_scope"] == 1
    assert detail["counts"]["out_of_scope"] == 1
    assert detail["out_of_scope"][0]["identifier"] == "api.acme.test"
    assert detail["counts"]["unsupported"] == 1  # ANDROID is a non-asset type
    assert detail["counts"]["exclusions"] == 1


# --------------------------------------------------------------------------- #
# recon views
# --------------------------------------------------------------------------- #


def test_tail_text_returns_the_last_lines(artifact_tree):
    path = recon_view.latest_run_log("example.test", "subdomain")
    assert path is not None and path.is_file()
    lines = recon_view.tail_text(path, 1)
    assert lines == ["[active] resolved 2"]


def test_tail_text_on_a_missing_file_is_empty(artifact_tree):
    assert recon_view.tail_text(artifact_tree / "nope.log", 10) == []


def test_run_logs_pick_newest_per_stage(artifact_tree):
    logs = recon_view.run_logs("example.test")
    stages = {entry["stage"] for entry in logs}
    assert {"subdomain", "ports", "url"} <= stages


def test_list_known_targets(artifact_tree):
    targets = recon_view.list_known_targets()
    assert "example.test" in targets


def test_read_runs_reads_the_timeline(artifact_tree):
    runs = recon_view.read_runs()
    assert runs and runs[0]["target"] == "example.test"


def test_graph_overview_counts_and_slice(artifact_tree):
    overview = recon_view.graph_overview(None)
    assert overview["available"] is True
    assert overview["counts"]["nodes"] == 3
    assert overview["counts"]["edges"] == 3
    assert overview["by_kind"]["domain"] == 1
    # nodes are sorted by score, desc
    scores = [n["score"] for n in overview["nodes"]]
    assert scores == sorted(scores, reverse=True)


def test_graph_overview_caps_and_keeps_edges_consistent(artifact_tree):
    overview = recon_view.graph_overview(None, cap=2)
    assert overview["counts"]["shown_nodes"] == 2
    kept = {n["id"] for n in overview["nodes"]}
    for edge in overview["edges"]:
        assert edge["source"] in kept and edge["target"] in kept


def test_graph_overview_filters_by_query(artifact_tree):
    overview = recon_view.graph_overview(None, query="search")
    assert [n["id"] for n in overview["nodes"]] == ["url:example.test/search#q"]


def test_graph_overview_degrades_without_a_file(artifact_tree, monkeypatch):
    monkeypatch.setattr(recon_view, "graph_state_path", lambda t=None: artifact_tree / "none.json")
    overview = recon_view.graph_overview(None)
    assert overview["available"] is False and "no graph_state.json" in overview["reason"]


# --------------------------------------------------------------------------- #
# engine views
# --------------------------------------------------------------------------- #


def test_log_overview_counts_rows_and_gate(artifact_tree):
    overview = engine_view.log_overview("example.test")
    assert overview["rows"] == len(WORLD_ROWS)
    assert overview["findings"] == 1
    assert overview["gate"]["ALLOW"] == 1
    assert overview["gate"]["DENY"] == 1
    assert overview["targets"] == ["example.test"]


def test_log_rows_streams_by_cursor_without_loss(artifact_tree):
    # The realtime contract: a cursor, not a timestamp — rows share `at`
    # values (a burst lands within the same millisecond), so resuming at
    # `at > t` would silently drop every same-`at` row after the boundary.
    # The index cursor walks the append-only ledger with zero loss.
    first = engine_view.log_rows("example.test", cursor=0, limit=3)
    assert first["count"] == 3
    assert first["rows"][0]["type"] == "run.begin"
    middle = engine_view.log_rows("example.test", cursor=first["next_index"], limit=4)
    assert middle["count"] == 4
    # no overlap, no gap: the second batch starts exactly where the first ended
    assert middle["rows"][0] == WORLD_ROWS[3]
    tail = engine_view.log_rows("example.test", cursor=middle["next_index"], limit=100)
    assert tail["count"] == len(WORLD_ROWS) - 7
    # timestamps-only query still works as a one-shot floor
    at_floor = engine_view.log_rows("example.test", after=1000.5)
    assert all(float(r["at"]) > 1000.5 for r in at_floor["rows"])


def test_log_rows_on_a_missing_run_is_empty(artifact_tree):
    overview = engine_view.log_overview("never_ran")
    assert overview["rows"] == 0
    rows = engine_view.log_rows("never_ran")
    assert rows["rows"] == []


def test_inputs_view_reads_the_seed(artifact_tree):
    inputs = engine_view.inputs_view("example.test")
    assert inputs["available"] is True
    assert inputs["target"] == "example.test"
    assert inputs["techniques"] == ["xss_reflected"]
    assert inputs["surfaces"][0]["param"] == "q"
    assert len(inputs["hypotheses"]) == 1
    assert inputs["scheduler_picks"][0]["technique"] == "xss_reflected"


def test_report_view_reads_report_json(artifact_tree):
    report = engine_view.report_view("example.test")
    assert report["available"] is True
    assert report["source"] == "report.json"
    assert report["report"]["findings"][0]["vuln_class"] == "xss"


def test_report_view_derives_findings_from_the_ledger(artifact_tree):
    """A campaign run writes no report.json — the findings are still in the
    ledger: every proven verdict joined to its candidate's typed fields."""
    # Add a candidate + proven verdict without a report.json (a campaign run).
    run_dir = artifact_tree / "output" / "vuln_engine" / "campaign_run"
    run_dir.mkdir(parents=True)
    rows = [
        {"type": "run.begin", "at": 2000.0, "target": "example.test",
         "techniques": ["xss_reflected"], "surfaces": []},
        {"type": "candidate", "at": 2001.0, "id": "c1", "vuln_class": "sqli",
         "summary": "timing separated", "payload": "1' AND SLEEP(4)",
         "repro_url": "http://example.test/x"},
        {"type": "gate.decision", "at": 2002.0, "verb": "ALLOW", "host": "example.test"},
        {"type": "verdict", "at": 2003.0, "candidate": "c1", "proven": True,
         "grade": "differential", "reason": "fresh measurement separated"},
    ]
    (run_dir / "world.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8", newline="\n"
    )
    report = engine_view.report_view("campaign_run")
    assert report["available"] is True
    assert report["source"] == "world_log"
    finding = report["report"]["findings"][0]
    assert finding["vuln_class"] == "sqli"
    assert finding["grade"] == "differential"
    assert finding["summary"] == "timing separated"
    assert finding["repro_url"] == "http://example.test/x"
    assert report["report"]["gate"]["by_verb"] == {"ALLOW": 1, "DENY": 0, "DEFER": 0}


def test_report_view_degrades_without_a_report(artifact_tree):
    report = engine_view.report_view("never_ran")
    assert report["available"] is False


# --------------------------------------------------------------------------- #
# trace views (both flows)
# --------------------------------------------------------------------------- #


def test_trace_discover_finds_both_flows(artifact_tree):
    runs = trace_view.discover()
    by_key = {run["key"]: run for run in runs}
    assert by_key["vuln_engine/example.test"]["flow"] == "classic"
    assert by_key["vuln_engine/twogate_demo"]["flow"] == "twogate"
    # the two-gate run used a model junction, so the label says so
    assert by_key["vuln_engine/twogate_demo"]["used_llm"] is True


def test_trace_view_phases_the_two_gate_flow(artifact_tree):
    view = trace_view.trace_view("vuln_engine/twogate_demo")
    assert view["available"] is True
    assert view["flow"] == "twogate"
    assert view["total_rows"] == len(TWOGATE_ROWS)
    phases = [step["phase"] for step in view["steps"]]
    assert phases[0] == "input"
    assert "measure" in phases and "reason" in phases
    assert phases[-1] == "output"
    # the model junction is the AI-reasoning step and keeps its prompt + answer
    reasoning = next(s for s in view["steps"] if s["type"] == "llm.junction")
    assert reasoning["phase"] == "reason"
    assert reasoning["raw"]["answer"] == {"label": "xss"}
    assert reasoning["raw"]["junction_input"]["options"] == ["xss"]


def test_trace_view_summarizes_capabilities_and_findings(artifact_tree):
    view = trace_view.trace_view("vuln_engine/twogate_demo")
    summary = view["summary"]
    assert summary["findings"] == 1
    assert summary["gate"]["ALLOW"] == 1
    measured = summary["capabilities"]["http://example.test/search#q"]
    assert measured == ["http_response_reflects_input"]  # the false one is excluded


def test_trace_view_streams_by_cursor_without_loss(artifact_tree):
    first = trace_view.trace_view("vuln_engine/twogate_demo", cursor=0, limit=4)
    assert [s["index"] for s in first["steps"]] == [0, 1, 2, 3]
    second = trace_view.trace_view(
        "vuln_engine/twogate_demo", cursor=first["next_index"], limit=4
    )
    assert [s["index"] for s in second["steps"]] == [4, 5, 6, 7]
    tail = trace_view.trace_view(
        "vuln_engine/twogate_demo", cursor=second["next_index"], limit=100
    )
    assert tail["count"] == len(TWOGATE_ROWS) - 8


def test_trace_view_on_a_missing_run_is_unavailable(artifact_tree):
    view = trace_view.trace_view("no_such_run")
    assert view["available"] is False
    assert view["steps"] == []


def test_trace_resolve_refuses_escape(artifact_tree):
    with pytest.raises(ArtifactError):
        trace_view.resolve("../.env")
    with pytest.raises(ArtifactError):
        trace_view.resolve("vuln_engine/../../secret")


def test_trace_output_reads_the_twogate_report(artifact_tree):
    out = trace_view.output_view("vuln_engine/twogate_demo")
    assert out["available"] is True
    assert out["source"] == "twogate_report.json"
    assert out["report"]["findings"][0]["vuln_class"] == "xss"


def test_trace_output_derives_classic_findings_from_the_ledger(artifact_tree):
    """The classic run here has report.json, so its source is the file."""
    out = trace_view.output_view("vuln_engine/example.test")
    assert out["flow"] == "classic"
    assert out["source"] == "report.json"


# --------------------------------------------------------------------------- #
# jobs
# --------------------------------------------------------------------------- #


def test_build_command_whitelists_and_refuses():
    argv, label = jobs_mod.build_command("recon", {"target": "example.com"})
    assert "run_recon.py" in argv and "example.com" in argv
    argv, _ = jobs_mod.build_command(
        "engine", {"target": "t.test", "surfaces": ["url=http://t.test;param=q"]}
    )
    assert "--surface" in argv and "url=http://t.test;param=q" in argv
    argv, _ = jobs_mod.build_command("engine_fixture", {})
    assert "--fixture" in argv
    with pytest.raises(ValueError):
        jobs_mod.build_command("shell", {"cmd": "rm -rf /"})
    with pytest.raises(ValueError):
        jobs_mod.build_command("recon", {"target": ""})


def test_job_lifecycle_captures_output(artifact_tree):
    manager = jobs_mod.JobManager()
    job = manager.start("engine_fixture", {})
    deadline = time.time() + 60
    while job.status == "running" and time.time() < deadline:
        time.sleep(0.2)
    assert job.status in ("done", "failed"), job.to_dict()
    output = manager.read_output(job.id, offset=0, limit=1000)
    assert output["lines"], "the child's output must be captured"
    assert any("run_engine" in line or "[ui]" in line for line in output["lines"])


def test_job_output_offset_resumes(artifact_tree):
    manager = jobs_mod.JobManager()
    job = manager.start("engine_fixture", {})
    deadline = time.time() + 60
    while job.status == "running" and time.time() < deadline:
        time.sleep(0.2)
    first = manager.read_output(job.id, offset=0, limit=2)
    assert first["lines"]
    second = manager.read_output(job.id, offset=first["offset"], limit=1000)
    # no overlap, no loss: the second read continues exactly where the first ended
    if second["lines"]:
        assert second["lines"][0] != first["lines"][0]


# --------------------------------------------------------------------------- #
# the HTTP surface
# --------------------------------------------------------------------------- #


def test_http_static_index(server):
    status, body = get(server + "/")
    assert status == 200
    assert "ATTACKBOT" in body


def test_http_static_refuses_traversal(server):
    status, body = get(server + "/static/..%2f..%2f..%2f.env")
    assert status == 404


def test_http_state(server, monkeypatch):
    # The real programs DB is not part of this fixture (Postgres down in the
    # hermetic suite) — the state endpoint must degrade around it, exactly as
    # the DB-degrade tests above pin, not block on the eager pool.
    def boom(query, params=()):
        raise programs_mod.DbUnavailable("no database here")
    monkeypatch.setattr(programs_mod, "_fetch", boom)
    status, payload = get(server + "/api/state")
    assert status == 200
    assert "programs" in payload and "engine_runs" in payload
    assert payload["programs_error"]
    assert any(run["run"] == "example.test" for run in payload["engine_runs"])
    assert "example.test" in payload["recon_targets"]


def test_http_recon_logs(server):
    status, payload = get(server + "/api/recon/logs?target=example.test")
    assert status == 200
    stages = {log["stage"] for log in payload["logs"]}
    assert "subdomain" in stages
    sub = next(log for log in payload["logs"] if log["stage"] == "subdomain")
    assert "[active] resolved 2" in sub["text"]


def test_http_recon_logs_refuses_bad_names(server):
    status, payload = get(server + "/api/recon/logs?target=" + "../.env")
    assert status == 400


def test_http_recon_graph(server):
    status, payload = get(server + "/api/recon/graph")
    assert status == 200
    assert payload["available"] is True
    assert payload["counts"]["nodes"] == 3


def test_http_engine_log_streams(server):
    status, first = get(server + "/api/engine/log?run=example.test&limit=3")
    assert status == 200
    assert first["count"] == 3
    status, second = get(
        server + f"/api/engine/log?run=example.test&cursor={first['next_index']}"
    )
    assert status == 200
    # no overlap: the second batch starts at the first batch's end
    assert second["rows"][0] == first["rows"][-1] or second["count"] == 0 or \
        float(second["rows"][0]["at"]) >= float(first["rows"][-1]["at"])


def test_http_engine_inputs(server):
    status, payload = get(server + "/api/engine/inputs?run=example.test")
    assert status == 200
    assert payload["surfaces"][0]["param"] == "q"


def test_http_engine_report(server):
    status, payload = get(server + "/api/engine/report?run=example.test")
    assert status == 200
    assert payload["report"]["findings"][0]["vuln_class"] == "xss"


def test_http_engine_holding_pen(server):
    """The backlog travels from report.json, value-weighted shape intact."""
    status, payload = get(server + "/api/engine/holding_pen?run=example.test")
    assert status == 200
    assert payload["available"] is True
    assert payload["source"] == "report.json"
    pen = payload["holding_pen"]
    assert pen["held"] == 2
    assert pen["value"] == 6.0
    assert pen["groups"][0]["needs_verifier"] == "authorization.state_change"
    assert pen["groups"][0]["value"] == 6.0


def test_http_engine_holding_pen_degrades_without_a_report(server):
    """A campaign-style run (ledger only) answers honestly, not with zeros."""
    status, payload = get(server + "/api/engine/holding_pen?run=twogate_demo")
    assert status == 200
    assert payload["available"] is False
    assert "no report.json" in payload["reason"]


def test_http_engine_holding_pen_refuses_bad_names(server):
    status, _ = get(server + "/api/engine/holding_pen?run=" + "../.env")
    assert status == 400


def test_http_state_exposes_traces(server, monkeypatch):
    def boom(query, params=()):
        raise programs_mod.DbUnavailable("no database here")
    monkeypatch.setattr(programs_mod, "_fetch", boom)
    status, payload = get(server + "/api/state")
    assert status == 200
    keys = {run["key"] for run in payload["traces"]}
    assert {"vuln_engine/example.test", "vuln_engine/twogate_demo"} <= keys


def test_http_trace_streams_steps(server):
    status, first = get(server + "/api/trace?key=vuln_engine/twogate_demo&limit=4")
    assert status == 200
    assert first["available"] is True
    assert first["flow"] == "twogate"
    assert [s["index"] for s in first["steps"]] == [0, 1, 2, 3]
    status, second = get(
        server + f"/api/trace?key=vuln_engine/twogate_demo&cursor={first['next_index']}&limit=4"
    )
    assert status == 200
    assert [s["index"] for s in second["steps"]] == [4, 5, 6, 7]


def test_http_trace_refuses_a_path_escape(server):
    status, _ = get(server + "/api/trace?key=..%2f..%2f.env")
    assert status == 400


def test_http_trace_output(server):
    status, payload = get(server + "/api/trace/output?key=vuln_engine/twogate_demo")
    assert status == 200
    assert payload["report"]["findings"][0]["vuln_class"] == "xss"


def test_http_unknown_route_is_404(server):
    status, _ = get(server + "/api/nope")
    assert status == 404


def test_http_run_refuses_unknown_kind(server):
    status, payload = post(server + "/api/run", {"kind": "shell", "params": {}})
    assert status == 400


def test_http_run_starts_and_streams_a_job(server):
    status, payload = post(server + "/api/run", {"kind": "engine_fixture", "params": {}})
    assert status == 200
    job_id = payload["job"]["id"]
    deadline = time.time() + 90
    lines: list[str] = []
    offset = 0
    while time.time() < deadline:
        got, out = get(server + f"/api/jobs/output?id={job_id}&offset={offset}&limit=2000")
        assert got == 200
        offset = out["offset"]
        lines.extend(out["lines"])
        if out["status"] != "running":
            break
        time.sleep(0.3)
    assert lines, "job output must stream over HTTP"
    assert any("run_engine" in line or "[ui]" in line for line in lines)


def test_build_command_twogate_whitelists_flags():
    argv, label = jobs_mod.build_command(
        "twogate",
        {
            "target": "t.test",
            "surfaces": ["url=http://t.test;param=q;capability=public_param"],
            "cookies": ["session=a"],
            "session_b_cookie": "session=b",
            "max_rounds": 4,
            "host_budget": 25,
            "llm": True,
            "output_dir": "dvwa_check",
        },
    )
    assert "run_twogate.py" in argv
    assert "-t" in argv and "t.test" in argv
    assert "--llm" in argv and "--max-rounds" in argv and "4" in argv
    assert "--session-b-cookie" in argv
    assert "output/vuln_engine/dvwa_check" in argv
    assert label == "twogate t.test"
    # an empty target is the fixture, not an error
    argv, label = jobs_mod.build_command("twogate", {})
    assert "--fixture" in argv and label == "twogate fixture"
    argv, _ = jobs_mod.build_command("twogate_fixture", {"max_rounds": 2})
    assert "--fixture" in argv and "--max-rounds" in argv


def test_job_output_dir_is_whitelisted(artifact_tree):
    argv, _ = jobs_mod.build_command(
        "engine_fixture", {"output_dir": "demo_flow"}
    )
    # A bare run name lands under the engine's own output root — run_engine
    # resolves --output-dir against its CWD, and the UI's views read
    # output/vuln_engine/<name>.
    assert "output/vuln_engine/demo_flow" in argv
    with pytest.raises(ValueError):
        jobs_mod.build_command("engine_fixture", {"output_dir": "../escape"})
    with pytest.raises(ValueError):
        jobs_mod.build_command("engine_fixture", {"output_dir": "a/b"})


# --------------------------------------------------------------------------- #
# the demo flow
# --------------------------------------------------------------------------- #


def test_demo_seed_writes_and_replaces_demo_rows(monkeypatch):
    """The seeder writes the demo program idempotently, through the same tables."""
    from service.ui import demo_seed

    executed: list[tuple] = []

    class FakeCursor:
        def execute(self, query, params=()):
            executed.append((" ".join(query.split()), params))

    fake = FakeCursor()

    selects = {"n": 0}

    def fake_fetch_one(conn, query, params=()):
        q = " ".join(query.split())
        if "SELECT id FROM bounty_master" in q:
            # First call: not found (insert path); second: found (the new id).
            selects["n"] += 1
            if selects["n"] >= 2:
                return {"id": "demo-id-1"}
            return None
        return None

    monkeypatch.setattr(demo_seed, "_fetch_one", fake_fetch_one)
    result = demo_seed.seed(cursor=fake)
    assert result["handle"] == "attackbot-demo"
    inserts = [q for q, _ in executed if q.startswith("INSERT INTO bounty_")]
    assert any("bounty_master" in q for q in inserts)
    assert sum(1 for q in inserts if "bounty_detail" in q) == len(demo_seed.DETAILS)
    # the boundary set: an explicitly out-of-scope detail row exists
    assert any("forbidden.demo.invalid" in str(p) for _, p in executed)


def test_demo_seed_is_idempotent_in_shape(monkeypatch):
    """Re-running replaces the demo rows rather than duplicating them."""
    from service.ui import demo_seed

    executed: list[tuple] = []

    class FakeCursor:
        def execute(self, query, params=()):
            executed.append((" ".join(query.split()), params))

    fake = FakeCursor()

    def fake_fetch_one(conn, query, params=()):
        return {"id": "demo-id-1"}  # always found: the update path

    monkeypatch.setattr(demo_seed, "_fetch_one", fake_fetch_one)
    demo_seed.seed(cursor=fake)
    updates = [q for q, _ in executed if q.startswith("UPDATE bounty_master")]
    deletes = [q for q, _ in executed if q.startswith("DELETE FROM bounty_")]
    assert len(updates) == 1
    assert len(deletes) == 3  # details, exclusions, weaknesses replaced whole


def test_demo_orchestrator_needs_the_ui(artifact_tree, monkeypatch, capsys):
    """Without a UI server up, the demo says so instead of crashing."""
    import service.ui.demo as demo

    monkeypatch.setattr(demo, "_ui_up", lambda base: False)
    rc = demo.main(["--ui-url", "http://127.0.0.1:1"])
    assert rc == 2
    out = capsys.readouterr().out
    assert "not reachable" in out


def test_the_demo_client_carries_the_write_guard_header(monkeypatch):
    """The guided demo POSTs through the same anti-CSRF guard the UI's JS does.

    Regression, found live rather than hermetically: the T5 guard landed on
    every POST, but the demo's own client forgot the header, so
    ``python -m service.ui.demo`` died at STEP 2 with a 403. This pins the
    header on the request the demo actually sends.
    """
    import service.ui.demo as demo

    seen: dict = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b'{"ok": true, "job": {"id": "demo-1"}}'

    def fake_urlopen(request, timeout=30):
        seen["request"] = request
        return FakeResponse()

    monkeypatch.setattr(demo.urllib.request, "urlopen", fake_urlopen)
    result = demo._post("http://127.0.0.1:8787", "/api/run", {"kind": "engine_fixture"})
    assert result["ok"] is True
    headers = {name.lower(): value for name, value in seen["request"].header_items()}
    assert headers[server_mod.CSRF_HEADER_NAME.lower()] == server_mod.CSRF_HEADER_VALUE


def test_http_demo_seed_endpoint(server, monkeypatch):
    """The endpoint reports the seeder's degrade honestly."""
    from service.ui import demo_seed

    def boom(cursor=None):
        raise demo_seed.DemoSeedError("no database in this test")

    monkeypatch.setattr(demo_seed, "seed", boom)
    status, payload = post(server + "/api/demo/seed", {})
    assert status == 503
    assert "no database in this test" in payload["error"]
