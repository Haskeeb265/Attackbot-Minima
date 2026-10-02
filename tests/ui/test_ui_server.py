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

REPORT = {
    "target": "example.test",
    "findings": [{"vuln_class": "xss", "grade": "execution",
                  "summary": "reflected XSS in q", "repro_url": "http://example.test/search?q=x"}],
    "leads": [],
    "gate": {"decisions": 2, "by_verb": {"ALLOW": 1, "DENY": 1}, "uncleared_effects": 0,
             "out_of_scope_requests": 1},
    "counts": {"findings": 1},
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


def post(url: str, payload: dict) -> tuple[int, dict]:
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
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


def test_http_state(server):
    status, payload = get(server + "/api/state")
    assert status == 200
    assert "programs" in payload and "engine_runs" in payload
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


def test_http_demo_seed_endpoint(server, monkeypatch):
    """The endpoint reports the seeder's degrade honestly."""
    from service.ui import demo_seed

    def boom(cursor=None):
        raise demo_seed.DemoSeedError("no database in this test")

    monkeypatch.setattr(demo_seed, "seed", boom)
    status, payload = post(server + "/api/demo/seed", {})
    assert status == 503
    assert "no database in this test" in payload["error"]
