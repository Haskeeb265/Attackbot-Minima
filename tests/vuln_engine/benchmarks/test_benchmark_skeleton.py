"""The benchmark skeleton's own invariants.

The benchmark consumes engine artifacts; the engine must not know the benchmark
exists. These tests pin the isolation rules mechanically — the import
direction, the loopback guard, the schema gate — and validate the scorer
against the two completed bouts' known outcomes, which is the scorer's own
ground truth: if the scorer cannot reproduce DVWA's two TPs and Juice Shop's
honest zero, the framework is measuring nothing.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BENCHMARKS = ROOT / "benchmarks"
ENGINE = ROOT / "service" / "vuln_engine"


# --------------------------------------------------------------------------- #
# the import direction: the engine must not reference the benchmark
# --------------------------------------------------------------------------- #


def test_no_engine_module_references_the_benchmark() -> None:
    """The one-way door, enforced: ground truth may not leak into runtime
    because the engine cannot even name the package it lives in."""
    offenders: list[str] = []
    for path in ENGINE.rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="replace")
        if "benchmark" in text.lower():
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == [], (
        "engine modules must not reference the benchmark: " + ", ".join(offenders)
    )


def test_run_engine_never_names_a_vwa_target() -> None:
    """Target names live in operator layer and benchmark only."""
    for path in (ENGINE.rglob("*.py")):
        text = path.read_text(encoding="utf-8", errors="replace").lower()
        for name in ("dvwa", "juice", "webgoat", "mutillidae", "bwapp"):
            assert name not in text, f"{path} mentions {name!r}"


# --------------------------------------------------------------------------- #
# case loading: schema gate and the loopback guard
# --------------------------------------------------------------------------- #


def _runner_symbol(name: str):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "run_benchmark", BENCHMARKS / "run_benchmark.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return getattr(module, name)


def test_every_case_passes_the_schema_gate_and_the_loopback_guard() -> None:
    load_case = _runner_symbol("load_case")
    check_loopback = _runner_symbol("check_loopback")
    case_dirs = [p for p in (BENCHMARKS / "vwas").iterdir() if p.is_dir()]
    assert len(case_dirs) >= 2, "the skeleton ships with two cases"
    for path in case_dirs:
        case = load_case(path.name)
        check_loopback(case)
        assert case["target"]["image"].startswith("sha256:") or "@sha256:" in case["target"]["image"], (
            f"{path.name}: image must be digest-pinned"
        )


def test_the_loopback_guard_refuses_a_real_host() -> None:
    check_loopback = _runner_symbol("check_loopback")
    case = {
        "id": "bad",
        "declared_surfaces": [{"url": "https://example.com/x", "param": "q"}],
    }
    try:
        check_loopback(case)
    except SystemExit as exc:
        assert "non-loopback" in str(exc)
    else:  # pragma: no cover - the guard must refuse
        raise AssertionError("the loopback guard did not refuse example.com")


# --------------------------------------------------------------------------- #
# the scorer, validated against the bouts' known outcomes
# --------------------------------------------------------------------------- #


def _scorer_symbol(name: str):
    import importlib.util

    spec = importlib.util.spec_from_file_location("score", BENCHMARKS / "score.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return getattr(module, name)


def _dvwa_pass_dir(tmp_path: Path) -> Path:
    """A synthetic pass dir whose log is the DVWA bout's shape: 2 TPs."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    log = tmp_path / "world.jsonl"
    rows = [
        {"type": "run.begin", "surfaces": [
            {"url": "http://127.0.0.1:4280/vulnerabilities/xss_r/", "host": "127.0.0.1", "param": "name"},
            {"url": "http://127.0.0.1:4280/vulnerabilities/sqli_blind/?Submit=Submit", "host": "127.0.0.1", "param": "id"},
        ]},
        {"type": "candidate", "id": "xss_reflected:127.0.0.1:/vulnerabilities/xss_r/:name",
         "vuln_class": "xss",
         "surface": {"url": "http://127.0.0.1:4280/vulnerabilities/xss_r/", "host": "127.0.0.1", "param": "name"}},
        {"type": "verdict", "candidate": "xss_reflected:127.0.0.1:/vulnerabilities/xss_r/:name",
         "proven": True, "grade": "execution"},
        {"type": "candidate", "id": "sqli_blind_time:127.0.0.1:/vulnerabilities/sqli_blind/?Submit=Submit:id",
         "vuln_class": "sqli",
         "surface": {"url": "http://127.0.0.1:4280/vulnerabilities/sqli_blind/?Submit=Submit", "host": "127.0.0.1", "param": "id"}},
        {"type": "verdict", "candidate": "sqli_blind_time:127.0.0.1:/vulnerabilities/sqli_blind/?Submit=Submit:id",
         "proven": True, "grade": "differential"},
        {"type": "receipt", "arm": "xss_reflected@xss_r", "outcome": "found"},
        {"type": "receipt", "arm": "sqli_blind_time@sqli_blind", "outcome": "found"},
    ]
    log.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    return tmp_path


def test_the_scorer_reproduces_the_dvwa_bout_scorecard(tmp_path: Path) -> None:
    score_case = _scorer_symbol("score_case")
    pass_dir = _dvwa_pass_dir(tmp_path / "dvwa-low" / "cf006da-fast" / "dvwa-low")
    scorecard = score_case("dvwa-low", pass_dir=pass_dir)

    outcomes = {row["vuln_id"]: row["outcome"] for row in scorecard["rows"]}
    assert outcomes["dvwa-low/xss_r/name"] == "TP"
    assert outcomes["dvwa-low/sqli_blind/id"] == "TP"
    # The undeclared GT entries must not count against the engine's recall...
    assert outcomes["dvwa-low/commandi/ip"] == "miss"
    assert scorecard["declared_gt"] == 2
    assert scorecard["recall_declared"] == 1.0
    # ...and the evidence classes must match what the bout actually produced.
    got = {row["vuln_id"]: row["got_evidence"] for row in scorecard["rows"]}
    assert got["dvwa-low/xss_r/name"] == "execution"
    assert got["dvwa-low/sqli_blind/id"] == "differential"


def test_the_scorer_surfaces_unadjudicated_findings(tmp_path: Path) -> None:
    """A finding matching no GT entry is unadjudicated — never a silent FP."""
    score_case = _scorer_symbol("score_case")
    pass_dir = tmp_path / "dvwa-low" / "x-fast" / "dvwa-low"
    pass_dir.mkdir(parents=True)
    log = pass_dir / "world.jsonl"
    rows = [
        {"type": "run.begin", "surfaces": []},
        {"type": "candidate", "id": "oob_fetch:127.0.0.1:/somewhere:url", "vuln_class": "ssrf",
         "surface": {"url": "http://127.0.0.1:4280/somewhere", "host": "127.0.0.1", "param": "url"}},
        {"type": "verdict", "candidate": "oob_fetch:127.0.0.1:/somewhere:url", "proven": True, "grade": "oob"},
    ]
    log.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    scorecard = score_case("dvwa-low", pass_dir=pass_dir)
    assert scorecard["unadjudicated"] == [
        {"candidate_id": "oob_fetch:127.0.0.1:/somewhere:url", "vuln_class": "ssrf"}
    ]


def test_the_juice_shop_case_declares_its_correct_negative(tmp_path: Path) -> None:
    """The JSON API's GT entry is a correct-negative: settling none there is a
    pass, which is what makes the case honest about its zero."""
    gt = json.loads(
        (BENCHMARKS / "vwas" / "juice-shop" / "ground-truth.json").read_text(encoding="utf-8")
    )
    negatives = [v for v in gt["vulns"] if v["vuln_class"] == "none"]
    assert len(negatives) == 1
    assert negatives[0]["reachable_by_declaration"] is True
    assert negatives[0]["tier"] == "T1"
