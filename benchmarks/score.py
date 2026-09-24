#!/usr/bin/env python3
"""Score one benchmark pass: join the engine's artifacts against ground truth.

Reads only what the run emitted (world log, report.json) and the case's ground
truth. The join key is **(host, path, param, vuln_class)** — never the payload,
because exact-payload matching would reward payload dictionaries over
capabilities. Outcome per ground-truth entry:

* **TP** — matched by a proven finding (tier and reachability recorded);
* **partial** — observations or a refused candidate exist on the surface/param;
* **miss** — nothing in the log for that surface/param;
* **correct-negative** — a GT entry whose ``vuln_class`` is ``"none"``: the
  engine must settle ``none`` on it, and doing so is a pass, not a miss;
* **unadjudicated** — a finding matching no GT entry: queued for the human
  ruling that either adds it to ground truth as T1 (novel-true) or counts it
  as a false positive.

Precision/recall are computed per GT tier and split by declared reachability —
``recall_declared`` is the engine's score; the gap to ``recall_total`` is the
operator gap. The summary is appended to the case's corpus JSONL so trends are
a query, keyed by pass id (git SHA + tier).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]

#: Findings are keyed by (host, path, param, vuln_class). Path comparison is
#: exact; a GT path of ``/#/search`` never matches ``/api/Products``.


def _join_key(host: str, url: str, param: str, vuln_class: str) -> tuple:
    parts = urlsplit(url)
    return (host.lower(), parts.path, param, vuln_class)


def _host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _display_path(pass_dir: Path) -> str:
    """The pass dir for the scorecard, relative to the repo when it lives there."""
    try:
        return str(pass_dir.relative_to(ROOT))
    except ValueError:  # a pass dir outside the repo (tests, archived runs)
        return str(pass_dir)


def load_findings(log_path: Path) -> list[dict]:
    """The run's proven findings, from the world log's verdict rows."""
    findings: list[dict] = []
    candidates: dict[str, dict] = {}
    for line in log_path.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if row.get("type") == "candidate":
            candidates[row.get("id", "")] = row
        elif row.get("type") == "verdict" and row.get("proven"):
            candidate = candidates.get(row.get("candidate", ""), {})
            findings.append(
                {
                    "candidate_id": row.get("candidate", ""),
                    "vuln_class": candidate.get("vuln_class", ""),
                    "surface": candidate.get("surface", {}),
                    "grade": row.get("grade", ""),
                }
            )
    return findings


def load_outcomes(log_path: Path) -> dict[str, dict[str, int]]:
    """Per-arm receipt outcomes, for correct-negative checking."""
    outcomes: dict[str, dict[str, int]] = {}
    for line in log_path.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if row.get("type") == "receipt":
            arm = str(row.get("arm", ""))
            bucket = outcomes.setdefault(arm, {})
            bucket[str(row.get("outcome", ""))] = bucket.get(str(row.get("outcome", "")), 0) + 1
    return outcomes


def load_observations(log_path: Path) -> set[tuple]:
    """(host, path, param) triples the run actually observed something on."""
    seen: set[tuple] = set()
    for line in log_path.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if row.get("type") == "run.begin":
            for surface in row.get("surfaces", []):
                seen.add(
                    (
                        str(surface.get("host", "")).lower(),
                        urlsplit(str(surface.get("url", ""))).path,
                        str(surface.get("param", "")),
                    )
                )
    return seen


def score_case(case_id: str, *, pass_dir: Path) -> dict:
    """One case's scorecard: the GT join, tiered and reachability-split."""
    case_dir = ROOT / "benchmarks" / "vwas" / case_id
    case = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
    gt = json.loads((case_dir / "ground-truth.json").read_text(encoding="utf-8"))
    log_path = pass_dir / "world.jsonl"

    findings = load_findings(log_path)
    outcomes = load_outcomes(log_path)
    observed = load_observations(log_path)
    declared_keys = {
        _join_key(
            _host_of(surface["url"]),
            surface["url"],
            surface["param"],
            "*",
        )[:3]
        for surface in case.get("declared_surfaces", [])
    }

    rows: list[dict] = []
    matched_findings: set[str] = set()
    for entry in gt.get("vulns", []):
        surface = entry.get("surface", {})
        vuln_class = str(entry.get("vuln_class", ""))
        key = (
            _host_of(f"http://{case['target']['host']}"),
            surface.get("path", ""),
            surface.get("param", ""),
        )
        hits = [
            finding
            for finding in findings
            if _join_key(
                str(finding["surface"].get("host", "")),
                str(finding["surface"].get("url", "")),
                str(finding["surface"].get("param", "")),
                str(finding["vuln_class"]),
            ) == (*key, vuln_class)
        ]
        hit = hits[0] if hits else None
        if hit is not None:
            matched_findings.add(hit["candidate_id"])
        if vuln_class == "none":
            settled_none = any(
                "none" in arms and arms.get("none", 0) > 0 for arms in outcomes.values()
            ) and hit is None
            outcome = "correct-negative" if settled_none else "fp-or-miss"
        elif hit is not None:
            outcome = "TP"
        elif key in observed or key in declared_keys:
            outcome = "partial" if key in observed else "miss"
        else:
            outcome = "miss"
        rows.append(
            {
                "vuln_id": entry.get("id", ""),
                "tier": entry.get("tier", "T3"),
                "declared": bool(entry.get("reachable_by_declaration", False)),
                "expected_evidence": entry.get("expected_evidence", ""),
                "got_evidence": (hit or {}).get("grade", ""),
                "outcome": outcome,
            }
        )

    unadjudicated = [
        finding
        for finding in findings
        if finding["candidate_id"] not in matched_findings
    ]

    tiered: dict[str, dict[str, int]] = {}
    for row in rows:
        if row["outcome"] in ("miss", "partial") and not row["declared"]:
            continue  # undeclared GT does not count against the engine's recall
        bucket = tiered.setdefault(row["tier"], {"tp": 0, "partial": 0, "miss": 0})
        bucket[
            {
                "TP": "tp",
                "partial": "partial",
                "miss": "miss",
                "correct-negative": "tp",  # settling none on a negative is a pass
                "fp-or-miss": "miss",  # failing a declared negative is a failure
            }[row["outcome"]]
        ] += 1

    declared_tps = sum(1 for row in rows if row["outcome"] == "TP" and row["declared"])
    declared_gt = sum(1 for row in rows if row["declared"] and row["outcome"] != "correct-negative")
    return {
        "case_id": case_id,
        "pass_dir": _display_path(pass_dir),
        "rows": rows,
        "tiered": tiered,
        "declared_tps": declared_tps,
        "declared_gt": declared_gt,
        "recall_declared": round(declared_tps / declared_gt, 3) if declared_gt else None,
        "unadjudicated": [
            {"candidate_id": item["candidate_id"], "vuln_class": item["vuln_class"]}
            for item in unadjudicated
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score one benchmark pass.")
    parser.add_argument("pass_dir", help="a pass directory under benchmarks/results/<case>/<pass-id>/<case>")
    args = parser.parse_args(argv)
    pass_dir = Path(args.pass_dir)
    if not (pass_dir / "world.jsonl").is_file():
        parser.error(f"no world.jsonl in {pass_dir}")

    case_id = pass_dir.name
    scorecard = score_case(case_id, pass_dir=pass_dir)
    print(json.dumps(scorecard, indent=2))
    corpus = ROOT / "benchmarks" / "results" / "corpus.jsonl"
    with corpus.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(scorecard, sort_keys=True) + "\n")
    print(f"\nappended to {corpus.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
