#!/usr/bin/env python3
"""Run the VWA benchmark: one case at a time, through the ordinary pipeline.

The runner is the *operator*, not the engine: it reads a case's declared
surfaces and session shape and invokes ``run_engine.py`` with the same flags a
human would use. Ground truth is never passed to the engine — not in argv, not
in the environment, not in the output directory — so the engine physically
cannot consult it. Comparison happens afterwards, in ``score.py``, from the
artifacts the run emitted.

Isolation rules (proposal §2):
  * process isolation — one subprocess per case, no in-process scheduler use;
  * output isolation — results land in ``benchmarks/results/<case>/<pass-id>/``,
    never ``output/vuln_engine/``;
  * policy isolation — nothing here touches scope or the gate; a DENY is a
    scored outcome, not a bypass;
  * loopback guard — a case whose target is not loopback is refused before any
    traffic can be considered.

Usage::

    python benchmarks/run_benchmark.py dvwa-low
    python benchmarks/run_benchmark.py --all --tier full
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
CASES_DIR = ROOT / "benchmarks" / "vwas"
RESULTS_DIR = ROOT / "benchmarks" / "results"
ENGINE = ROOT / "run_engine.py"


def load_case(case_id: str) -> dict:
    """Read and validate one case file (schema 1)."""
    path = CASES_DIR / case_id / "case.json"
    case = json.loads(path.read_text(encoding="utf-8"))
    if case.get("schema") != 1:
        raise SystemExit(f"{path}: unsupported schema {case.get('schema')!r}")
    if case.get("id") != case_id:
        raise SystemExit(f"{path}: id {case.get('id')!r} does not match directory {case_id!r}")
    return case


def check_loopback(case: dict) -> None:
    """Refuse any case whose declared target is not loopback."""
    for surface in case.get("declared_surfaces", []):
        host = (urlsplit(surface["url"]).hostname or "").lower()
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise SystemExit(
                f"case {case['id']!r} declares a non-loopback target ({host!r}); "
                "the benchmark runs against local compose only"
            )


def _session_cookies(case: dict) -> list[str]:
    """Literal ``NAME=VALUE`` pairs for the engine's ``--cookie`` flag.

    A case may declare a bootstrap script (DVWA needs login plus a security
    level before any surface works, which is operator work by definition). The
    script runs fresh per pass and its printed ``cookie header:`` line is
    parsed, so a pass never reuses another pass's session. ``seeded_cookies``
    entries are merged in verbatim (a case can pin ``security=low`` without
    knowing the session id), and the declared cookie *names* become a check:
    a bootstrap that produced nothing the case expected fails the pass here,
    before the engine wastes a run on a dead session.
    """
    session = case.get("session", {})
    cookies: list[str] = []
    bootstrap = session.get("bootstrap", "")
    if bootstrap:
        script = ROOT / bootstrap
        if not script.is_file():
            raise SystemExit(f"case {case['id']!r}: bootstrap script missing: {bootstrap}")
        print(f"  bootstrapping session via {bootstrap} ...")
        completed = subprocess.run(
            [sys.executable, str(script)], capture_output=True, text=True, cwd=ROOT
        )
        if completed.returncode != 0:
            raise SystemExit(
                f"case {case['id']!r}: bootstrap failed (exit {completed.returncode}):\n"
                f"{completed.stderr.strip()}"
            )
        match = re.search(r"cookie header:\s*(\S.*)", completed.stdout)
        if not match:
            raise SystemExit(
                f"case {case['id']!r}: bootstrap printed no 'cookie header:' line; "
                f"got: {completed.stdout.strip()!r}"
            )
        cookies = [chunk.strip() for chunk in match.group(1).split(";") if chunk.strip()]
    for cookie in session.get("seeded_cookies", []):
        if cookie not in cookies:
            cookies.append(cookie)
    declared = session.get("cookies", [])
    if declared:
        names = {chunk.split("=", 1)[0].strip() for chunk in cookies}
        missing = [name for name in declared if name not in names]
        if missing:
            raise SystemExit(
                f"case {case['id']!r}: session produced no cookie named {', '.join(missing)}"
            )
    return cookies


def pass_id(tier: str) -> str:
    """The pass directory name: git SHA + tier, so a scorecard row is keyed."""
    try:
        sha = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, check=True, cwd=ROOT,
        ).stdout.strip()
    except Exception:  # noqa: BLE001 - a missing git is not a benchmark blocker
        sha = "nogit"
    return f"{sha}-{tier}"


def run_case(case_id: str, *, tier: str, engine_args: list[str] | None = None) -> Path:
    """Run one case end to end and return the pass directory."""
    case = load_case(case_id)
    check_loopback(case)

    out_dir = RESULTS_DIR / case_id / pass_id(tier) / case_id
    if out_dir.exists():
        # One pass per (sha, tier, case): a re-run replaces the artifacts so a
        # scorecard never mixes passes.
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    command = [
        sys.executable, str(ENGINE),
        "-t", str(case["target"]["host"]),
        "--declare", str(case["target"]["host"]),
        "--campaign", str(case.get("campaign_rounds", 6)),
        "--output-dir", str(out_dir),
        "--force",
    ]
    for cookie in _session_cookies(case):
        command.extend(["--cookie", cookie])
    for surface in case.get("declared_surfaces", []):
        fields = [
            f"url={surface['url']}",
            f"param={surface['param']}",
            f"where={surface.get('where', 'query')}",
            f"capability={surface.get('capability', 'public_param')}",
        ]
        if surface.get("label"):
            fields.append(f"label={surface['label']}")
        command.extend(["--surface", ";".join(fields)])
    if tier == "llm-ab" or engine_args:
        command.extend(engine_args or ["--llm-draft"])

    started = time.monotonic()
    completed = subprocess.run(command, capture_output=True, text=True, cwd=ROOT)
    elapsed = time.monotonic() - started

    meta = {
        "case_id": case_id,
        "tier": tier,
        "image": case["target"].get("image", ""),
        "returncode": completed.returncode,
        "elapsed_seconds": round(elapsed, 1),
        "command": command,
    }
    (out_dir / "pass.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    (out_dir / "stdout.txt").write_text(completed.stdout, encoding="utf-8")
    (out_dir / "stderr.txt").write_text(completed.stderr, encoding="utf-8")
    if not (out_dir / "world.jsonl").is_file():
        raise SystemExit(
            f"case {case_id!r} produced no world log (returncode {completed.returncode}); "
            f"see {out_dir / 'stderr.txt'}"
        )
    print(f"  {case_id}: {elapsed:.0f}s -> {out_dir.relative_to(ROOT)}")
    return out_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run VWA benchmark cases.")
    parser.add_argument("cases", nargs="*", help="case ids (directory names under benchmarks/vwas)")
    parser.add_argument("--all", action="store_true", help="run every case")
    parser.add_argument("--tier", default="fast", choices=("fast", "full", "llm-ab"))
    args = parser.parse_args(argv)

    case_ids = (
        sorted(p.name for p in CASES_DIR.iterdir() if p.is_dir())
        if args.all else args.cases
    )
    if not case_ids:
        parser.error("no cases given (and --all not set)")

    print(f"benchmark pass, tier={args.tier}:")
    for case_id in case_ids:
        run_case(case_id, tier=args.tier)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
