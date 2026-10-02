"""The guided demo: the whole flow through a test, watched in the UI.

One command::

    python -m service.ui.demo           # --seed skips if already seeded

and it drives, printing what to watch in the UI as each stage runs:

1. **Program**  — seed the demo program into the scraper's tables (the same
   rows the scraper persists), so panel 1 shows a complete program document.
2. **Engine**   — run the vuln engine against the compose fixture app via the
   UI's own job runner (the same POST the Run panel makes), with the fixture's
   two declared surfaces plus an IDOR surface.
3. **Realtime** — tail the engine's world log exactly as panel 5 does while
   the run streams (picks → hypotheses → gated requests → observations →
   candidates → verdicts).
4. **Output**   — read the run's findings the way panel 6 does.

Everything targets 127.0.0.1 and the compose containers only; nothing is sent
anywhere else. It is the flow of a real engagement with the target swapped for
the fixture — not a separate path: the demo POSTs to ``/api/run`` and reads
``/api/engine/log`` like the UI does, so what you watch is what the UI shows.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from service.ui.artifacts import ROOT

UI_URL = "http://127.0.0.1:8787"
#: The engine output dir for the demo run — isolated, so the run is clean and
#: its world log is only this demo's rows.
DEMO_RUN_DIR = "demo_flow"

STEP = "\n\033[1;36m==>\033[0m \033[1m{}\033[0m"
INFO = "    \033[2m{}\033[0m"
GOOD = "    \033[1;32m{}\033[0m"
WARN = "    \033[1;33m{}\033[0m"
BAD = "    \033[1;31m{}\033[0m"

#: The fixture's two planted surfaces (the Phase 1 profile) plus the IDOR
#: surface M2 added. Capabilities are the operator's claims; the gate still
#: decides everything.
SURFACES = [
    "url=http://127.0.0.1:8080/search;param=q;capability=public_param",
    "url=http://127.0.0.1:8080/fetch;param=url;capability=can_influence_remote_fetch",
    "url=http://127.0.0.1:8080/api/invoices/4821;param=4821;capability=access_differs_by_session",
]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m service.ui.demo",
        description="Run the whole Attackbot flow against the local fixtures, watched in the UI.",
    )
    parser.add_argument("--ui-url", default=UI_URL, help="the UI server (default %(default)s)")
    parser.add_argument("--seed-only", action="store_true", help="seed the demo program and stop")
    parser.add_argument("--force", action="store_true", help="ignore the receipts ledger on the engine run")
    args = parser.parse_args(argv)

    base = args.ui_url.rstrip("/")
    print(__doc__.split("\n\n")[0])

    # ------------------------------------------------------------------ #
    print(STEP.format("STEP 1 · the program (watch panel 1: Program)"))
    try:
        from service.ui.demo_seed import seed

        result = seed()
        print(GOOD.format(
            f"demo program seeded: {result['details']} scope rows, "
            f"{result['exclusions']} exclusions, {result['weaknesses']} weakness classes"
        ))
        print(INFO.format(f"handle: {result['handle']} — select it in panel 1"))
    except Exception as exc:
        print(WARN.format(f"program seeding skipped: {exc}"))
        print(INFO.format("(no Docker/Postgres? panels 2-6 still work — they read files)"))

    if args.seed_only:
        return 0

    # ------------------------------------------------------------------ #
    print(STEP.format("STEP 2 · the engine run (watch panel 4: Engine inputs)"))
    if not _ui_up(base):
        print(BAD.format(f"the UI server is not reachable at {base}"))
        print(INFO.format("start it in another terminal:  python -m service.ui.server"))
        return 2

    surfaces = list(SURFACES)
    if args.force:
        payload = {"kind": "engine", "params": {
            "target": "127.0.0.1", "surfaces": surfaces,
            "cookies": ["session=a1b2c3d4e5f6"],
            "session_b_cookie": "session=9f8e7d6c5b4a",
            "campaign": 4, "host_budget": 200, "force": True,
            "output_dir": DEMO_RUN_DIR,
        }}
    else:
        payload = {"kind": "engine_fixture", "params": {
            "campaign": 4, "force": True, "output_dir": DEMO_RUN_DIR,
        }}
    job = _post(base, "/api/run", payload).get("job") or {}
    job_id = job.get("id", "")
    if not job_id:
        print(BAD.format(f"the UI refused the run: {job}"))
        return 2
    print(GOOD.format(f"job {job_id} started ({job.get('label', '')})"))
    for surface in surfaces:
        print(INFO.format(f"surface: {surface}"))

    # ------------------------------------------------------------------ #
    print(STEP.format("STEP 3 · the world log, live (watch panel 5: Engine log — press Follow)"))
    run = DEMO_RUN_DIR
    cursor = 0
    seen_types: dict[str, int] = {}
    polls = 0
    last_status = ""
    while True:
        polls += 1
        try:
            log = _get(base, f"/api/engine/log?run={run}&cursor={cursor}&limit=200")
            for row in log.get("rows", []):
                row_type = str(row.get("type", ""))
                seen_types[row_type] = seen_types.get(row_type, 0) + 1
                if row_type in ("verdict", "candidate", "gate.decision") and seen_types[row_type] <= 3:
                    if row_type == "verdict":
                        print(GOOD.format(
                            f"  VERDICT: proven={row.get('proven')} grade={row.get('grade')} — {row.get('reason', '')[:70]}"
                        ))
                    elif row_type == "candidate":
                        print(INFO.format(
                            f"  candidate: [{row.get('vuln_class', '')}] {row.get('summary', '')[:70]}"
                        ))
                    else:
                        print(INFO.format(
                            f"  gate: {row.get('verb')} {row.get('host')} — {row.get('reason', '')[:60]}"
                        ))
            cursor = int(log.get("next_index", cursor))
            job_out = _get(base, f"/api/jobs/output?id={job_id}&offset=0&limit=3")
            status = str(job_out.get("status", ""))
            if status != last_status:
                print(INFO.format(f"job status: {status}"))
                last_status = status
            if status != "running" and log.get("count") == 0:
                break
            if status == "running" and polls > 120:
                print(WARN.format("timed out waiting for the run to finish"))
                break
        except urllib.error.HTTPError as exc:
            print(BAD.format(f"stream interrupted: {exc}"))
            return 2
        time.sleep(0.8)

    print(GOOD.format(f"streamed {cursor} world-log rows live; by type:"))
    for row_type, count in sorted(seen_types.items()):
        print(INFO.format(f"  {row_type}: {count}"))

    # ------------------------------------------------------------------ #
    print(STEP.format("STEP 4 · the findings (watch panel 6: Engine output)"))
    report = _get(base, f"/api/engine/report?run={run}")
    findings = (report.get("report") or {}).get("findings") or []
    if findings:
        for finding in findings:
            print(GOOD.format(
                f"FINDING [{finding.get('vuln_class', '?')}] grade={finding.get('grade', '?')}"
            ))
            print(INFO.format(f"  {finding.get('summary', '')}"))
            if finding.get("repro_url"):
                print(INFO.format(f"  repro: {finding['repro_url']}"))
    else:
        print(WARN.format("no findings in this run — check the log panel for the refusals"))

    overview = _get(base, f"/api/engine/overview?run={run}")
    print(GOOD.format(
        f"ledger: {overview.get('rows')} rows · gate {overview.get('gate')} · findings {overview.get('findings')}"
    ))

    print(STEP.format("Done. Open the UI and switch panels — everything you just watched is still there."))
    return 0


def _ui_up(base: str) -> bool:
    try:
        _get(base, "/api/state")
        return True
    except (urllib.error.URLError, OSError):
        return False


def _get(base: str, path: str) -> dict:
    with urllib.request.urlopen(base + path, timeout=30) as res:
        return json.loads(res.read().decode("utf-8"))


def _post(base: str, path: str, payload: dict) -> dict:
    request = urllib.request.Request(
        base + path, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as res:
        return json.loads(res.read().decode("utf-8"))


if __name__ == "__main__":
    sys.exit(main())
