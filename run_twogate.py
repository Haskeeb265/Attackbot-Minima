#!/usr/bin/env python3
"""Run the two-gate flow against one engagement.

    recon seed ─▶ capability prober ─▶ capability agent ─▶ planner
                                          ▲                 │
                                          │ observations    ▼
                                          └── loop-back ◀── confirmation runner ◀── verifier agent

Same policy gate, same transports, same append-only world log as the classic
engine — but the eligibility gate is *measured* (the prober) and the confirmation
gate is a declarative spec run by a deterministic oracle. A model may advise the
two agents; with no key the whole flow is deterministic.

Usage::

    python run_twogate.py --fixture
    python run_twogate.py -t 127.0.0.1 \
        --surface "url=http://127.0.0.1:8080/search;param=q"
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

from service.vuln_engine.policy.gate import PolicyGate, default_effects  # noqa: E402
from service.vuln_engine.twogate import StoppingCriteria, TwoGateLoop  # noqa: E402
from service.vuln_engine.world.log import WorldLog  # noqa: E402

from run_engine import (  # noqa: E402
    COLLABORATOR_PORT,
    DEFAULT_OUTPUT_ROOT,
    Profile,
    _build_graph_backend,
    fixture_profile,
    load_env_file,
    parse_surface,
    target_profile,
)
from service.vuln_engine.kernel.technique import EngagementSeed  # noqa: E402
from service.vuln_engine.paths import safe_component  # noqa: E402
from service.vuln_engine.seed import (  # noqa: E402
    DEFAULT_MAX_SURFACES,
    derive_surfaces,
    merge_surfaces,
)


def build_gate(profile: Profile, *, log: WorldLog | None = None) -> PolicyGate:
    """Wire the transports and the gate for *profile* (mirrors ``run_engine.run``)."""
    from service.recon_pipeline.platform import dispatch, escalation

    dispatcher = dispatch.Dispatcher(
        profile.scope,
        policy=dispatch.DispatchPolicy(
            min_score=40, host_budget=profile.host_budget, run_budget=0
        ),
        escalation=escalation.EscalationPolicy(),
    )
    effects = default_effects(
        oob_public_base=profile.collaborator_public,
        oob_local_base=profile.collaborator_local,
        chrome_path=profile.chrome_path,
        driver=profile.browser_driver,
        cookies=profile.cookies,
        session_b_cookie=profile.session_b_cookie,
    )
    return PolicyGate(dispatcher, log=log, **effects)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the two-gate vuln flow.")
    parser.add_argument("--fixture", action="store_true", help="run the fixture profile (default)")
    parser.add_argument("-t", "--target", default="", help="declared target domain")
    parser.add_argument(
        "--surface",
        action="append",
        default=[],
        metavar="url=...;param=...;capability=...",
        help="a declared input surface (repeatable)",
    )
    parser.add_argument("--declare", action="append", default=[], help="extra declared domain/CIDR")
    parser.add_argument("--collaborator-url", default="", help="collaborator URL the TARGET must reach")
    parser.add_argument("--collaborator-local", default="", help="collaborator URL we read records from")
    parser.add_argument("--chrome-path", default="", help="explicit chrome/chromium binary")
    parser.add_argument("--driver", default="auto", choices=("auto", "playwright", "cdp"))
    parser.add_argument("--cookie", action="append", default=[], metavar="NAME=VALUE")
    parser.add_argument("--session-b-cookie", action="append", default=[], metavar="NAME=VALUE")
    parser.add_argument("--host-budget", type=int, default=0)
    parser.add_argument(
        "--from-graph",
        nargs="?",
        const="",
        default=None,
        metavar="PATH",
        help="derive candidate surfaces from the recon graph (a graph_state.json)",
    )
    parser.add_argument("--graph-neo4j", action="store_true", help="use Neo4j as the graph backend")
    parser.add_argument("--max-surfaces", type=int, default=DEFAULT_MAX_SURFACES)
    parser.add_argument("--no-infer-remote-fetch", action="store_true")
    parser.add_argument("--max-rounds", type=int, default=3, help="stopping criteria: rounds per surface")
    parser.add_argument(
        "--llm",
        action="store_true",
        help=(
            "let the model advise the capability and verifier agents (choose among "
            "the closed sets the deterministic core already admits); no key = no-op"
        ),
    )
    parser.add_argument("--output-dir", default="")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    # A target becomes a filesystem name (output/vuln_engine/<target> when
    # --output-dir is not given): refuse a traversal-shaped or separator-bearing
    # one HERE, before any graph, policy or network work happens.
    if args.target:
        safe_component(args.target)
    load_env_file()

    if args.target:
        profile = target_profile(
            args.target,
            surfaces=[parse_surface(token) for token in args.surface],
            declared=args.declare,
            collaborator_public=args.collaborator_url or f"http://oob_collaborator:{COLLABORATOR_PORT}",
            collaborator_local=args.collaborator_local or f"http://127.0.0.1:{COLLABORATOR_PORT}",
            chrome_path=args.chrome_path,
        )
    else:
        profile = fixture_profile(chrome_path=args.chrome_path)
    profile.browser_driver = args.driver
    profile.cookies = "; ".join(args.cookie)
    profile.session_b_cookie = "; ".join(args.session_b_cookie)
    if args.host_budget > 0:
        profile.host_budget = args.host_budget

    if args.from_graph is not None or args.graph_neo4j:
        # Step 1 of the flow: the engine's surfaces come from recon. Out-of-scope
        # and needs-review URLs are filtered by the *same* scope engine the gate
        # uses; operator-declared surfaces win on a collision.
        backend = _build_graph_backend(args)
        derived = derive_surfaces(
            backend,
            scope_state=lambda host: profile.scope.check_host(host).state,
            max_surfaces=max(1, args.max_surfaces),
            infer_remote_fetch=not args.no_infer_remote_fetch,
        )
        profile.seed = EngagementSeed(
            target=profile.target,
            surfaces=tuple(merge_surfaces(list(profile.seed.surfaces), derived.surfaces)),
        )
        print(
            f"graph seed: {len(derived.surfaces)} surface(s) from "
            f"{derived.report.get('urls_considered', 0)} URL node(s); "
            f"filtered {derived.report.get('skipped_out_of_scope', 0)} out-of-scope"
        )

    output_dir = (
        Path(args.output_dir) if args.output_dir
        else DEFAULT_OUTPUT_ROOT / safe_component(profile.target)
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    log = WorldLog(output_dir / "twogate.jsonl")
    gate = build_gate(profile, log=log)

    capability_advisor = None
    verifier_advisor = None
    if args.llm:
        from service.vuln_engine.twogate.advisor import build_advisor

        advisor = build_advisor(log=log, clock=gate.now)
        if advisor is not None:
            capability_advisor = advisor.capability_advisor
            verifier_advisor = advisor.verifier_advisor
    loop = TwoGateLoop(
        profile.seed,
        gate=gate,
        log=log,
        criteria=StoppingCriteria(max_rounds_per_surface=max(1, args.max_rounds)),
        capability_advisor=capability_advisor,
        verifier_advisor=verifier_advisor,
    )
    report = loop.run()
    payload = report.to_dict()
    (output_dir / "twogate_report.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8", newline="\n"
    )

    if args.json:
        print(json.dumps(payload, indent=2))
        return 0

    print(f"two-gate run - {report.target}")
    print(f"  log:          {report.log_path}")
    print(f"  capabilities: {json.dumps(report.capabilities.get('surfaces', {}))}")
    print(f"  rounds:       {report.counts.get('rounds', 0)}")
    print(f"  proposals:    {report.counts.get('proposals', 0)}  planned: {report.counts.get('planned', 0)}")
    print(f"  executions:   {report.counts.get('executions', 0)}")
    print(f"  gate:         {report.gate.get('by_verb', {})}; uncleared: {report.gate.get('uncleared_effects')}")
    print(f"  findings:     {len(report.findings)}")
    for line in report.report_lines:
        print(f"    {line}")
    if report.leads:
        print(f"  leads:        {len(report.leads)}")
    return 0 if report.findings else 1


if __name__ == "__main__":
    sys.exit(main())
