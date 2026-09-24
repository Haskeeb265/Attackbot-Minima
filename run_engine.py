#!/usr/bin/env python3
"""Run the vuln engine against one engagement and write its report.

The thin CLI, mirroring ``run_recon.py``: it wires the pieces together and prints
what the engine proved. Everything it prints is *derived from the world log*
(``vuln_engine.world.views``), so the report cannot claim something the record does
not contain — which is the same rule the recon side's report assembly follows.

Three things it exists to make easy:

``--fixture`` (the default)
    The Phase 1 exit criteria, run against the compose fixture app and the compose
    collaborator. The fixture is **declared in scope as an address** — the honest
    way to authorise a local replica, and the only way criteria 1 and 4 can both
    hold (see the checklist's item 12). Nothing here bypasses the gate;
``--replay LOG``
    Recompute a finished run's decisions from its log, offline. No transports are
    constructed on this path at all, which is the point;
``--json``
    The machine report, for a harness.

Usage::

    docker compose up -d fixture_app oob_collaborator
    python run_engine.py --fixture
    python run_engine.py --replay output/vuln_engine/<target>/world.jsonl
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent

from service.recon_pipeline.platform import dispatch, escalation  # noqa: E402
from service.recon_pipeline.platform.scope import ScopeEngine  # noqa: E402
from service.recon_pipeline.platform.receipt import Receipt  # noqa: E402
from service.vuln_engine.kernel.technique import (  # noqa: E402
    CAP_INFLUENCE_REMOTE_FETCH,
    EngagementSeed,
    Surface,
)
from service.vuln_engine.llm.wiring import Advisory  # noqa: E402
from service.vuln_engine.policy.gate import PolicyGate, default_effects  # noqa: E402
from service.vuln_engine.registry import TechniqueRegistry  # noqa: E402
from service.vuln_engine.scheduler.campaign import Budget, Campaign, CampaignReport  # noqa: E402
from service.vuln_engine.scheduler.driver import Engine, RunReport  # noqa: E402
from service.vuln_engine.scheduler.replay import replay  # noqa: E402
from service.vuln_engine.world.log import WorldLog  # noqa: E402

#: Where a run writes by default.  One directory per target, holding the log, the
#: receipts ledger and the report — a run is a directory, not a session.
DEFAULT_OUTPUT_ROOT = ROOT / "output" / "vuln_engine"

#: The fixture app's published port and the collaborator's, matching
#: ``docker-compose.yml``.
FIXTURE_PORT = 8080
COLLABORATOR_PORT = 9009

#: The collaborator URL the *target* must be able to reach.  The compose service
#: name rather than ``host.docker.internal``: it works identically on Docker
#: Desktop and on Linux, and the alternative fails in a way that looks like the
#: target refusing to fetch.
FIXTURE_COLLABORATOR_PUBLIC = f"http://oob_collaborator:{COLLABORATOR_PORT}"


@dataclass
class Profile:
    """Everything a run needs that is not a technique: scope, surfaces, transports."""

    target: str
    seed: EngagementSeed
    scope: ScopeEngine
    collaborator_public: str
    collaborator_local: str
    chrome_path: str = ""
    browser_driver: str = "auto"
    #: Raw ``Cookie`` header value for every request and page load — the session
    #: shim a login-walled target needs. Empty means no header at all.
    cookies: str = ""
    #: Per-host action budget.  The fixture profile is generous because the count
    #: is a *policy* number, not a safety one: the interesting refusal in Phase 1
    #: is scope, and a budget DEFER would only make the log harder to read.
    host_budget: int = 50


def _out(line: str) -> None:
    """Print a line, losing a glyph rather than the report.

    Report lines contain an em dash, and a Windows console in cp1252 cannot encode
    one: the write raises and the run ends with a traceback after it has already
    done the work. The file the run writes is UTF-8 and lossless; the console is a
    window, and a window may drop a character. Same fix, same reason as
    ``run_recon.py``'s.
    """
    try:
        print(line)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "utf-8"
        print(line.encode(encoding, "replace").decode(encoding, "replace"))


def load_env_file(path: Path | None = None) -> dict[str, str]:
    """Load ``KEY=VALUE`` lines from *path* (default: the repo root ``.env``).

    The engine's only secrets mechanism, deliberately ten lines: the LLM
    junctions need a key, the key already sits in the operator's ``.env`` (the
    same file compose reads), and adding a dotenv dependency to parse one
    format we fully control would be a supply chain for a config file. Rules:
    blank lines and ``#`` comments are skipped, an ``export `` prefix is
    tolerated, surrounding quotes are stripped, and **the real environment
    wins** — a variable already set is never overwritten, so an operator's
    shell overrides the file, which is the only precedence worth having.
    Values are never logged and never echoed; the return value is for tests.
    """
    env_path = path or ROOT / ".env"
    if not env_path.is_file():
        return {}
    loaded: dict[str, str] = {}
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("export "):
            line = line[len("export "):]
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if not key:
            continue
        if key not in os.environ:
            os.environ[key] = value
        loaded[key] = value
    return loaded


def fixture_profile(*, chrome_path: str = "") -> Profile:
    """The Phase 1 evaluation profile: the compose fixture app, declared in scope.

    Note how the fixture is authorised: it is a **declared address**
    (``127.0.0.1``), which is exactly the operator's own statement of intent and
    the same mechanism a real engagement uses for a staging host. It is *not* a
    test-only ``ALLOW`` shortcut — the scope engine still has to say yes, and if
    the declaration were removed the gate would correctly DENY every request
    (``127.0.0.1`` is not globally routable, so undeclared private space is
    refused).
    """
    base = f"http://127.0.0.1:{FIXTURE_PORT}"
    host = "127.0.0.1"
    surfaces = (
        Surface(
            url=f"{base}/search",
            host=host,
            param="q",
            where="query",
            capability="public_param",
            label="search parameter",
        ),
        Surface(
            url=f"{base}/fetch",
            host=host,
            param="url",
            where="query",
            capability=CAP_INFLUENCE_REMOTE_FETCH,
            label="caller-supplied URL the server fetches",
        ),
    )
    return Profile(
        target=host,
        seed=EngagementSeed(target=host, surfaces=surfaces),
        scope=ScopeEngine(declared_addresses={"127.0.0.1"}),
        collaborator_public=FIXTURE_COLLABORATOR_PUBLIC,
        collaborator_local=f"http://127.0.0.1:{COLLABORATOR_PORT}",
        chrome_path=chrome_path,
    )


def target_profile(
    target: str,
    *,
    surfaces: list[Surface],
    declared: list[str],
    collaborator_public: str,
    collaborator_local: str,
    chrome_path: str = "",
) -> Profile:
    """An engagement against a declared target, with operator-declared surfaces."""
    scope = ScopeEngine()
    if target.count(".") == 3 and not target.replace(".", "").isdigit():
        # A dotted-quad target is an address, not a domain: routing it to
        # ``add_declared_domain`` would authorize a name that never answers and
        # leave the address itself refused (``check_address`` rejects
        # non-routable space before consulting declared *networks*, so an IP
        # literal must land in ``declared_addresses`` — exactly what the fixture
        # profile does for the same reason).
        scope.add_declared_address(target)
    else:
        scope.add_declared_domain(target)
    for token in declared:
        if "/" in token:
            scope.add_declared_network(token)
        elif token.count(".") == 3 and token.replace(".", "").isdigit():
            scope.add_declared_address(token)
        else:
            scope.add_declared_domain(token)
    return Profile(
        target=target,
        seed=EngagementSeed(target=target, surfaces=tuple(surfaces)),
        scope=scope,
        collaborator_public=collaborator_public,
        collaborator_local=collaborator_local,
        chrome_path=chrome_path,
    )


def run(
    profile: Profile,
    *,
    output_dir: Path,
    force: bool = False,
    advisory: Advisory | None = None,
) -> RunReport:
    """Wire the engine and run it.  The only function in this file that sends traffic."""
    output_dir.mkdir(parents=True, exist_ok=True)
    log = WorldLog(output_dir / "world.jsonl")
    receipt = Receipt(output_dir / "receipts.jsonl")

    dispatcher = dispatch.Dispatcher(
        profile.scope,
        # Nothing here is scored: Phase 1 has no scoring pass for the engine's own
        # assets, and inventing one to satisfy a floor would be a number nobody
        # measured. The floor is therefore not the mechanism in play — scope is.
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
    )
    gate = PolicyGate(dispatcher, log=log, **effects)
    engine = Engine(
        profile.seed,
        gate=gate,
        registry=TechniqueRegistry.discover(strict=False),
        log=log,
        receipt=receipt,
        force=force,
        advisory=advisory,
    )
    report = engine.run()
    (output_dir / "report.json").write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=False), encoding="utf-8", newline="\n"
    )
    return report


def campaign_run(
    profile: Profile,
    *,
    output_dir: Path,
    rounds: int,
    force: bool = False,
    advisory: Advisory | None = None,
) -> CampaignReport:
    """Wire the campaign and spend its round budget.  Phase 2's runner, CLI-exposed."""
    output_dir.mkdir(parents=True, exist_ok=True)
    log = WorldLog(output_dir / "world.jsonl")
    receipt = Receipt(output_dir / "receipts.jsonl")

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
    )
    gate = PolicyGate(dispatcher, log=log, **effects)
    campaign = Campaign(
        profile.seed,
        gate=gate,
        registry=TechniqueRegistry.discover(strict=False),
        log=log,
        receipt=receipt,
        advisory=advisory,
    )
    return campaign.run(Budget(rounds=rounds))


def parse_surface(token: str) -> Surface:
    """``url=<url>;param=<name>;capability=<name>`` → a Surface.

    Semicolon-separated rather than colon-separated because a URL contains colons
    and a parser that cannot tell ``https://host`` from ``url:param`` would produce
    a surface nobody meant.

    The capability is the operator's claim, and it is the only thing that makes
    ``oob_fetch`` fire — see the technique's hypothesis module. Without it the
    engine does not ask a stranger's server to fetch our collaborator.
    """
    from urllib.parse import urlsplit

    fields: dict[str, str] = {}
    for chunk in token.split(";"):
        if not chunk.strip():
            continue
        key, _, value = chunk.partition("=")
        fields[key.strip().lower()] = value.strip()
    url = fields.get("url", "")
    param = fields.get("param", "")
    return Surface(
        url=url,
        host=(urlsplit(url).hostname or "").lower(),
        param=param,
        where=fields.get("where", "query"),
        capability=fields.get("capability", "public_param" if param else ""),
        label=fields.get("label", ""),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the vuln engine (Phase 1).")
    parser.add_argument("--fixture", action="store_true", help="run the Phase 1 fixture profile (default)")
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
    parser.add_argument("--cookie", action="append", default=[], metavar="NAME=VALUE", help="session cookie for a login-walled target (repeatable; sent as one Cookie header on every request and page load)")
    parser.add_argument("--driver", default="auto", choices=("auto", "playwright", "cdp"))
    parser.add_argument("--output-dir", default="", help="where the run writes (default: per target)")
    parser.add_argument("--force", action="store_true", help="ignore the receipts ledger")
    parser.add_argument("--campaign", type=int, default=0, metavar="ROUNDS", help="run the Phase 2 campaign for ROUNDS rounds instead of one pass")
    parser.add_argument("--llm-draft", action="store_true", help="draft advisory report prose via the LLM junctions (no-op without a key)")
    parser.add_argument("--replay", default="", metavar="LOG", help="recompute a finished run offline")
    parser.add_argument("--json", action="store_true", help="print the machine report only")
    args = parser.parse_args(argv)
    # Secrets before anything that could want them: the advisory junctions read
    # the environment lazily at client construction, which happens inside run().
    load_env_file()

    if args.replay:
        log = WorldLog(args.replay)
        registry = TechniqueRegistry.discover(strict=False)
        seed = (
            fixture_profile(chrome_path=args.chrome_path).seed
            if args.fixture or not args.target
            else target_profile(
                args.target,
                surfaces=[parse_surface(token) for token in args.surface],
                declared=args.declare,
                collaborator_public=args.collaborator_url,
                collaborator_local=args.collaborator_local,
            ).seed
        )
        result = replay(log, seed=seed, registry=registry)
        payload = result.to_dict()
        if args.json:
            _out(json.dumps(payload, indent=2))
        else:
            _out(f"replay of {args.replay}")
            _out(f"  candidates logged:     {result.candidates_logged}")
            _out(f"  candidates recomputed: {result.candidates_recomputed}")
            _out(f"  mismatches:            {len(result.mismatches)}")
            _out(f"  independence issues:   {len(result.independence_violations)}")
            for mismatch in result.mismatches:
                _out(f"    ! {mismatch}")
            for line in result.report_lines:
                _out(f"  {line}")
        return 0 if result.clean else 1

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

    advisory = Advisory.from_env() if args.llm_draft else None
    output_dir = Path(args.output_dir) if args.output_dir else DEFAULT_OUTPUT_ROOT / profile.target.replace(":", "_")

    if args.campaign > 0:
        campaign_report = campaign_run(
            profile,
            output_dir=output_dir,
            rounds=args.campaign,
            force=args.force,
            advisory=advisory,
        )
        if args.json:
            _out(json.dumps(campaign_report.to_dict(), indent=2))
            return 0
        _out(f"vuln engine campaign - {campaign_report.target}")
        _out(f"  rounds:     {campaign_report.rounds_run}/{campaign_report.rounds_planned}")
        for item in campaign_report.rounds:
            _out(
                f"    round {item['round']}: {item['arm']['technique']} on {item['arm']['surface']}"
                f" ({item['reason']}) -> {item['findings']} finding(s)"
            )
        if campaign_report.free_rounds:
            _out(f"  free rounds (nothing reached the target): {campaign_report.free_rounds}")
        _out(f"  findings:   {len(campaign_report.findings)}")
        for finding in campaign_report.findings:
            _out(f"    {finding.get('summary', finding.get('vuln_class', '?'))}")
        if campaign_report.problems:
            _out(f"  notes:      {'; '.join(campaign_report.problems)}")
        return 0 if campaign_report.findings else 1

    report = run(profile, output_dir=output_dir, force=args.force, advisory=advisory)
    write_drafts(report.to_dict(), output_dir, advisory)

    if args.json:
        _out(json.dumps(report.to_dict(), indent=2))
        return 0

    _out(f"vuln engine - {report.target}")
    _out(f"  log:        {report.log_path}")
    _out(f"  techniques: {', '.join(item['name'] for item in report.techniques) or '(none)'}")
    if getattr(report, "advisory", None):
        health = report.advisory
        llm = health.get("llm", {})
        state = "available" if health.get("available") else "degraded"
        detail = llm.get("model") or llm.get("reason", "")
        _out(f"  advisory:   {state} ({detail})")
    gate = report.gate
    _out(
        f"  gate:       {gate['decisions']} decision(s) {gate['by_verb']}; "
        f"uncleared effects: {gate['uncleared_effects']}; "
        f"out of scope: {gate['out_of_scope_requests']}"
    )
    _out(f"  counts:     {report.counts}")
    _out(f"  findings:   {len(report.findings)}")
    for line in report.report_lines:
        _out(f"    {line}")
    if report.leads:
        _out(f"  leads:      {len(report.leads)} (recorded, not promoted)")
    if report.problems:
        _out(f"  registry:   {len(report.problems)} folder(s) skipped")
    return 0 if report.findings else 1


def write_drafts(report_dict: dict, output_dir: Path, advisory: Advisory | None) -> None:
    """Advisory prose beside the canonical lines, when the junction is available.

    Written as ``report.draft.json`` next to ``report.json`` — never into it.
    The canonical report remains a pure derivation of the log; the draft is an
    overlay an operator reads beside it, flagged with the model and the
    validation outcome per finding.
    """
    if advisory is None or not advisory.available:
        return
    findings = list(report_dict.get("findings") or [])
    if not findings:
        return
    drafts = advisory.draft_report(findings)
    (output_dir / "report.draft.json").write_text(
        json.dumps({"drafts": drafts, "advisory": advisory.to_dict()}, indent=2),
        encoding="utf-8",
        newline="\n",
    )


if __name__ == "__main__":
    sys.exit(main())
