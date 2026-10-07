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
from service.vuln_engine.abduction.deterministic import abduce  # noqa: E402
from service.vuln_engine.abduction.validator import Validator  # noqa: E402
from service.vuln_engine.kernel.technique import (  # noqa: E402
    CAP_INFLUENCE_REMOTE_FETCH,
    EngagementSeed,
    Surface,
)
from service.vuln_engine.llm import graph_nav
from service.vuln_engine.llm.wiring import (
    Advisory,
    hypothesized_seed_advisory,
    load_memory,
    load_recon_artifacts,
    remember,
)
from service.vuln_engine.paths import safe_component  # noqa: E402
from service.vuln_engine.policy.eligibility import (  # noqa: E402
    ProgramPolicy,
    annotate_findings,
    policy_from_document,
)
from service.vuln_engine.policy.gate import PolicyGate, default_effects  # noqa: E402
from service.vuln_engine.seed import (  # noqa: E402
    DEFAULT_MAX_SURFACES,
    MAX_GRAPH_CONTEXT,
    derive_surfaces,
    graph_context_rows,
    merge_surfaces,
)
from service.vuln_engine.registry import TechniqueRegistry  # noqa: E402
from service.vuln_engine.scheduler.campaign import Budget, Campaign, CampaignReport  # noqa: E402
from service.vuln_engine.scheduler.driver import Engine, RunReport  # noqa: E402
from service.vuln_engine.scheduler.pool import HypothesisPool  # noqa: E402
from service.vuln_engine.scheduler.replay import replay  # noqa: E402
from service.vuln_engine.scheduler.tree import AndNode, OrNode, Tree  # noqa: E402
from service.vuln_engine.world.holding_pen import HoldingPen  # noqa: E402
from service.vuln_engine.world.log import WorldLog  # noqa: E402

#: Where a run writes by default.  One directory per target, holding the log, the
#: receipts ledger and the report — a run is a directory, not a session.
DEFAULT_OUTPUT_ROOT = ROOT / "output" / "vuln_engine"

#: The fixture app's published port and the collaborator's, matching
#: ``docker-compose.yml``.
FIXTURE_PORT = 8080
COLLABORATOR_PORT = 9009

#: Where ``--hypothesize-from-recon`` looks for recon artifacts by default: the
#: url_endpoint pipeline's own directory, exactly as ``run_recon.py`` leaves it.
DEFAULT_RECON_DIR = ROOT / "service/recon_pipeline/pipelines/url_endpoint"

#: Where ``--from-graph`` looks for the asset model by default: the
#: graph_normalize pipeline's own output, where ``run_recon.py`` leaves it.
DEFAULT_GRAPH_STATE = (
    ROOT / "service/recon_pipeline/pipelines/graph_normalize/output/graph_state.json"
)

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
    #: The second session's raw ``Cookie`` header value — the authorization
    #: technique's other identity (session A is ``cookies``). Empty means no
    #: second session: the gate refuses any request asking for session B, and
    #: ``idor_differential`` never fires.
    session_b_cookie: str = ""
    #: Per-host action budget.  The fixture profile is generous because the count
    #: is a *policy* number, not a safety one: the interesting refusal in Phase 1
    #: is scope, and a budget DEFER would only make the log harder to read.
    host_budget: int = 50
    #: The program's bounty-eligibility rules, when a program was loaded.  The
    #: engine never lets this decide *whether* to test (scope does that); it only
    #: annotates proven findings with what the program would likely accept.
    policy: ProgramPolicy | None = None


def print_holding_pen(report: "RunReport") -> None:
    """The holding-pen backlog, as the report's human lines (empty when none).

    The machine shape travels under the ``holding_pen`` key of ``report.json``
    and ``--json``; this is the operator-facing rendering of the same view, and
    it prints nothing at all when no hypothesis is waiting.
    """
    pen = getattr(report, "holding_pen", None) or {}
    if not pen.get("held"):
        return
    _out(
        f"  holding pen: {pen['held']} held hypothesis(es) waiting on a "
        "verifier; run --json for the breakdown"
    )
    for group in pen.get("groups", []):
        _out(
            f"    - {group['count']}x {group['needs_verifier']} "
            f"({group['key']})"
        )


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


def _wire_grammars(advisory: Advisory | None, registry: TechniqueRegistry) -> None:
    """Collect the techniques' synthesis grammars into the advisory, once.

    Lives here (the composition root) rather than in ``llm/``: the llm layer's
    import rule keeps it kernel- and world-side only, and which techniques'
    grammars the model may shape is a composition decision, not a junction
    behavior. A technique without ``synthesis_grammar()`` simply contributes
    nothing — the synthesize junction stays silent for it.
    """
    if advisory is None:
        return
    for registration in registry.all():
        grammar = getattr(registration.technique, "synthesis_grammar", None)
        if callable(grammar):
            advisory.grammars[registration.name] = grammar()


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


def _build_graph_backend(args):
    """The graph the seed is derived from — a ``graph_state.json`` or Neo4j.

    Both satisfy ``platform.graph.reader.GraphBackend``; the choice is the
    operator's, and nothing above the protocol changes with it.  A missing file
    is named, not silently treated as an empty graph: deriving zero surfaces from
    an absent model would look like "nothing to test" when it is really "recon
    has not run".
    """
    if args.graph_neo4j:
        from service.recon_pipeline.platform.graph.neo4j_backend import Neo4jBackend

        return Neo4jBackend(
            os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            os.getenv("NEO4J_USERNAME"),
            os.getenv("NEO4J_PASSWORD"),
            os.getenv("NEO4J_DATABASE") or None,
        )
    from service.recon_pipeline.platform.graph.reader import JsonFileBackend

    path = Path(args.from_graph) if args.from_graph else DEFAULT_GRAPH_STATE
    if not path.is_file():
        raise FileNotFoundError(
            f"no graph_state.json at {path} — run the graph_normalize pipeline "
            "first (or point --from-graph at one)"
        )
    return JsonFileBackend(path)


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


def program_profile(
    scope,
    *,
    target: str,
    surfaces: list[Surface],
    declared: list[str],
    collaborator_public: str,
    collaborator_local: str,
    chrome_path: str = "",
) -> Profile:
    """An engagement whose scope is a program the scraper ingested.

    This is the recon seam brought to the engine: the declared scope and the
    **boundary set** (assets the program explicitly placed out of scope) are
    applied to the engine's own ``ScopeEngine``, so the gate refuses an
    out-of-scope host even if the operator typed a surface for it.  The engine
    still declares no surfaces of its own — the operator declares what to test,
    the program decides whether it is theirs.
    """
    from service.recon_pipeline.platform.programs import apply_program_scope

    engine = ScopeEngine()
    apply_program_scope(engine, scope)
    # Operator declarations still apply, on top of the program's — an engagement
    # may add a staging host the program does not list.
    for token in declared:
        if "/" in token:
            engine.add_declared_network(token)
        elif token.count(".") == 3 and token.replace(".", "").isdigit():
            engine.add_declared_address(token)
        else:
            engine.add_declared_domain(token)
    return Profile(
        target=target,
        seed=EngagementSeed(target=target, surfaces=tuple(surfaces)),
        scope=engine,
        collaborator_public=collaborator_public,
        collaborator_local=collaborator_local,
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
    if target.count(".") == 3 and target.replace(".", "").isdigit():
        # A dotted-quad target is an address, not a domain: routing it to
        # ``add_declared_domain`` would authorize a name that never answers and
        # leave the address itself refused (``check_address`` rejects
        # non-routable space before consulting declared *networks*, so an IP
        # literal must land in ``declared_addresses`` — exactly what the fixture
        # profile does for the same reason). The digits-and-dots test is what
        # makes a dotted quad take THIS branch; the inverse sent every IP
        # literal to the domain branch, where the gate then refused it as
        # "not globally routable".
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
    elicit: bool = False,
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
        session_b_cookie=profile.session_b_cookie,
    )
    registry = TechniqueRegistry.discover(strict=False)
    _wire_grammars(advisory, registry)
    gate = PolicyGate(dispatcher, log=log, **effects)
    # The abductive loop is on by default (PRD §6.5): the deterministic abducer
    # is the control arm, the advisory's model channel attaches through it when a
    # key is configured, and the pen persists beside the log so a held hypothesis
    # survives the run. Expressible explanations are *run* by the driver's
    # bounded abduced round; nothing they produce is a finding until the ordinary
    # verifier proves it.
    engine = Engine(
        profile.seed,
        gate=gate,
        registry=registry,
        log=log,
        receipt=receipt,
        force=force,
        advisory=advisory,
        abducer=abduce,
        validator=Validator(),
        pen=HoldingPen(output_dir / "holding_pen.jsonl"),
        pool=HypothesisPool(),
        elicit=elicit,
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
    widening: dict | None = None,
    elicit: bool = False,
    tree: "Tree | None" = None,
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
        session_b_cookie=profile.session_b_cookie,
    )
    registry = TechniqueRegistry.discover(strict=False)
    _wire_grammars(advisory, registry)
    gate = PolicyGate(dispatcher, log=log, **effects)
    campaign = Campaign(
        profile.seed,
        gate=gate,
        registry=registry,
        log=log,
        receipt=receipt,
        advisory=advisory,
        force=force,
        widening=widening,
        abducer=abduce,
        validator=Validator(),
        pen=HoldingPen(output_dir / "holding_pen.jsonl"),
        elicit=elicit,
        tree=tree,
    )
    return campaign.run(Budget(rounds=rounds))


def load_attack_tree(path: str) -> Tree:
    """Parse ``--attack-tree``'s JSON into a :class:`Tree`.

    The file is data, not code: ``{"root": name, "nodes": [{"kind": "or",
    "name", "techniques"} | {"kind": "and", "name", "requires", "objective"}]}``.
    Malformed shapes fail loudly here, before a campaign spends anything — the
    same loudness a manifest that validates badly gets at discovery.
    """
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    nodes: list[OrNode | AndNode] = []
    for entry in document.get("nodes") or []:
        kind = str(entry.get("kind") or "or")
        if kind == "or":
            nodes.append(
                OrNode(
                    name=str(entry.get("name") or ""),
                    techniques=tuple(str(name) for name in entry.get("techniques") or ()),
                )
            )
        elif kind == "and":
            objective = entry.get("objective") or {}
            nodes.append(
                AndNode(
                    name=str(entry.get("name") or ""),
                    requires=tuple(str(name) for name in entry.get("requires") or ()),
                    objective=OrNode(
                        name=str(objective.get("name") or ""),
                        techniques=tuple(
                            str(name) for name in objective.get("techniques") or ()
                        ),
                    ),
                )
            )
        else:
            raise ValueError(f"attack tree node {entry.get('name')!r} has unknown kind {kind!r}")
    root = str(document.get("root") or "")
    if not root or not nodes:
        raise ValueError("an attack tree needs a root name and at least one node")
    return Tree(root=root, nodes=tuple(nodes))


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
    # ``companions`` declares the fixed form fields every body submission must
    # carry (``companions=key1=value1,key2=value2``) — a guestbook's submit
    # button is part of the surface's protocol, not part of any payload.
    companions: dict[str, str] = {}
    for pair in fields.get("companions", "").split(","):
        if "=" in pair:
            name, _, value = pair.partition("=")
            companions[name.strip()] = value.strip()
    return Surface(
        url=url,
        host=(urlsplit(url).hostname or "").lower(),
        param=param,
        where=fields.get("where", "query"),
        capability=fields.get("capability", "public_param" if param else ""),
        label=fields.get("label", ""),
        companions=companions,
        read_back=fields.get("read_back", ""),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the vuln engine (Phase 1).")
    parser.add_argument("--fixture", action="store_true", help="run the Phase 1 fixture profile (default)")
    parser.add_argument("-t", "--target", default="", help="declared target domain")
    parser.add_argument(
        "--program",
        default="",
        metavar="HANDLE",
        help=(
            "load the declared scope AND the explicitly out-of-scope boundary for "
            "one ingested program from PostgreSQL (the scraper's tables); surfaces "
            "are still declared with --surface, and an out-of-scope host is refused "
            "by the gate even if a surface names it"
        ),
    )
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
    parser.add_argument(
        "--session-b-cookie",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help=(
            "the SECOND session's cookie, for the authorization technique "
            "(repeatable; --cookie is session A — typically owner/admin, "
            "--session-b-cookie the low-privilege identity)"
        ),
    )
    parser.add_argument(
        "--host-budget",
        type=int,
        default=0,
        metavar="N",
        help="per-host action budget (default 50; raise it for wide surface sets - a policy number, not a safety one)",
    )
    parser.add_argument("--driver", default="auto", choices=("auto", "playwright", "cdp"))
    parser.add_argument("--output-dir", default="", help="where the run writes (default: per target)")
    parser.add_argument("--force", action="store_true", help="ignore the receipts ledger")
    parser.add_argument(
        "--elicit",
        action="store_true",
        help=(
            "Capability Closure: before the ordinary pass, measure the "
            "preconditions the techniques gate on (reflection, remote fetch, "
            "timing, sessions, storage) with the elicitor corpus, and let the "
            "measured facts open the technique gates a declared claim alone "
            "used to have to open"
        ),
    )
    parser.add_argument("--campaign", type=int, default=0, metavar="ROUNDS", help="run the Phase 2 campaign for ROUNDS rounds instead of one pass")
    parser.add_argument("--llm-draft", action="store_true", help="draft advisory report prose via the LLM junctions (no-op without a key)")
    parser.add_argument(
        "--hypothesize-from-recon",
        action="store_true",
        help=(
            "ask the hypothesize junction to widen the declared seed with surfaces "
            "derived from recon artifacts (parameters.jsonl / url_validation.jsonl); "
            "every proposed URL must be one recon observed, and the widened seed "
            "then runs through the ordinary gate and verifier. No-op without a key."
        ),
    )
    parser.add_argument(
        "--recon-dir",
        default="",
        metavar="DIR",
        help="the url_endpoint pipeline directory for --hypothesize-from-recon (default: auto-detect from the repo)",
    )
    parser.add_argument(
        "--from-graph",
        nargs="?",
        const="",
        default=None,
        metavar="PATH",
        help=(
            "derive candidate surfaces from the recon graph (a graph_state.json); "
            "omit PATH for graph_normalize's default output. Out-of-scope and "
            "needs-review URLs are filtered out before they become surfaces"
        ),
    )
    parser.add_argument(
        "--graph-neo4j",
        action="store_true",
        help="use the configured Neo4j store as the graph backend for --from-graph",
    )
    parser.add_argument(
        "--max-surfaces",
        type=int,
        default=DEFAULT_MAX_SURFACES,
        metavar="N",
        help="cap on graph-derived surfaces (default %(default)s)",
    )
    parser.add_argument(
        "--no-infer-remote-fetch",
        action="store_true",
        help=(
            "do not claim can_influence_remote_fetch from URL-shaped parameter "
            "names (the claim only arms an SSRF hypothesis; verification proves it)"
        ),
    )
    parser.add_argument(
        "--graph-include-historical",
        action="store_true",
        help=(
            "propose surfaces from URL nodes recon marked historical (dead nodes "
            "are always skipped; historical ones are an operator opt-in)"
        ),
    )
    parser.add_argument(
        "--attack-tree",
        default="",
        metavar="JSON",
        help=(
            "gate each campaign round's arm pick through the AND/OR attack tree "
            "described in the file ({root, nodes: [{kind: or, name, techniques} | "
            "{kind: and, name, requires, objective}]}); parked subtrees are not "
            "spent on"
        ),
    )
    parser.add_argument(
        "--graph-agent",
        action="store_true",
        help=(
            "let the model navigate the recon graph through its read-only tools "
            "(requires --from-graph or --graph-neo4j); the node ids it selects are "
            "expanded under the ordinary scope rules, never trusted directly"
        ),
    )
    parser.add_argument(
        "--graph-goal",
        default="",
        metavar="TEXT",
        help="what the graph agent should look for (default: the target's endpoints most worth testing)",
    )
    parser.add_argument(
        "--graph-steps",
        type=int,
        default=0,
        metavar="N",
        help=(
            "max tool calls the graph agent may make (default: the junction's "
            "own budget, " + str(graph_nav.MAX_STEPS) + ")"
        ),
    )
    parser.add_argument(
        "--memory-file",
        default="",
        metavar="PATH",
        help="a previous engagement's memory record (written by --remember) to inform --hypothesize-from-recon",
    )
    parser.add_argument(
        "--remember",
        action="store_true",
        help="after the run, write a memory record (arms, contexts, timings, leads) beside the report for the next engagement",
    )
    parser.add_argument("--replay", default="", metavar="LOG", help="recompute a finished run offline")
    parser.add_argument("--json", action="store_true", help="print the machine report only")
    args = parser.parse_args(argv)
    # A target becomes a filesystem name (output/vuln_engine/<target> when
    # --output-dir is not given): refuse a traversal-shaped or separator-bearing
    # one HERE, before any graph, policy or network work happens.
    if args.target:
        safe_component(args.target)
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

    policy: ProgramPolicy | None = None
    if args.program:
        # Fail-fast, exactly like the recon side's --program: an unknown handle,
        # a program with no engagable domain, or a -t the program does not
        # declare all stop the run before anything is wired. Scope is the safety
        # input; there is no silent fallback to the fixture.
        from service.recon_pipeline.platform.graph.program_graph import document_from_db
        from service.recon_pipeline.platform.programs import (
            ProgramScopeError,
            ProgramScopeLoader,
        )

        try:
            program_scope = ProgramScopeLoader().load(args.program)
        except ProgramScopeError as exc:
            print(f"program scope: {exc}", file=sys.stderr)
            return 2
        target = args.target or (program_scope.apexes[0] if program_scope.apexes else "")
        if not target:
            print(
                "program declares no engagable domain — pass -t to name the "
                "engagement target",
                file=sys.stderr,
            )
            return 2
        if args.target and not program_scope.declares(args.target):
            print(
                f"program {args.program!r} does not declare {args.target!r}; "
                f"declared domains: {', '.join(program_scope.apexes) or '(none)'}",
                file=sys.stderr,
            )
            return 2
        profile = program_profile(
            program_scope,
            target=target,
            surfaces=[parse_surface(token) for token in args.surface],
            declared=args.declare,
            collaborator_public=args.collaborator_url or f"http://oob_collaborator:{COLLABORATOR_PORT}",
            collaborator_local=args.collaborator_local or f"http://127.0.0.1:{COLLABORATOR_PORT}",
            chrome_path=args.chrome_path,
        )
        try:
            policy = policy_from_document(document_from_db(args.program))
        except (KeyError, ValueError):
            policy = None
        _out(
            f"program {program_scope.handle}: {len(program_scope.domains)} declared domain(s), "
            f"{len(program_scope.out_of_scope_domains) + len(program_scope.out_of_scope_networks) + len(program_scope.out_of_scope_addresses)} "
            "explicitly out-of-scope boundary rule(s)"
        )
        _out(
            f"  eligibility policy: "
            + (
                f"{len(policy.eligible_classes)} accepted class(es) from {policy.handle}"
                if policy and policy.eligible_classes
                else "none published — findings will be assessed as UNKNOWN"
            )
        )
    elif args.target:
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
    profile.policy = policy

    graph_seed: dict | None = None
    graph_context: list[dict] | None = None
    graph_backend = None
    if args.from_graph is not None or args.graph_neo4j:
        # Seed construction from graph context: recon's observed URLs and their
        # parameters become surfaces, filtered by the *same* scope engine the
        # gate uses, so a boundary asset is never proposed. Operator-declared
        # surfaces win on a collision. This adds hypotheses, not conclusions —
        # every derived surface still pays the gate and the verifier.
        try:
            backend = _build_graph_backend(args)
        except (FileNotFoundError, ValueError) as exc:
            print(f"graph seed: {exc}", file=sys.stderr)
            return 2
        graph_backend = backend
        derived = derive_surfaces(
            backend,
            scope_state=lambda host: profile.scope.check_host(host).state,
            max_surfaces=max(1, args.max_surfaces),
            infer_remote_fetch=not args.no_infer_remote_fetch,
            include_historical=args.graph_include_historical,
        )
        graph_seed = derived.report
        if args.hypothesize_from_recon:
            # The advisory junction may widen the seed further, but only across
            # what recon observed — so the same scope-filtered candidates the
            # deterministic derivation used become the junction's context rows.
            graph_context = graph_context_rows(
                backend,
                scope_state=lambda host: profile.scope.check_host(host).state,
                max_rows=MAX_GRAPH_CONTEXT,
                infer_remote_fetch=not args.no_infer_remote_fetch,
                include_historical=args.graph_include_historical,
            )
        declared = list(profile.seed.surfaces)
        profile.seed = EngagementSeed(
            target=profile.target,
            surfaces=tuple(merge_surfaces(declared, derived.surfaces)),
        )
        _out(
            f"graph seed: {len(derived.surfaces)} surface(s) from "
            f"{graph_seed.get('urls_considered', 0)} URL node(s); "
            f"{graph_seed.get('remote_fetch_claims', 0)} remote-fetch claim(s); "
            f"filtered {graph_seed.get('skipped_out_of_scope', 0)} out-of-scope / "
            f"{graph_seed.get('skipped_needs_review', 0)} needs-review"
        )
        if graph_seed.get("truncated"):
            _out(f"  capped at {args.max_surfaces} ({graph_seed.get('dropped', 0)} dropped)")

    profile.browser_driver = args.driver
    profile.cookies = "; ".join(args.cookie)
    profile.session_b_cookie = "; ".join(args.session_b_cookie)
    if args.host_budget > 0:
        profile.host_budget = args.host_budget

    advisory = Advisory.from_env() if (args.llm_draft or args.hypothesize_from_recon or args.graph_agent) else None
    output_dir = (
        Path(args.output_dir) if args.output_dir
        else DEFAULT_OUTPUT_ROOT / safe_component(profile.target)
    )

    agent_result: dict | None = None
    if args.graph_agent:
        # Junction 6: the model navigates the graph through the *same* read-only
        # tools an operator uses, and reports node ids — never surfaces. The ids
        # are expanded by ``candidates_for_nodes``, which re-applies the
        # whole-graph rule and the scope filter, so an agent cannot turn an
        # invented id or a boundary asset into a target. Degrades to no
        # navigation without a key; the deterministic seed is unaffected.
        if graph_backend is None:
            print(
                "--graph-agent needs a graph: pass --from-graph PATH (or "
                "--graph-neo4j)",
                file=sys.stderr,
            )
            return 2
        from service.recon_pipeline.platform.graph.tools import (
            dispatch as graph_dispatch,
            tool_schemas,
        )
        from service.vuln_engine.llm.wiring import graph_navigation_advisory
        from service.vuln_engine.seed import candidates_for_nodes

        tool_names = [schema["function"]["name"] for schema in tool_schemas()]
        # The operator's step budget, or the junction's own.  A larger budget
        # buys more exploration, not more authority: every step is still one
        # validated, logged decision and the expansion rules do not move.
        max_steps = args.graph_steps if args.graph_steps > 0 else graph_nav.MAX_STEPS
        navigation = graph_navigation_advisory(
            advisory,
            args.graph_goal or f"find the endpoints of {profile.target} most worth testing",
            tool_names=tool_names,
            dispatch=lambda name, arguments: graph_dispatch(
                graph_backend, name, arguments
            ),
            log_handle=WorldLog(output_dir / "world.jsonl"),
            max_steps=max_steps,
        )
        agent_result = navigation.to_dict()
        if navigation.selected_nodes:
            expanded = candidates_for_nodes(
                graph_backend,
                navigation.selected_nodes,
                scope_state=lambda host: profile.scope.check_host(host).state,
                infer_remote_fetch=not args.no_infer_remote_fetch,
                include_historical=args.graph_include_historical,
            )
            existing = list(profile.seed.surfaces)
            profile.seed = EngagementSeed(
                target=profile.target,
                surfaces=tuple(merge_surfaces(existing, expanded.surfaces)),
            )
            agent_result["expanded_surfaces"] = len(expanded.surfaces)
            agent_result["expansion"] = expanded.report
        _out(
            f"graph agent: {navigation.source} - {navigation.observations} tool call(s), "
            f"{len(navigation.selected_nodes)} node(s) selected"
            + (
                f", {agent_result.get('expanded_surfaces', 0)} surface(s) expanded"
                if navigation.selected_nodes
                else ""
            )
        )
        if navigation.reason:
            _out(f"  agent: {navigation.reason}")

    widening: dict | None = None
    if args.hypothesize_from_recon:
        # Junction 4, on the operator's explicit request: widen the declared
        # seed with surfaces derived from recon artifacts BEFORE the engine or
        # campaign is built. The widened seed flows through the ordinary gate,
        # the ordinary techniques and the ordinary verifier — the model widened
        # the attention, it did not add a conclusion. The call is logged into
        # the run's own world log (digest-keyed), so a replay reproduces the
        # widening with the key removed; a degraded opinion (no key, invalid
        # answer) leaves the seed exactly as the operator declared it.
        recon_dir = Path(args.recon_dir) if args.recon_dir else DEFAULT_RECON_DIR
        parameters_rows, alive_urls = load_recon_artifacts(recon_dir)
        memory = load_memory(args.memory_file) if args.memory_file else None
        widening_log = WorldLog(output_dir / "world.jsonl")
        widening_result = hypothesized_seed_advisory(
            advisory,
            profile.seed,
            parameters_rows=parameters_rows,
            alive_urls=alive_urls,
            memory=memory,
            graph_context=graph_context,
            log_handle=widening_log,
        )
        profile.seed = widening_result.seed
        widening = widening_result.to_dict()
        _out(
            f"hypothesize: {widening_result.source} - {widening_result.added} surface(s) added "
            f"of {widening_result.proposed_raw} proposed (recon: {recon_dir})"
        )
        if widening_result.reason:
            _out(f"  junction: {widening_result.reason}")

    if args.campaign > 0:
        attack_tree: Tree | None = None
        if args.attack_tree:
            try:
                attack_tree = load_attack_tree(args.attack_tree)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                print(f"attack tree: {exc}", file=sys.stderr)
                return 2
        campaign_report = campaign_run(
            profile,
            output_dir=output_dir,
            rounds=args.campaign,
            force=args.force,
            advisory=advisory,
            widening=widening,
            elicit=args.elicit,
            tree=attack_tree,
        )
        campaign_payload = campaign_report.to_dict()
        # Same provenance the single-run report carries: what the graph-derived
        # seed was, and what (if anything) the navigating agent selected.
        if graph_seed is not None:
            campaign_payload["graph_seed"] = graph_seed
        if agent_result is not None:
            campaign_payload["graph_agent"] = agent_result
        if args.json:
            _out(json.dumps(campaign_payload, indent=2))
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
        if args.remember:
            memory_path = output_dir / "memory.json"
            record = remember(
                output_dir / "world.jsonl", campaign_report.target
            )
            memory_path.write_text(
                json.dumps(record, indent=2), encoding="utf-8", newline="\n"
            )
            _out(f"  memory:     {memory_path} (feed back with --memory-file)")
        if campaign_report.widening:
            _out(
                f"  widened:    {campaign_report.widening.get('added', 0)} surface(s) "
                f"of {campaign_report.widening.get('proposed_raw', 0)} proposed "
                f"({campaign_report.widening.get('source', '?')}, hypothesize junction)"
            )
            for surface in campaign_report.widening.get("surfaces", []):
                key = surface.get("url", "?")
                if surface.get("param"):
                    key = f"{key}#{surface['param']}"
                _out(f"    + {key}")
        write_drafts(
            campaign_payload,
            output_dir,
            advisory,
            log_handle=WorldLog(output_dir / "world.jsonl"),
        )
        return 0 if campaign_report.findings else 1

    report = run(
        profile, output_dir=output_dir, force=args.force, advisory=advisory, elicit=args.elicit
    )
    payload = report.to_dict()
    if graph_seed is not None:
        payload["graph_seed"] = graph_seed
    if agent_result is not None:
        payload["graph_agent"] = agent_result
    # Eligibility is a view of a *proven* finding, not part of the world log (the
    # log cannot change because a program's rules did). So it is attached here,
    # to the report the run writes, and the canonical findings remain the log's.
    if args.program:
        payload["findings"] = annotate_findings(
            payload.get("findings") or [],
            policy=profile.policy,
            scope_lookup=lambda host: profile.scope.check_host(host).state,
        )
        payload["program"] = profile.policy.handle if profile.policy else args.program
    if graph_seed is not None or agent_result is not None or args.program:
        # Re-write the report with the enrichments attached: the file on disk
        # should match what --json prints, and a graph seed or an agent walk
        # missing from the report would be provenance an operator cannot audit.
        (output_dir / "report.json").write_text(
            json.dumps(payload, indent=2, sort_keys=False),
            encoding="utf-8",
            newline="\n",
        )
    write_drafts(
        payload,
        output_dir,
        advisory,
        log_handle=WorldLog(output_dir / "world.jsonl"),
    )
    if args.remember:
        memory_path = output_dir / "memory.json"
        record = remember(output_dir / "world.jsonl", report.target)
        memory_path.write_text(
            json.dumps(record, indent=2), encoding="utf-8", newline="\n"
        )
        _out(f"  memory:     {memory_path} (feed back with --memory-file)")

    if args.json:
        _out(json.dumps(payload, indent=2))
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
    if report.closure:
        established = report.closure.get("established", [])
        _out(
            f"  closure:    {len(established)} capability fact(s) established, "
            f"{len(report.closure.get('negatives', []))} negative(s), "
            f"{report.closure.get('refused', 0)} refused"
        )
        for fact in established:
            _out(
                f"    + {fact.get('capability')} on {fact.get('surface_key')} "
                f"(grade {fact.get('grade')})"
            )
    blocked = int(report.counts.get("blocked_on_session_b", 0) or 0)
    if blocked:
        checks = int(report.counts.get("blocked_on_session_b_capability_checks", 0) or 0)
        candidates = int(
            report.counts.get("blocked_on_session_b_candidates", 0) or 0
        )
        _out(
            f"  blocked:    {checks} capability check(s) and {candidates} "
            "candidate(s) were blocked only by a missing second session — run "
            "with --session-b-cookie to unlock them."
        )
    print_holding_pen(report)
    _out(f"  counts:     {report.counts}")
    _out(f"  findings:   {len(report.findings)}")
    for line in report.report_lines:
        _out(f"    {line}")
    if args.program:
        for finding in payload.get("findings") or []:
            _out(
                f"    scope={finding.get('scope_state', 'unknown')} "
                f"eligibility={finding.get('eligibility', 'unknown')} "
                f"({finding.get('eligibility_reason', '')})"
            )
    if report.leads:
        _out(f"  leads:      {len(report.leads)} (recorded, not promoted)")
    if report.problems:
        _out(f"  registry:   {len(report.problems)} folder(s) skipped")
    return 0 if report.findings else 1


def write_drafts(
    report_dict: dict,
    output_dir: Path,
    advisory: Advisory | None,
    *,
    log_handle: WorldLog | None = None,
) -> None:
    """Advisory prose beside the canonical lines, when the junction is available.

    Written as ``report.draft.json`` next to ``report.json`` — never into it.
    The canonical report remains a pure derivation of the log; the draft is an
    overlay an operator reads beside it, flagged with the model and the
    validation outcome per finding. ``log_handle`` is the world log: every
    junction call is appended there like every other junction's, so the
    model's prose is as replayable as its ranking.
    """
    if advisory is None or not advisory.available:
        return
    findings = list(report_dict.get("findings") or [])
    if not findings:
        return
    drafts = advisory.draft_report(findings, log_handle=log_handle)
    (output_dir / "report.draft.json").write_text(
        json.dumps({"drafts": drafts, "advisory": advisory.to_dict()}, indent=2),
        encoding="utf-8",
        newline="\n",
    )


if __name__ == "__main__":
    sys.exit(main())
