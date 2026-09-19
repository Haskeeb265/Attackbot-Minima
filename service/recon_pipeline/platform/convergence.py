"""The convergence loop: run rounds over a frontier until it stops growing.

The recon tree could always expand *once* — a name resolves, permutation derives
new names from it, the pipeline ends.  What it could not do is keep going while
new assets kept appearing, and the honest reason is that "keep running the
pipelines until exhausted" is not a design: two of the collectors ask a question
whose answer cannot change within an engagement (see below), so a naive
``while True: run everything`` spends its budget re-asking them.

This module is the loop, built out of one measurable quantity and one decision.

**The frontier.** After every round the driver reads each pipeline's declared
``frontier_artifacts`` and canonicalises every line into an asset token —
``host:api.example.com``, ``ip:104.16.0.1``, ``url:https://…/path``,
``net:103.53.44.0/22``.  The union of those tokens is the frontier.  Every token
ever seen goes into the :class:`Ledger`; a round's **new assets** are the tokens
the frontier has never held before.  That single number is what "exhausted"
means, and it is measured, not inferred.

**Which pipelines may repeat.** Declared per pipeline (``repeat_stages``), because
it is an empirical property of the collector, not a preference:

* the passive names sources are **subtree queries** — crt.sh is asked for
  ``%.<apex>`` and Wayback with ``matchType=domain``, so one call returns every
  depth.  Re-running them re-queries a subset of a set already covered
  (``tests/recon/test_passive_sources.py`` pins that contract);
* ``asn_cidr`` is **seed-keyed** — RIPEstat/RDAP answer about the addresses and
  orgs you name, so repeating it only pays when the address set grew;
* ``url_endpoint``'s sources are per-domain archives, so a second pass asks the
  same question of the same archive;
* the names pipeline's ``active``/``permutation`` stages are the one true
  **generator** (bruteforce under newly-resolved parents, permutations of
  newly-known names), and ``cloud_resource``'s harvest is genuinely
  frontier-driven (new names/URLs/JS ⇒ new bucket candidates).

**Decisive stopping.** ``decide()`` is a pure function over the rounds so far and
a :class:`StopPolicy`, and it always names the condition that fired.  Caps
outrank the happy ending on purpose: a run that hit its time budget *and* found
nothing new reports the budget, because claiming "exhausted" when we simply ran
out of wall-clock would overstate what we know.  ``STOP_FIXED_POINT`` means the
frontier genuinely stopped growing.

Nothing here opens a socket or imports a pipeline; the driver takes a
``round_fn`` callable and a clock, so the whole loop is testable against a fake
round and a frozen clock.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .common.io import read_text
from .common.normalize import canonicalize_host, canonicalize_ip, is_ip_literal

log = logging.getLogger("platform.convergence")

#: Verdict reasons.  Every stop names its condition; nothing stops silently.
CONTINUE = "continue"
STOP_FIXED_POINT = "frontier_exhausted"
STOP_DEGRADED_FIXED_POINT = "frontier_exhausted_while_degraded"
STOP_MAX_ROUNDS = "max_rounds_reached"
STOP_TIME_BUDGET = "time_budget_exhausted"
STOP_ACTION_BUDGET = "active_action_budget_exhausted"
STOP_BLOCKED = "blocked_by_target"
STOP_STAGE_FAILURE = "round_failed"
STOP_NOTHING_TO_REPEAT = "no_pipeline_declares_repeatable_stages"
STOP_NO_FRONTIER = "no_frontier_artifacts_declared"

#: Reasons that mean the surface was, as far as this run can tell, fully walked.
EXHAUSTED_REASONS = (STOP_FIXED_POINT, STOP_DEGRADED_FIXED_POINT)


# --------------------------------------------------------------------------- #
# The frontier: what counts as "an asset"
# --------------------------------------------------------------------------- #


def _url_token(value: str) -> str | None:
    """``url:https://host:port/path?query`` — fragment dropped, host canonical."""
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    host = canonicalize_host(parts.hostname or "")
    if not host:
        return None
    scheme = (parts.scheme or "https").lower()
    try:
        port = parts.port
    except ValueError:  # malformed port — reject rather than invent one
        return None
    authority = host if port in (None, 80, 443) else f"{host}:{port}"
    path = parts.path or "/"
    query = f"?{parts.query}" if parts.query else ""
    return f"url:{scheme}://{authority}{path}{query}"


def _network_token(value: str) -> str | None:
    """``net:103.53.44.0/22`` — host bits cleared so two spellings are one asset."""
    left, _, prefix = value.partition("/")
    address = canonicalize_ip(left)
    if address is None or not prefix.isdigit():
        return None
    try:
        network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
    except ValueError:
        return None
    return f"net:{network.with_prefixlen}"


def token_kind(token: str) -> str:
    """The kind of a canonical token: ``host`` / ``ip`` / ``url`` / ``net``."""
    return token.split(":", 1)[0]


def canonical_token(value: str) -> str | None:
    """Canonical asset token for one frontier line, or ``None`` when it is not one.

    Kind-prefixed on purpose: a bucket name and a hostname are the same shape
    (``qbsco-assets``), so the prefix keeps two collections of the same spelling
    from silently merging into one asset.  Never invents: an unparseable line is
    dropped, not trimmed into something valid.
    """
    token = (value or "").strip()
    if not token or token.startswith("#"):
        return None
    if token.lower().startswith(("http://", "https://")):
        return _url_token(token)
    if "/" in token:
        return _network_token(token)
    if is_ip_literal(token):
        address = canonicalize_ip(token)
        return f"ip:{address}" if address else None
    host = canonicalize_host(token)
    return f"host:{host}" if host else None


@dataclass
class FrontierRead:
    """One pass over the declared frontier artifacts."""

    tokens: set[str] = field(default_factory=set)
    read: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    empty: list[str] = field(default_factory=list)

    @property
    def measured(self) -> bool:
        """True when at least one declared artifact existed at all.

        The distinction that matters is **missing vs. empty**: a file a stage
        wrote with nothing in it is the answer "no such asset", which is a
        measurement; a file that was never written is no answer at all, and the
        driver must not read *that* as exhaustion (the same rule the pipeline
        reports follow).  So existence — not content — is what is measured.
        """
        return bool(self.read or self.empty)

    def to_dict(self) -> dict:
        return {
            "measured": self.measured,
            "tokens": len(self.tokens),
            "artifacts_read": sorted(self.read),
            "artifacts_missing": sorted(self.missing),
            "artifacts_empty": sorted(self.empty),
        }


def read_frontier(paths: Iterable[Path | str]) -> FrontierRead:
    """Canonicalise every line of every declared frontier artifact."""
    result = FrontierRead()
    for path in paths:
        resolved = Path(path)
        body = read_text(resolved)
        if not body:
            # Distinguish "not written" from "written empty": the first is no
            # answer, the second is the answer "nothing found".
            (result.empty if resolved.is_file() else result.missing).append(
                resolved.as_posix()
            )
            continue
        result.read.append(resolved.as_posix())
        for line in body.splitlines():
            token = canonical_token(line)
            if token:
                result.tokens.add(token)
    return result


# --------------------------------------------------------------------------- #
# The ledger: what we have already seen
# --------------------------------------------------------------------------- #


class Ledger:
    """Append-only record of every asset token this engagement has seen.

    One row per newly-observed token (``{"asset", "round", "at"}``), so the file
    doubles as the audit trail of *when* each asset first appeared — and as the
    receipt the escalation loop had been missing: ``seen("host:api…")`` answers
    "have we already been here?" without re-reading a pipeline's artifacts.

    Never raises on write failure: losing telemetry must not take a run down.
    """

    def __init__(self, path: Path | str | None = None) -> None:
        self._path = Path(path) if path else None
        self._seen: set[str] = set()
        if self._path is not None:
            self._load()

    def _load(self) -> None:
        assert self._path is not None
        for line in read_text(self._path).splitlines():
            stripped = line.strip()
            if not stripped.startswith("{"):
                continue
            try:
                row = json.loads(stripped)
            except (json.JSONDecodeError, ValueError):
                continue
            asset = str(row.get("asset") or "")
            if asset:
                self._seen.add(asset)

    def __len__(self) -> int:
        return len(self._seen)

    @property
    def path(self) -> Path | None:
        return self._path

    def seen(self, token: str) -> bool:
        return token in self._seen

    def observe(self, tokens: Iterable[str], *, round_index: int = 0, at: float | None = None) -> set[str]:
        """Record *tokens*; return the ones that were new. Idempotent."""
        now = time.time() if at is None else at
        new = {token for token in tokens if token not in self._seen}
        self._seen |= new
        if new:
            self._append(sorted(new), round_index=round_index, at=now)
        return new

    def _append(self, tokens: Sequence[str], *, round_index: int, at: float) -> None:
        if self._path is None:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8", newline="\n") as handle:
                for token in tokens:
                    handle.write(
                        json.dumps(
                            {"asset": token, "round": round_index, "at": round(at, 3)},
                            sort_keys=False,
                        )
                        + "\n"
                    )
        except OSError as exc:
            log.warning("ledger append failed: %s", exc)

    def to_dict(self) -> dict:
        return {
            "path": self._path.as_posix() if self._path else "",
            "assets_seen": len(self._seen),
        }


# --------------------------------------------------------------------------- #
# The policy and the decision
# --------------------------------------------------------------------------- #


@dataclass
class StopPolicy:
    """The operator-tunable limits; defaults are the conservative ones.

    ``max_rounds`` and ``time_budget_seconds`` are the two that make the loop
    *decisive*: whichever fires first, the run ends with a named reason instead
    of a rumour that it converged.  ``require_empty_rounds`` is the strictness of
    the exhaustion test itself.
    """

    #: Hard ceiling on rounds (round 1 always runs).
    max_rounds: int = 4
    #: Wall-clock ceiling for the whole loop (0 = no time limit).
    time_budget_seconds: float = 2700.0
    #: Cumulative active actions across all rounds (0 = unlimited; the
    #: dispatcher's own per-run budgets still apply inside each round).
    max_active_actions: int = 0
    #: Consecutive rounds that must add fewer than ``min_new_assets`` assets.
    require_empty_rounds: int = 1
    #: A round adding fewer than this is not growth (1 = "nothing new at all").
    min_new_assets: int = 1
    #: Stop the moment a round reports the target blocked/challenged us.
    stop_on_block: bool = True
    #: Treat "no frontier artifact was readable" as a stop (unmeasurable loop).
    stop_without_frontier: bool = True

    def to_dict(self) -> dict:
        return {
            "max_rounds": self.max_rounds,
            "time_budget_seconds": self.time_budget_seconds,
            "max_active_actions": self.max_active_actions,
            "require_empty_rounds": self.require_empty_rounds,
            "min_new_assets": self.min_new_assets,
            "stop_on_block": self.stop_on_block,
            "stop_without_frontier": self.stop_without_frontier,
        }


@dataclass
class Round:
    """One round's outcome — what ran, what it cost, what it added."""

    index: int
    new_assets: int = 0
    frontier_assets: int = 0
    seconds: float = 0.0
    stages_run: int = 0
    stages_failed: int = 0
    active_actions: int = 0
    #: True when the round ran with a degraded service or an unavailable source.
    degraded: bool = False
    #: True when the target blocked/challenged us (stealth quarantine, WAF).
    blocked: bool = False
    #: Whether any declared frontier artifact was readable this round.
    frontier_measured: bool = False
    #: True when this round ran fewer stages than it could have because nothing
    #: new of the kind those stages work on appeared.  A gated round is not the
    #: same as a pipeline that declares no repeat stages: the first has converged,
    #: the second never had a loop.
    gated: bool = False
    stages: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "round": self.index,
            "new_assets": self.new_assets,
            "frontier_assets": self.frontier_assets,
            "seconds": round(self.seconds, 2),
            "stages_run": self.stages_run,
            "stages_failed": self.stages_failed,
            "active_actions": self.active_actions,
            "degraded": self.degraded,
            "blocked": self.blocked,
            "gated": self.gated,
            "frontier_measured": self.frontier_measured,
            "stages": list(self.stages),
            **({"notes": list(self.notes)} if self.notes else {}),
        }


@dataclass(frozen=True)
class Verdict:
    """Should the loop take another round, and why."""

    stop: bool
    reason: str
    detail: str

    @property
    def exhausted(self) -> bool:
        return self.reason in EXHAUSTED_REASONS

    def to_dict(self) -> dict:
        return {"stop": self.stop, "reason": self.reason, "detail": self.detail}


def _empty_streak(rounds: Sequence[Round], policy: StopPolicy) -> int:
    """Trailing rounds that added less than ``min_new_assets`` assets."""
    streak = 0
    for entry in reversed(rounds):
        if entry.new_assets < policy.min_new_assets:
            streak += 1
        else:
            break
    return streak


def decide(
    rounds: Sequence[Round],
    policy: StopPolicy,
    *,
    elapsed: float = 0.0,
) -> Verdict:
    """The whole stopping decision: pure over the rounds so far.

    Precedence, most-safety-first and most-specific-first:

    1. the target blocked us — continuing is the least efficient thing possible;
    2. every stage of the round failed — more rounds would repeat the failure;
    3. no pipeline executed anything — the loop has nothing to iterate;
    4. the active-action budget is spent;
    5. the wall-clock budget is spent;
    6. the round ceiling is reached;
    7. the frontier is unmeasurable (no declared artifact was readable);
    8. the frontier stopped growing — the surface is exhausted, which is the
       *only* reason that claims exhaustion.

    Caps outrank the happy ending deliberately: a run that ran out of time with
    an empty round reports the budget, and says in its detail that the frontier
    was quiet too, rather than overstating "exhausted".
    """
    if not rounds:
        return Verdict(False, CONTINUE, "no round has completed yet")

    last = rounds[-1]

    if policy.stop_on_block and last.blocked:
        return Verdict(
            True,
            STOP_BLOCKED,
            f"round {last.index} was blocked/challenged; stopping before we "
            "escalate the block rather than starve the next engagement's data",
        )

    if last.stages_run and last.stages_failed >= last.stages_run:
        return Verdict(
            True,
            STOP_STAGE_FAILURE,
            f"every stage of round {last.index} failed "
            f"({last.stages_failed}/{last.stages_run}); another round would "
            "repeat the same failure",
        )

    if last.index >= 2 and last.stages_run == 0 and not last.gated:
        return Verdict(
            True,
            STOP_NOTHING_TO_REPEAT,
            "no pipeline declares repeatable stages, so a second round has "
            "nothing to run; convergence is one round by construction",
        )

    total_actions = sum(entry.active_actions for entry in rounds)
    if policy.max_active_actions and total_actions >= policy.max_active_actions:
        return Verdict(
            True,
            STOP_ACTION_BUDGET,
            f"{total_actions} active action(s) reached the budget of "
            f"{policy.max_active_actions}"
            + (" (the frontier was quiet this round too)" if last.new_assets < policy.min_new_assets else ""),
        )

    if policy.time_budget_seconds and elapsed >= policy.time_budget_seconds:
        return Verdict(
            True,
            STOP_TIME_BUDGET,
            f"{elapsed:.0f}s reached the budget of {policy.time_budget_seconds:.0f}s"
            + (" (the frontier was quiet this round too)" if last.new_assets < policy.min_new_assets else ""),
        )

    if len(rounds) >= policy.max_rounds:
        return Verdict(
            True,
            STOP_MAX_ROUNDS,
            f"{len(rounds)} round(s) reached the ceiling of {policy.max_rounds}"
            + (" (the frontier was quiet this round too)" if last.new_assets < policy.min_new_assets else ""),
        )

    if policy.stop_without_frontier and not last.frontier_measured:
        return Verdict(
            True,
            STOP_NO_FRONTIER,
            f"round {last.index} had no readable frontier artifact, so growth "
            "cannot be measured; running on would be unbounded, not convergent",
        )

    streak = _empty_streak(rounds, policy)
    if streak >= policy.require_empty_rounds:
        if last.degraded:
            return Verdict(
                True,
                STOP_DEGRADED_FIXED_POINT,
                f"{streak} round(s) added fewer than {policy.min_new_assets} "
                "asset(s) — exhausted as far as this run could see, with a "
                "degraded service or source; the surface is not proven complete",
            )
        return Verdict(
            True,
            STOP_FIXED_POINT,
            f"{streak} round(s) added fewer than {policy.min_new_assets} "
            "asset(s) and nothing was degraded — the frontier stopped growing",
        )

    return Verdict(
        False,
        CONTINUE,
        f"round {last.index} added {last.new_assets} new asset(s); "
        f"{_empty_streak(rounds, policy)}/{policy.require_empty_rounds} "
        "quiet round(s) toward exhaustion",
    )


# --------------------------------------------------------------------------- #
# The report
# --------------------------------------------------------------------------- #


@dataclass
class ConvergenceReport:
    """The loop's machine-readable account of itself."""

    target: str
    rounds: list[Round] = field(default_factory=list)
    verdict: Verdict = field(default_factory=lambda: Verdict(False, CONTINUE, ""))
    policy: StopPolicy = field(default_factory=StopPolicy)
    ledger: dict = field(default_factory=dict)
    seconds: float = 0.0
    #: The frontier after the last round (declared artifacts, read state).
    frontier: dict = field(default_factory=dict)

    @property
    def total_new_assets(self) -> int:
        return sum(entry.new_assets for entry in self.rounds)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "rounds": [entry.to_dict() for entry in self.rounds],
            "rounds_run": len(self.rounds),
            "new_assets_total": self.total_new_assets,
            "seconds": round(self.seconds, 2),
            "verdict": self.verdict.to_dict(),
            "exhausted": self.verdict.exhausted,
            "policy": self.policy.to_dict(),
            "ledger": self.ledger,
            "frontier": self.frontier,
        }


#: A round executes and reports; the driver owns the loop, not the work.  It is
#: handed the round number and the tokens the *previous* round newly discovered,
#: which is what lets a round skip the pipelines no new asset of theirs appeared
#: for — the difference between iterating and re-asking.
RoundFn = Callable[[int, frozenset[str]], Round]


class ConvergenceDriver:
    """Run rounds until the frontier stops growing, or a limit says stop.

    The driver holds no asset logic and performs no I/O of its own beyond the
    frontier artifacts and the ledger: ``round_fn(index)`` executes round
    ``index`` and returns a :class:`Round` with its cost and health, and the
    driver decides whether there is a round ``index + 1``.  That split is what
    lets the loop run under the platform runner, under ``run_recon.py``'s
    subprocesses, or against a fake round in a test.
    """

    def __init__(
        self,
        *,
        policy: StopPolicy | None = None,
        ledger: Ledger | None = None,
        frontier_paths: Iterable[Path | str] = (),
        clock: Callable[[], float] = time.monotonic,
        log_round: Callable[[str], None] | None = None,
    ) -> None:
        self.policy = policy or StopPolicy()
        # ``is not None``, not ``or``: an empty ledger is falsy (it defines
        # ``__len__``), and silently swapping a file-backed ledger for an
        # in-memory one would lose exactly the cross-round memory this module
        # exists to keep.
        self.ledger = ledger if ledger is not None else Ledger()
        self._frontier_paths = [Path(path) for path in frontier_paths]
        self._clock = clock
        self._log = log_round or (lambda message: log.info("%s", message))

    @property
    def frontier_paths(self) -> list[Path]:
        return list(self._frontier_paths)

    def run(self, round_fn: RoundFn, *, target: str = "") -> ConvergenceReport:
        """Execute rounds until :func:`decide` stops the loop."""
        started = self._clock()
        report = ConvergenceReport(target=target, policy=self.policy)
        read = FrontierRead()
        found: frozenset[str] = frozenset()

        while True:
            index = len(report.rounds) + 1
            outcome = round_fn(index, found)
            if outcome.index != index:
                outcome.index = index  # the driver owns the round numbering

            read = read_frontier(self._frontier_paths)
            new = self.ledger.observe(
                read.tokens, round_index=index, at=time.time()
            )
            found = frozenset(new)
            outcome.new_assets = len(new)
            outcome.frontier_assets = len(read.tokens)
            outcome.frontier_measured = read.measured
            outcome.notes = [
                *outcome.notes,
                *(
                    [f"new this round: {len(new)}"]
                    if new
                    else ["nothing new on the frontier"]
                ),
            ]
            report.rounds.append(outcome)

            elapsed = self._clock() - started
            verdict = decide(report.rounds, self.policy, elapsed=elapsed)
            self._log(
                f"round {index}: {outcome.new_assets} new asset(s) from "
                f"{outcome.frontier_assets} known, {outcome.seconds:.1f}s — "
                f"{'STOP' if verdict.stop else 'continue'} ({verdict.reason})"
            )
            if verdict.stop:
                report.verdict = verdict
                break

        report.seconds = self._clock() - started
        report.ledger = self.ledger.to_dict()
        report.frontier = read.to_dict()
        return report
