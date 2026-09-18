"""
End-to-end runner for the active stage.

The stage answers one question — *which of these names actually exist in DNS, and
what is behind them* — and this module owns the order in which that happens::

    validate resolvers -> gather candidates -> resolve (puredns)
                       -> bruteforce (wordlist) -> recurse under live hosts
                       -> zone-transfer attempts -> wildcard filter
                       -> enrich records -> [opt-in HTTP probe] -> write output

Output contract (everything lands in ``active/output/``)
-------------------------------------------------------
=========================== ==================================================
``resolvers.txt``           validated public resolver pool (tools are pointed
                            here, never at the curated seed files)
``resolvers-trusted.txt``   validated high-trust subset for poisoning checks
``resolvers_rejected.txt``  probed-but-rejected resolvers, with reasons
``candidates.txt``          every candidate name fed to resolution
``resolved.txt``            **the artifact downstream stages consume**: live,
                            wildcard-filtered, in-scope hostnames
``domains.txt``             the in-scope apex itself — the "domain" layer
``wildcards.txt``           confirmed wildcard records, merged with the passive
                            stage's findings when available
``wildcard_suppressed.txt`` names dropped as wildcard noise (auditable)
``records.txt``             per-host DNS records (A/AAAA/CNAME/NS/MX/TXT)
``records.jsonl``           the same, as raw dnsx output
``axfr.txt``                names recovered from a successful zone transfer
``foreign.txt``             out-of-scope names seen in the inputs (excluded)
``http.jsonl``              opt-in HTTP probe results (``--http``)
``report.json``             machine-readable run report
``<tool>.log``              per-tool stderr, for when something looks wrong
=========================== ==================================================

Provenance
----------
Every resolved host is tagged with the step(s) that found it
(``passive``/``bruteforce``/``recursive``/``axfr``).  That is not decoration: the
wildcard filter keeps a name outright when two independent steps corroborate it,
so provenance is what stops a genuinely live host that a wildcard happens to
explain from being discarded.

Safety properties
-----------------
* **A missing tool image is a clean abort, not a crash mid-run.**  The stage's
  tools live in a locally built image, so that is checked before any work starts
  and reported with the exact build command.
* **A failing step degrades, a failing pool aborts.**  One engine, the AXFR pass
  or the HTTP probe failing costs that step only, and the report says which.  But
  fewer than three working resolvers aborts the run: without a trustworthy pool,
  "no such host" and "no working resolver" are indistinguishable, and a
  half-resolved list that looks complete is worse than an obvious failure.
* **Out-of-scope names never reach the output**, and a majority of them abort the
  run — the same stale-input signature the passive stage guards against.
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path

import shared.colorlog as colorlog

from service.recon_pipeline.platform.common.config import TARGET

from ..passive.normalize import ForeignDomainError, canonicalize_host, normalize_host_list
from ..passive.pipeline import (  # noqa: F401  (policy constants, shared vocabulary)
    FOREIGN_ABORT_SHARE,
    FOREIGN_POLICY_LENIENT,
    FOREIGN_POLICY_STRICT,
    FOREIGN_POLICY_THRESHOLD,
)
from ..passive.wildcard import Resolver, detect_wildcards, filter_wildcard_noise
from . import axfr as axfr_mod
from . import enrich as enrich_mod
from . import resolvers as resolver_mod
from .resolve import (
    DEFAULT_ENGINE,
    ENGINES,
    Engine,
    ResolveContext,
    apex_candidates,
    describe_engines,
    get_engine,
    recursion_parents,
    recursive_candidates,
)
from .settings import (
    AXFR_ENABLED,
    AXFR_MAX_NAMESERVERS,
    AXFR_SPACING,
    BRUTEFORCE_ENABLED,
    DEFAULT_SOURCE_TIMEOUT,
    HTTP_ENABLED,
    HTTP_IMPERSONATE,
    HTTP_RATE_LIMIT,
    HTTP_THREADS,
    OUTPUT_DIR,
    PASSIVE_ONLY,
    QUARANTINE_FILE,
    STEALTH_ENABLED,
    PASSIVE_SUBDOMAINS_FILE,
    PUREDNS_RATE_LIMIT,
    RECURSION_ENABLED,
    RECURSION_MAX_DEPTH,
    RECURSION_WORD_LIMIT,
    RESOLVER_MIN_VALID,
    RESOLVER_QUERY_TIMEOUT,
    WILDCARD_ENABLED,
)
from ....platform.stealth.session import StealthConfig, StealthSession
from .tools import ToolImageMissingError, ensure_image, describe_tools
from .wordlist import build_wordlist
from .resolvers import Query, dnspython_query

log = logging.getLogger("active.pipeline")

# Derived output file names (see the module docstring's output contract).
RESOLVED_FILE = "resolved.txt"
CANDIDATES_FILE = "candidates.txt"
DOMAINS_FILE = "domains.txt"
WILDCARDS_FILE = "wildcards.txt"
SUPPRESSED_FILE = "wildcard_suppressed.txt"
AXFR_FILE = "axfr.txt"
FOREIGN_FILE = "foreign.txt"
REPORT_FILE = "report.json"


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #


@dataclass
class ActiveReport:
    """Machine-readable summary of one active stage run."""

    target: str
    engine: str
    started_at: str
    finished_at: str = ""
    seconds: float = 0.0
    ok: bool = True
    #: Set when the run could not proceed at all (e.g. image not built).
    fatal: str | None = None
    resolvers: dict[str, object] = field(default_factory=dict)
    wordlist: dict[str, object] = field(default_factory=dict)
    steps: list[dict[str, object]] = field(default_factory=list)
    axfr: list[dict[str, object]] = field(default_factory=list)
    records: dict[str, object] = field(default_factory=dict)
    http: dict[str, object] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)
    #: Stealth layer state: transport and its limits, identities, pacing, the DNS
    #: budget plan, and any quarantine.  Present so an operator can answer "how
    #: did this run present itself, and what did the target do about it?".
    stealth: dict[str, object] = field(default_factory=dict)
    domains: list[str] = field(default_factory=list)
    wildcards: list[str] = field(default_factory=list)
    suppressed: dict[str, str] = field(default_factory=dict)
    foreign: dict[str, list[str]] = field(default_factory=dict)
    outputs: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(self.__dict__, indent=2, sort_keys=False)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def read_candidate_file(path: Path | str, apex: str) -> set[str]:
    """Read an operator-supplied candidate list, normalised to *apex*'s scope."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        log.warning("candidate file %s not found - ignored", path)
        return set()
    except OSError as exc:
        log.warning("candidate file %s unreadable (%s) - ignored", path, exc)
        return set()
    return set(normalize_host_list(text.splitlines(), apex))


def _foreign_is_disqualifying(policy: str, *, count: int, share: float) -> bool:
    """Decide whether out-of-scope names should abort the stage.

    Deliberately the same rule (and the same constants) as the passive stage —
    the failure it detects, a stale input enumerating the wrong domain, is
    identical here.  Kept local rather than importing the passive stage's private
    helper.
    """
    if policy == FOREIGN_POLICY_LENIENT:
        return False
    if policy == FOREIGN_POLICY_STRICT:
        return count > 0
    return share >= FOREIGN_ABORT_SHARE


def _write_json(path: Path, report: ActiveReport) -> Path:
    """Persist the run report as JSON (atomic replace)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(report.to_json(), encoding="utf-8", newline="\n")
    tmp.replace(path)
    return path


# --------------------------------------------------------------------------- #
# Stage
# --------------------------------------------------------------------------- #


def run_active_stage(
    target: str = TARGET,
    *,
    engine: Engine | str = DEFAULT_ENGINE,
    candidates: Iterable[str] = (),
    candidate_files: Iterable[Path | str] = (),
    from_passive: bool = True,
    bruteforce: bool = BRUTEFORCE_ENABLED,
    wordlist_files: Iterable[Path | str] = (),
    builtin_wordlist: bool = True,
    recursion: bool = RECURSION_ENABLED,
    recursive_depth: int = RECURSION_MAX_DEPTH,
    recursive_word_limit: int = RECURSION_WORD_LIMIT,
    axfr: bool = AXFR_ENABLED,
    enrich: bool = True,
    http: bool = HTTP_ENABLED,
    resolvers: Iterable[str] | None = None,
    trusted_resolvers: Iterable[str] | None = None,
    wildcards: bool = WILDCARD_ENABLED,
    foreign_policy: str = FOREIGN_POLICY_THRESHOLD,
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
    output_dir: Path | str = OUTPUT_DIR,
    query: Query = dnspython_query,
    resolver: Resolver | None = None,
    passive_subdomains_file: Path | str = PASSIVE_SUBDOMAINS_FILE,
    stealth: bool = STEALTH_ENABLED,
    session: StealthSession | None = None,
) -> ActiveReport:
    """Run the full active stage for *target* and write its outputs.

    Parameters
    ----------
    target:
        Apex domain (everything is normalised into its scope).
    engine:
        An :class:`..resolve.Engine`, or the name of one.  Tests inject a fake.
    candidates / candidate_files:
        Extra names to resolve, inline or from files.
    from_passive:
        Seed from the passive stage's ``output/subdomains.txt``.
    bruteforce / wordlist_files / builtin_wordlist:
        Level-1 wordlist enumeration and where its words come from.
    recursion / recursive_depth / recursive_word_limit:
        Bounded second (and later) passes under hosts that already resolved.
    axfr / enrich / http:
        Zone-transfer attempts, DNS record enrichment, and the opt-in HTTP probe.
    resolvers / trusted_resolvers:
        Explicit resolver candidates; the curated seed files are used when not
        supplied.
    wildcards:
        Run detection and suppress wildcard-explained names.
    foreign_policy:
        ``threshold`` (default) / ``strict`` / ``lenient``.
    query / resolver:
        Injected DNS callables for tests (resolver validation / wildcard probing).
    stealth / session:
        Whether to run under the stealth layer (spec §5.1), or an explicit
        :class:`..stealth.session.StealthSession` to use.  When it is active the
        stage refuses to run in passive-only mode, shuffles candidate order, and
        resolves in budget-sized batches, pacing and detecting blocks as it goes.

    Returns
    -------
    ActiveReport
        Also written to ``output/report.json``.  ``ok`` is false when a fatal
        condition or any failed step occurred; ``fatal`` explains an abort.

    Raises
    ------
    ValueError
        For an invalid target or policy.
    ForeignDomainError
        When the selected policy says out-of-scope input is disqualifying.
    """
    if foreign_policy not in (
        FOREIGN_POLICY_THRESHOLD,
        FOREIGN_POLICY_STRICT,
        FOREIGN_POLICY_LENIENT,
    ):
        raise ValueError(
            f"unknown foreign_policy {foreign_policy!r}; expected one of "
            f"{FOREIGN_POLICY_THRESHOLD!r}, {FOREIGN_POLICY_STRICT!r}, "
            f"{FOREIGN_POLICY_LENIENT!r}"
        )

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    apex = canonicalize_host(target)
    if apex is None:
        raise ValueError(
            f"target {target!r} is not a valid domain (expected e.g. 'example.com')"
        )

    engine_obj = engine if isinstance(engine, Engine) else get_engine(engine)
    started = time.monotonic()
    report = ActiveReport(target=apex, engine=engine_obj.name, started_at=_utc_now())

    def finish() -> ActiveReport:
        report.finished_at = _utc_now()
        report.seconds = time.monotonic() - started
        if session is not None:
            # Persist quarantine state (and record how the run presented itself)
            # before the report is serialised, so the report describes the run's
            # final stealth state rather than a stale snapshot.
            report.stealth = session.to_dict()
            session.save()
        report.outputs["report"] = _write_json(output_dir / REPORT_FILE, report).as_posix()
        _log_summary(report)
        return report

    def abort(message: str) -> ActiveReport:
        log.error(message)
        report.ok = False
        report.fatal = message
        return finish()

    # 1. Stealth layer (spec §5.1).  Built before anything else so that even the
    #    image check and resolver validation are paced, and so a run that has
    #    degraded to passive-only refuses *before* touching Docker or DNS rather
    #    than quietly hammering on.
    if session is None and stealth:
        session = StealthSession(
            StealthConfig.from_settings(
                quarantine_path=QUARANTINE_FILE,
                passive_only=PASSIVE_ONLY,
            )
        )
    if session is not None:
        if session.passive_only:
            return abort(
                "passive-only mode is active (PASSIVE_ONLY, or a WAF quarantine carried "
                "over from a previous run): refusing to run the active stage"
            )
        log.info("stealth: %s", session.selection.reason)

    # 2. The stage's tools all run out of a locally built image.  Fail before any
    #    work rather than midway with a confusing tool error.
    if engine_obj.name in ENGINES:
        try:
            ensure_image()
        except ToolImageMissingError as exc:
            return abort(str(exc))
        except Exception as exc:  # Docker missing / daemon down
            return abort(f"Docker is not available: {exc}")

    # 3. Resolver pool.  Without a trustworthy pool nothing below means anything.
    pool = resolver_mod.prepare_resolvers(
        output_dir=output_dir,
        resolvers=resolvers,
        trusted=trusted_resolvers,
        query=query,
        timeout=RESOLVER_QUERY_TIMEOUT,
    )
    report.resolvers = pool.to_dict()
    if not pool.enough:
        return abort(
            f"only {len(pool.valid)}/{RESOLVER_MIN_VALID} working resolver(s) "
            "validated - refusing to produce a resolution result that cannot be "
            "distinguished from a network problem"
        )

    context = ResolveContext(
        apex=apex,
        output_dir=output_dir,
        resolvers=pool.valid,
        trusted=pool.trusted,
        timeout=timeout,
        # The resolver tools' own rate limit is derived from the stealth budget
        # when the operator has not set one explicitly (0 = derive).
        rate_limit=PUREDNS_RATE_LIMIT or (session.dns_rate_limit(resolver_count=len(pool.valid)) if session else 0),
    )

    def resolve_all(names: Sequence[str], *, step: str, label: str = "") -> set[str]:
        """Resolve *names*, honouring the per-resolver volume budget.

        The volume budget is a *count* per resolver, not a rate, so it is
        enforced by splitting the work into batches that are separated in time
        (each batch is its own invocation, with a jittered pause between them)
        rather than by slowing one blast down — slowing a blast changes how it
        looks, not how many names each resolver learns.  A single batch keeps the
        phase's plain artefact names, so small runs look exactly as before.
        """
        candidates = list(dict.fromkeys(names))
        if not candidates:
            return set()
        if session is None:
            result = engine_obj.resolve(candidates, context)
            report.steps.append(dict(result.to_dict(), step=step))
            if not result.ok:
                report.ok = False
            return result.resolved

        plan = session.plan_dns(candidates, pool.valid, seed=apex)
        single = len(plan.batches) <= 1
        found: set[str] = set()
        for batch in plan.batches:
            if batch.index:
                session.pause_between_batches(batch.index)
            batch_context = context if single else replace(context, label=f"{label}batch-{batch.index + 1}")
            result = engine_obj.resolve(list(batch.labels), batch_context)
            report.steps.append(
                dict(result.to_dict(), step=step if single else f"{step}-{batch.index + 1}")
            )
            if not result.ok:
                report.ok = False
            found |= result.resolved
        return found

    # 3. Candidate sources.
    sources: dict[str, set[str]] = {}
    origin: dict[str, str] = {}

    def absorb(hosts: Iterable[str], label: str) -> None:
        for host in hosts:
            sources.setdefault(host, set()).add(label)
            origin.setdefault(host, label)

    passive_candidates: set[str] = set()
    if from_passive:
        passive_candidates = read_candidate_file(passive_subdomains_file, apex)
        if passive_candidates:
            log.info(
                "seeded %d candidate(s) from the passive stage (%s)",
                len(passive_candidates),
                Path(passive_subdomains_file).name,
            )
        else:
            log.warning(
                "no passive candidates found at %s - run the passive stage first "
                "for better coverage (bruteforce alone is much thinner)",
                passive_subdomains_file,
            )

    supplied: set[str] = set()
    for path in candidate_files:
        supplied |= read_candidate_file(path, apex)
    supplied |= set(normalize_host_list(candidates, apex))

    seeds = passive_candidates | supplied

    # 4. Out-of-scope guard: drop and report, abort when it dominates.
    foreign = _foreign_from_sources(apex, candidates, candidate_files)
    if foreign:
        flat = sorted({host for hosts in foreign.values() for host in hosts})
        share = len(flat) / max(1, len(flat) + len(seeds))
        (output_dir / FOREIGN_FILE).write_text(
            "".join(f"{host}\n" for host in flat), encoding="utf-8", newline="\n"
        )
        report.outputs["foreign"] = (output_dir / FOREIGN_FILE).as_posix()
        report.foreign = foreign
        log.warning(
            "%d out-of-scope name(s) in the inputs (%.0f%%) - excluded; see %s",
            len(flat),
            share * 100,
            FOREIGN_FILE,
        )
        if _foreign_is_disqualifying(foreign_policy, count=len(flat), share=share):
            # Raised, not merely recorded, so the condition cannot be mistaken
            # for ordinary "some steps failed" — same contract as the passive
            # stage, which raises the same exception type.
            report.counts = _counts(report, sources, set(), live=set())
            finish()
            raise ForeignDomainError(
                f"{len(flat)} name(s) outside {apex!r} in the inputs "
                f"({share:.0%} of all names - possible stale candidate file or "
                f"wrong TARGET): " + ", ".join(flat[:5]) + f" ({FOREIGN_FILE})",
                offenders={name: list(values) for name, values in foreign.items()},
            )

    # Every candidate name actually queried, so ``candidates.txt`` reflects the
    # run rather than only its inputs.
    queried: set[str] = set(seeds)
    resolved: set[str] = set()

    # 5. Resolve the known candidates (passive + operator-supplied).
    if seeds:
        # ``resolve_all`` shuffles (keyed on the target) before resolving, so the
        # order of the batch does not advertise the source layout, and splits the
        # work when the resolver pool cannot carry the whole volume inside the
        # budget window.
        found = resolve_all(sorted(seeds), step="resolve")
        # One label per *source that contained the name*, so a host found by the
        # passive stage and also handed over by the operator carries both — and
        # therefore counts as corroborated when the wildcard filter runs.
        absorb(found & passive_candidates, "passive")
        absorb(found & supplied, "supplied")
        resolved |= found

    # 6. Level-1 wordlist bruteforce.
    wordlist = build_wordlist(
        files=wordlist_files,
        builtin=builtin_wordlist,
        context={"apex": apex, "output_dir": output_dir},
    )
    report.wordlist = wordlist.to_dict()
    if bruteforce and len(wordlist):
        brute = engine_obj.bruteforce(list(wordlist), context)
        report.steps.append(dict(brute.to_dict(), step="bruteforce"))
        if not brute.ok:
            report.ok = False
        queried |= set(apex_candidates(wordlist, apex))
        fresh = brute.resolved - resolved
        absorb(brute.resolved, "bruteforce")
        resolved |= brute.resolved
        if fresh:
            log.info("bruteforce added %d new live host(s)", len(fresh))

    # 7. Recursion: brute under hosts that already resolved (and their
    #    ancestors), to reach the deeper names a generic wordlist can never find
    #    on its own.
    if recursion and len(wordlist):
        processed: set[str] = set()
        for level in range(1, max(1, recursive_depth)):
            parents = [
                parent
                for parent in recursion_parents(
                    resolved | supplied,
                    apex,
                    max_depth=recursive_depth,
                    prefer=resolved,
                )
                if parent not in processed
            ]
            if not parents:
                break
            names = recursive_candidates(
                list(parents), list(wordlist), word_limit=recursive_word_limit
            )
            log.info(
                "recursion level %d: %d parent(s) x %d word(s) = %d candidate(s)",
                level,
                len(parents),
                min(recursive_word_limit, len(wordlist)),
                len(names),
            )
            # A labelled context gives each pass its own input/output artefacts,
            # so the primary resolve's raw results survive the recursion pass.
            deep_resolved = resolve_all(names, step=f"recursive-{level}", label=f"recursive-{level}-")
            queried |= set(names)
            fresh = deep_resolved - resolved
            absorb(deep_resolved, "recursive")
            resolved |= deep_resolved
            processed |= set(parents)
            if not fresh:
                break

    # 8. Zone transfer attempts (authoritative names, when a server allows it).
    #    Spaced out: one query per nameserver fired back-to-back is a sweep.
    transfers: list[axfr_mod.ZoneTransfer] = []
    if axfr:
        transfers = axfr_mod.zone_transfer(
            apex,
            output_dir=output_dir,
            max_nameservers=AXFR_MAX_NAMESERVERS,
            timeout=timeout,
            spacing=AXFR_SPACING if session else 0.0,
            sleep=(lambda seconds: session.clock.sleep(seconds)) if session else None,
        )
        report.axfr = [transfer.to_dict() for transfer in transfers]
        zone_hosts = axfr_mod.transfer_hosts(transfers)
        if zone_hosts:
            (output_dir / AXFR_FILE).write_text(
                "".join(f"{host}\n" for host in sorted(zone_hosts)),
                encoding="utf-8",
                newline="\n",
            )
            report.outputs["axfr"] = (output_dir / AXFR_FILE).as_posix()
            absorb(zone_hosts, "axfr")
            resolved |= zone_hosts

    # 9. Wildcard detection + suppression, reusing the passive stage's layer so
    #    both stages agree on what a wildcard is.
    verdicts = []
    if wildcards and sources:
        verdicts = detect_wildcards(apex, sources, resolver=resolver)
        filtered = filter_wildcard_noise(sources, verdicts, resolver=resolver)
        kept = filtered.kept
        report.suppressed = filtered.suppressed
    else:
        kept = sources

    report.domains = [apex]
    report.wildcards = sorted({v.pattern for v in verdicts if v.is_wildcard})

    live = sorted(kept)

    # 10. Record enrichment on the names that survived.  The apex and the DMARC
    #     policy name are always enriched alongside the live hosts: mail policy
    #     (MX, SPF in TXT, DMARC in ``_dmarc.<apex>`` TXT) lives on the apex, not
    #     on subdomains.  Measured miss (qbsco.net, 2026-09-17): the stage queried
    #     MX/TXT for four subdomains, none of which had any, while the M365 MX
    #     records that answered for the apex were never asked for.  A NXDOMAIN
    #     ``_dmarc`` is kept as an answered-empty row, so "no DMARC policy" stays a
    #     recorded fact rather than an absence of evidence.
    if enrich:
        enrichment_names = [*live, apex, f"_dmarc.{apex}"]
        enriched = enrich_mod.enrich_records(
            enrichment_names, output_dir=output_dir, timeout=timeout
        )
        report.records = enriched.to_dict()
        if not enriched.ok:
            report.ok = False

    # 11. Opt-in HTTP probe.
    if http and live:
        probed = enrich_mod.probe_http(
            live,
            output_dir=output_dir,
            timeout=timeout,
            rate_limit=HTTP_RATE_LIMIT,
            threads=HTTP_THREADS,
            session=session,
            impersonate=HTTP_IMPERSONATE,
        )
        report.http = probed.to_dict()
        if not probed.ok:
            report.ok = False

    # 12. Write the derived outputs.
    outputs = {
        CANDIDATES_FILE: _write_lines(
            output_dir / CANDIDATES_FILE, sorted(queried)
        ),
        RESOLVED_FILE: _write_lines(output_dir / RESOLVED_FILE, live),
        DOMAINS_FILE: _write_lines(output_dir / DOMAINS_FILE, report.domains),
        WILDCARDS_FILE: _write_lines(output_dir / WILDCARDS_FILE, report.wildcards),
        SUPPRESSED_FILE: _write_lines(
            output_dir / SUPPRESSED_FILE, sorted(report.suppressed)
        ),
    }
    report.outputs.update({key: Path(path).as_posix() for key, path in outputs.items()})

    report.counts = _counts(report, sources, queried, live=set(live))
    return finish()


def _write_lines(path: Path, lines: Iterable[str]) -> Path:
    """Write newline-terminated lines atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(f"{line}\n" for line in lines if line)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(body, encoding="utf-8", newline="\n")
    tmp.replace(path)
    return path


def _foreign_from_sources(
    apex: str, candidates: Iterable[str], candidate_files: Iterable[Path | str]
) -> dict[str, list[str]]:
    """Out-of-scope names seen in operator-supplied candidate sources."""
    foreign: dict[str, list[str]] = {}
    if candidates:
        offenders = sorted(
            {
                str(value).strip().lower().rstrip(".")
                for value in candidates
                if canonicalize_host(str(value)) and not _in_scope(str(value), apex)
            }
        )
        if offenders:
            foreign["candidates"] = offenders
    for path in candidate_files:
        offenders = _foreign_in_file(path, apex)
        if offenders:
            foreign[Path(path).name] = offenders
    return foreign


def _in_scope(value: str, apex: str) -> bool:
    host = canonicalize_host(value)
    return bool(host) and (host == apex or host.endswith("." + apex))


def _foreign_in_file(path: Path | str, apex: str) -> list[str]:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    offenders = {
        str(line).strip().lower().rstrip(".")
        for line in text.splitlines()
        if str(line).strip() and not _in_scope(str(line), apex)
    }
    return sorted(offenders)


def _counts(
    report: ActiveReport,
    sources: dict[str, set[str]],
    queried: set[str],
    *,
    live: set[str],
) -> dict[str, int]:
    """Assemble the report's count block."""
    by_step: dict[str, int] = {}
    for labels in sources.values():
        for label in labels:
            by_step[label] = by_step.get(label, 0) + 1
    return {
        "candidates": len(queried),
        "resolved": len(live),
        "subdomains": len(live),
        "passive": by_step.get("passive", 0),
        "supplied": by_step.get("supplied", 0),
        "bruteforce": by_step.get("bruteforce", 0),
        "recursive": by_step.get("recursive", 0),
        "axfr": by_step.get("axfr", 0),
        "wildcards": len(report.wildcards),
        "wildcard_suppressed": len(report.suppressed),
        "records": int(report.records.get("resolved", 0) or 0),
        "http_live": int(report.http.get("responded", 0) or 0),
        "foreign": sum(len(hosts) for hosts in report.foreign.values()),
    }


def _log_summary(report: ActiveReport) -> None:
    counts = report.counts
    if report.fatal:
        colorlog.log.failed(f"active stage for {report.target}: {report.fatal}")
        return

    colorlog.log.info(
        f"active stage for {report.target}: {counts.get('subdomains', 0)} live "
        f"host(s) from {counts.get('candidates', 0)} candidate(s) "
        f"[passive {counts.get('passive', 0)}, bruteforce "
        f"{counts.get('bruteforce', 0)}, recursion {counts.get('recursive', 0)}, "
        f"axfr {counts.get('axfr', 0)}] in {report.seconds:.1f}s"
    )
    if counts.get("axfr"):
        colorlog.log.warn(
            f"ZONE TRANSFER succeeded - {counts['axfr']} name(s) came straight "
            "from an authoritative zone"
        )
    if report.wildcards:
        colorlog.log.warn(
            "wildcard DNS present; names only explained by it were dropped "
            f"({', '.join(report.wildcards)})"
        )
    if counts.get("foreign"):
        colorlog.log.warn(
            f"{counts['foreign']} out-of-scope name(s) excluded from the output - "
            f"see {report.outputs.get('foreign', FOREIGN_FILE)}"
        )
    for step in report.steps:
        if not step.get("ok"):
            colorlog.log.warn(
                f"step {step.get('step')} ({step.get('engine')}) failed: "
                f"{step.get('error')}"
            )
    if report.ok:
        colorlog.log.success(
            f"live hosts written to {report.outputs.get(RESOLVED_FILE)}"
        )
    else:
        colorlog.log.failed(
            f"active stage for {report.target} completed with failures - see "
            f"{report.outputs.get('report', REPORT_FILE)}"
        )


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m "
        "service.recon_pipeline.pipelines.subdomain_domain_wildcards.active.pipeline",
        description=(
            "Resolve the passive stage's subdomains, brute-force a wordlist, "
            "recurse, attempt zone transfers, enrich records, and write "
            "active/output/."
        ),
    )
    parser.add_argument(
        "-t", "--target", default=TARGET, help=f"apex domain (default: {TARGET})"
    )
    parser.add_argument(
        "--engine", default=DEFAULT_ENGINE,
        help=f"resolution engine (default: {DEFAULT_ENGINE}); see --list",
    )
    parser.add_argument(
        "--candidates", action="append", default=[],
        help="extra candidate file (repeatable)",
    )
    parser.add_argument(
        "--no-passive", action="store_true",
        help="do not seed from passive/output/subdomains.txt",
    )
    parser.add_argument(
        "--wordlist", action="append", default=[],
        help="extra wordlist file (repeatable; the bundled list is also used)",
    )
    parser.add_argument(
        "--no-builtin-wordlist", action="store_true",
        help="use only --wordlist files, not the bundled list",
    )
    parser.add_argument(
        "--no-bruteforce", action="store_true", help="skip wordlist bruteforce"
    )
    parser.add_argument(
        "--no-recursion", action="store_true", help="skip recursive bruteforce"
    )
    parser.add_argument(
        "--no-axfr", action="store_true", help="skip zone-transfer attempts"
    )
    parser.add_argument(
        "--no-enrich", action="store_true", help="skip DNS record enrichment"
    )
    parser.add_argument(
        "--no-wildcards", action="store_true",
        help="skip wildcard detection and wildcard-flood suppression",
    )
    parser.add_argument(
        "--http", action="store_true",
        help="enable the HTTP probe (sends application traffic to the target)",
    )
    parser.add_argument(
        "--resolvers", action="append", default=[],
        help="resolver list to probe instead of the curated seed (repeatable)",
    )
    parser.add_argument(
        "--trusted-resolvers", action="append", default=[],
        help="trusted resolver list for poisoning validation (repeatable)",
    )
    foreign_group = parser.add_mutually_exclusive_group()
    foreign_group.add_argument(
        "--strict-foreign", action="store_true",
        help="abort on a single out-of-scope name (overrides the default)",
    )
    foreign_group.add_argument(
        "--lenient-foreign", action="store_true",
        help="never abort on out-of-scope names; only record and warn",
    )
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_SOURCE_TIMEOUT,
        help=f"per-tool timeout in seconds (default: {DEFAULT_SOURCE_TIMEOUT})",
    )
    parser.add_argument(
        "--output-dir", default=str(OUTPUT_DIR),
        help=f"output directory (default: {OUTPUT_DIR})",
    )
    parser.add_argument(
        "--list", action="store_true", help="list engines and tools, then exit"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="show debug logging"
    )
    return parser


def _read_resolver_args(paths: Iterable[str]) -> list[str] | None:
    """Read ``--resolvers``/``--trusted-resolvers`` files into one address list."""
    paths = list(paths)
    if not paths:
        return None
    addresses: list[str] = []
    for path in paths:
        addresses += resolver_mod.load_resolvers_file(path)
    return addresses


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.  Returns a process exit code."""
    args = _build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-7s %(name)s: %(message)s",
    )

    if args.list:
        print("engines")
        print("-" * 78)
        for row in describe_engines():
            print(f"  {row['name']:<12} {row['description']}")
        print("\ntools")
        print("-" * 78)
        for row in describe_tools():
            print(f"  {row['name']:<12} {row['description']}")
        return 0

    try:
        report = run_active_stage(
            args.target,
            engine=args.engine,
            candidate_files=args.candidates,
            from_passive=not args.no_passive,
            bruteforce=not args.no_bruteforce,
            wordlist_files=args.wordlist,
            builtin_wordlist=not args.no_builtin_wordlist,
            recursion=not args.no_recursion,
            axfr=not args.no_axfr,
            enrich=not args.no_enrich,
            http=args.http,
            resolvers=_read_resolver_args(args.resolvers),
            trusted_resolvers=_read_resolver_args(args.trusted_resolvers),
            wildcards=not args.no_wildcards,
            foreign_policy=(
                FOREIGN_POLICY_STRICT
                if args.strict_foreign
                else FOREIGN_POLICY_LENIENT
                if args.lenient_foreign
                else FOREIGN_POLICY_THRESHOLD
            ),
            timeout=args.timeout,
            output_dir=args.output_dir,
        )
    except ForeignDomainError as exc:
        colorlog.log.failed(str(exc))
        return 2
    except (ValueError, KeyError) as exc:
        colorlog.log.failed(str(exc))
        return 2

    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
