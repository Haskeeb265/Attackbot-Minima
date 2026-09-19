"""URL live verification — turning an archived URL into a checked fact.

This module is the URL pipeline's answer to the one question historical harvests
cannot answer: **is it still there?**  Wayback, Common Crawl, urlscan and gau
prove that a URL *existed* when a crawler saw it — sometimes a decade ago.  They
prove nothing about now, and until this stage existed nothing in the pipeline
ever found out, so "3 207 URLs" was a number about the past being read as a
statement about the present.

Discovery and validation stay semantically separate, and the artifact says which
is which::

    wayback / gau  ->  URL candidate  ->  normalize/dedupe  ->  policy gate
                   ->  live HTTP validation  ->  URL enriched (this module)

An archived URL is never treated as automatically live.  Every URL carries two
independent kinds of statement about it: the historical claim (``urls.jsonl``,
with its own provenance) and the validation record written here.

The gate
--------

Validation is *not* "probe everything".  Two things decide who gets checked:

* **the scope engine** — an out-of-scope host is never probed, whatever else is
  true about it (the same chokepoint the active DNS stage uses).  In practice the
  passive union is already apex-filtered; this is the second lock on the door,
  because "the passive stage filtered it" is not a safety argument;
* **the platform's escalation policy** (:mod:`platform.escalation`) — the
  ``url_validation`` operation, which refuses a URL that was already validated in
  a previous run, one that has already been measured dead, and anything the
  policy's operator tunables exclude.

Candidates are prioritised rather than taken in file order, because the cap is
real: interesting paths first (``.git/config``, ``.env``, backups, admin
consoles), then APIs and parameterised URLs — the endpoints a human wants checked
first — then everything else, deterministically ordered so two runs over the same
union validate the same URLs.

Idempotency
-----------

The validation artifact *is* the operation state.  On re-run, records fresher
than ``URL_VALIDATE_TTL`` are reused and their URLs are not probed again, so the
stage is safe to run repeatedly in one engagement: it validates the new
candidates and leaves the rest alone.  Merging is keyed on the canonical URL, so
a repeat can never duplicate a record — and a *stale* record is refreshed in
place, keeping its URL identity.

Everything above except the HTTP call itself is pure: the candidate policy, the
tool-output parser, the merge and the state classification.  That is what makes
them unit-testable without a network, which is the only way to trust the counts
a run reports.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from service.recon_pipeline.platform import escalation
from service.recon_pipeline.platform import scoring as engine
from service.recon_pipeline.platform.common.io import write_jsonl
from service.recon_pipeline.platform.scope import OUT_OF_SCOPE

from . import normalize as norm
from .active import probe as probe_mod
from .settings import (
    OUTPUT_DIR,
    PASSIVE_OUTPUT_DIR,
    VALIDATE_MAX_PER_HOST,
    VALIDATE_MAX_URLS,
    VALIDATE_TTL,
)

log = logging.getLogger("url.validate")

#: The artifact this stage writes: one JSON object per validated URL.
VALIDATIONS_FILE = "url_validation.jsonl"
REPORT_FILE = "validation.json"

# --------------------------------------------------------------------------- #
# Validation states — the vocabulary a consumer filters on
# --------------------------------------------------------------------------- #

#: A response in the 2xx/3xx range, with the address unchanged by redirects.
STATE_VERIFIED = "verified"
#: A response that landed somewhere else — recorded with the chain that proves it.
STATE_REDIRECTED = "redirected"
#: Answered, but the request was refused (401/403/429/...).  Real evidence the
#: URL is served; not evidence of what it serves.
STATE_PROTECTED = "protected"
#: Answered, and the resource is gone (404/410/400/405/451).
STATE_DEAD = "dead"
#: Answered with a server error (5xx): present and broken.
STATE_ERRORED = "errored"
#: No response at all: DNS failure, timeout, TLS refusal, connection reset.
STATE_UNREACHABLE = "unreachable"

ALL_STATES: tuple[str, ...] = (
    STATE_VERIFIED,
    STATE_REDIRECTED,
    STATE_PROTECTED,
    STATE_DEAD,
    STATE_ERRORED,
    STATE_UNREACHABLE,
)

#: States where the server answered *something*.
ANSWERED_STATES = frozenset(
    {STATE_VERIFIED, STATE_REDIRECTED, STATE_PROTECTED, STATE_DEAD, STATE_ERRORED}
)

#: Status codes that mean "the resource is not served here any more".
DEAD_STATUSES = frozenset({400, 404, 405, 410, 451})
#: Status codes that mean "answered, but on its own terms".
PROTECTED_STATUSES = frozenset({401, 403, 407, 429})


def state_for(status: int | None, *, error: str = "", final_url: str = "", url: str = "") -> str:
    """The validation state for one response.

    ``None`` status is a transport failure and is classified from the error text
    only in the sense of being *unreachable* — the function never guesses that a
    timeout was a 404.
    """
    if status is None:
        return STATE_UNREACHABLE
    if 200 <= status < 400:
        same = not final_url or _same_resource(final_url, url)
        return STATE_VERIFIED if same else STATE_REDIRECTED
    if status in DEAD_STATUSES:
        return STATE_DEAD
    if status in PROTECTED_STATUSES:
        return STATE_PROTECTED
    if status >= 500:
        return STATE_ERRORED
    return STATE_DEAD


def _same_resource(final_url: str, url: str) -> bool:
    """True when two URLs differ only in ways that are not a redirect target change.

    Both sides are already canonical (see :func:`parse_httpx_jsonl`), so a
    default port, a trailing slash on the empty path or a folded fragment cannot
    masquerade as one.
    """
    if not url:
        return True
    return final_url == url


# --------------------------------------------------------------------------- #
# The record
# --------------------------------------------------------------------------- #


@dataclass
class ValidationRecord:
    """What one live check of one URL found, with its provenance."""

    url: str
    #: One of :data:`ALL_STATES`.
    state: str
    #: True when a response came back at all (any status).
    alive: bool = False
    status: int | None = None
    #: Where the request actually landed, when that is not the URL itself.
    final_url: str = ""
    #: Every hop the tool observed, in order (``[301, 200]``).
    redirect_chain: list[int] = field(default_factory=list)
    content_type: str = ""
    title: str = ""
    server: str = ""
    tech: list[str] = field(default_factory=list)
    #: The address the response came from, when the tool reported one.
    address: str = ""
    #: Transport-level error, when there was one.
    error: str = ""
    #: ``observed``: we measured it.  The historical claim is a different record.
    trust: str = "observed"
    #: ISO-8601 UTC, the moment the check happened.
    validated_at: str = ""
    #: Which tool produced this (``httpx`` today; a field, not a constant, so a
    #: second validator can coexist and still be distinguishable in the graph).
    tool: str = "httpx"
    #: The candidate's own classification (``page``, ``api``, ``js``, …) from the
    #: extract stage, carried along because it is what made the URL a candidate
    #: in the first place.  Not the discovery *tool*: the templates's source is the
    #: URL pipeline's passive stage, and naming it here would duplicate a fact the
    #: graph already records on the URL node.
    kinds: list[str] = field(default_factory=list)

    @property
    def redirected(self) -> bool:
        return self.state == STATE_REDIRECTED and bool(self.final_url)

    @property
    def dead(self) -> bool:
        return self.state in (STATE_DEAD, STATE_UNREACHABLE)

    def is_fresh(self, *, now: float, ttl: float) -> bool:
        """True when this measurement is recent enough to reuse.

        ``ttl <= 0`` means "never reuse": the operator asked for a fresh
        measurement of every candidate, so no previous one counts as current.
        """
        if ttl <= 0 or not self.validated_at:
            return False
        return (now - _timestamp(self.validated_at)) <= ttl

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "url": self.url,
            "state": self.state,
            "alive": self.alive,
            "validation_tool": self.tool,
            "validated_at": self.validated_at,
            "trust": self.trust,
        }
        if self.status is not None:
            payload["status"] = self.status
        if self.final_url:
            payload["final_url"] = self.final_url
        if self.redirect_chain:
            payload["redirect_chain"] = list(self.redirect_chain)
        for key, value in (
            ("content_type", self.content_type),
            ("title", self.title),
            ("server", self.server),
            ("address", self.address),
            ("error", self.error),
        ):
            if value:
                payload[key] = value
        if self.tech:
            payload["tech"] = list(self.tech)
        if self.kinds:
            payload["kinds"] = list(self.kinds)
        return payload

    @classmethod
    def from_dict(cls, row: dict[str, object]) -> "ValidationRecord | None":
        """Rebuild a record from an artifact line; ``None`` when it is not one."""
        url = str(row.get("url", "")).strip()
        state = str(row.get("state", "")).strip()
        if not url or state not in ALL_STATES:
            return None
        status = row.get("status")
        return cls(
            url=url,
            state=state,
            alive=bool(row.get("alive")),
            status=int(status) if isinstance(status, int) else None,
            final_url=str(row.get("final_url", "") or ""),
            redirect_chain=_int_list(row.get("redirect_chain")),
            content_type=str(row.get("content_type", "") or ""),
            title=str(row.get("title", "") or ""),
            server=str(row.get("server", "") or ""),
            tech=[str(item) for item in _as_list(row.get("tech"))],
            address=str(row.get("address", "") or ""),
            error=str(row.get("error", "") or ""),
            trust=str(row.get("trust", "") or "observed"),
            validated_at=str(row.get("validated_at", "") or ""),
            tool=str(row.get("validation_tool", "") or "httpx"),
            kinds=[str(item) for item in _as_list(row.get("kinds"))],
        )


# --------------------------------------------------------------------------- #
# Candidate selection — the policy gate
# --------------------------------------------------------------------------- #


#: The URL stage's kind vocabulary → the policy's rank.  Kept here because the
#: kinds are this pipeline's (``normalize.KIND_*``) and the *policy* must not
#: depend on them: the table is the adapter between the two.
KIND_RANK: dict[str, int] = {
    norm.KIND_API: 1,
    norm.KIND_JSON: 2,
    norm.KIND_XML: 2,
    norm.KIND_JS: 3,
    norm.KIND_SOURCEMAP: 3,
    norm.KIND_DOC: 4,
    norm.KIND_ARCHIVE: 4,
    norm.KIND_PAGE: 5,
    norm.KIND_OTHER: 6,
    norm.KIND_IMAGE: 7,
    norm.KIND_MEDIA: 8,
    norm.KIND_CSS: 9,
}


def candidate_priority(
    item: norm.ParsedUrl,
    *,
    scope_state: str = "",
    sources: int = 1,
    host_state: str = escalation.URL_HOST_UNKNOWN,
) -> escalation.UrlPriority:
    """How urgently this URL deserves one of the run's bounded request budget.

    The ranking *rule* lives in the platform policy
    (:func:`platform.escalation.url_validation_priority`), not here, so the
    selection cannot drift away from the policy the rest of the pipeline is
    gated by; this function only translates the URL stage's own vocabulary (its
    kinds) into it.  The old version ranked by "interesting paths first" and
    nothing else, which meant two thousand archived pages competed on path length
    alone and a host whose every measurement had already failed kept getting
    picked — both are inputs now.
    """
    return escalation.url_validation_priority(
        scope_state=scope_state,
        kind_rank=KIND_RANK.get(item.kind, 6),
        interesting=item.interesting,
        has_parameters=bool(item.params),
        sources=sources,
        host_state=host_state,
    )


def host_states(records: Iterable[ValidationRecord]) -> dict[str, str]:
    """Per-host state from what this run has *already measured*, for prioritising.

    ``verified`` means the host answered something (any status, including a 404:
    a server that speaks is a host worth asking more of), ``dead`` means nothing
    on it has answered yet.  Adaptive and measured — it never infers a host's
    state from a score.
    """
    answered: set[str] = set()
    seen: set[str] = set()
    for record in records:
        host = _host_of(record.url)
        if not host:
            continue
        seen.add(host)
        if record.state in ANSWERED_STATES:
            answered.add(host)
    return {
        host: (escalation.URL_HOST_VERIFIED if host in answered else escalation.URL_HOST_DEAD)
        for host in seen
    }


def source_counts(
    urls: Iterable[str], *, passive_dir: Path | str | None = None
) -> dict[str, int]:
    """How many passive sources independently emitted each canonical URL.

    Read from the passive stage's own per-source files (``<source>.urls.txt``),
    because that is where independent provenance already lives: the union loses
    it by design, and "three archives agree this endpoint exists" is a stronger
    reason to spend a request than "one crawler mentioned it once".  An absent
    directory is an empty answer, not an error — the stage must still work when
    the passive outputs have been cleaned up.
    """
    directory = Path(passive_dir) if passive_dir is not None else PASSIVE_OUTPUT_DIR
    wanted = set(urls)
    if not directory.is_dir() or not wanted:
        return {}
    counts: dict[str, int] = {}
    for path in sorted(directory.glob("*.urls.txt")):
        seen: set[str] = set()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            canonical = norm.canonicalize_url(line)
            if canonical and canonical in wanted:
                seen.add(canonical)
        for url in seen:
            counts[url] = counts.get(url, 0) + 1
    return counts


@dataclass
class CandidateSelection:
    """Who the policy gate let through, and who it refused (with the reason)."""

    selected: list[norm.ParsedUrl] = field(default_factory=list)
    refused: list[dict[str, object]] = field(default_factory=list)
    already_validated: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    capped: int = 0
    #: Why each selected URL was selected, by rank — the explainable half of the
    #: prioritisation, kept for the first few so ``validation.json`` shows the
    #: reasoning without carrying thousands of rows.
    priorities: list[dict[str, object]] = field(default_factory=list)
    #: The per-host limit actually applied, after the fairness share below.
    per_host_limit: int = 0
    #: How many candidates were skipped because their host's share was spent.
    capped_per_host: int = 0

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "selected": len(self.selected),
            "already_validated": len(self.already_validated),
            "out_of_scope": len(self.out_of_scope),
            "refused": len(self.refused),
        }
        if self.capped:
            payload["capped"] = self.capped
            payload["capped_per_host"] = self.capped_per_host
            payload["refused_sample"] = self.refused[:10]
        if self.per_host_limit:
            payload["per_host_limit"] = self.per_host_limit
        if self.priorities:
            payload["priority_sample"] = self.priorities[:5]
        return payload


def per_host_limit(
    *, max_urls: int, hosts: int, max_per_host: int
) -> int:
    """How many candidates one host may take before the others get their turn.

    Two settings, two jobs: ``max_urls`` is the run's budget and ``max_per_host``
    is the *fairness* floor that stops one chatty host consuming it.  Reading the
    floor as a hard ceiling conflated them, and the difference is measurable: on
    the ``qbsco.net`` union (3 207 URLs, but only 5 hosts, 2 408 of them on the
    apex) a flat 25 per host validated **50** URLs out of a budget of 200, so 150
    authorised requests went unspent while 3 061 candidates were skipped as
    "per-host cap reached".  The budget was never the constraint.

    So a host's share is an equal division of the run budget, and the configured
    value is the floor beneath it — never a cap above it.  Nothing is inflated:
    the total is still ``max_urls``, and a run with many hosts behaves exactly as
    before, because the share collapses below the floor the moment there are more
    hosts than the budget can go round.
    """
    if not max_urls or not hosts:
        return max_per_host
    share = -(-max_urls // hosts)  # ceil, so the budget is actually spendable
    return max(max_per_host, share)


def select_candidates(
    parsed: Iterable[norm.ParsedUrl],
    *,
    scope=None,
    policy: escalation.EscalationPolicy | None = None,
    known_fresh: Iterable[str] = (),
    max_urls: int = VALIDATE_MAX_URLS,
    max_per_host: int = VALIDATE_MAX_PER_HOST,
    dispatcher=None,
    sources: dict[str, int] | None = None,
    host_state_map: dict[str, str] | None = None,
    explain: int = 5,
) -> CandidateSelection:
    """Decide which canonical URLs deserve a live check — and record why not.

    Pure: it takes the parsed URLs, the scope engine and the policy, and returns
    the selection.  Nothing here sends a request, which is what makes the gate
    testable on its own (see ``tests/recon/test_url_validation.py``).

    *sources* (independent mention counts) and *host_state_map* (what this run has
    already measured per host) only affect *order*, never eligibility: the budget
    is spent best-first and the gate is untouched by the ranking.
    """
    policy = policy or escalation.EscalationPolicy()
    fresh = {url for url in known_fresh if url}
    per_host: dict[str, int] = {}
    selection = CandidateSelection()
    parsed = list(parsed)
    source_map = sources or {}
    host_states_map = host_state_map or {}
    host_count = len({item.host for item in parsed})
    host_limit = per_host_limit(
        max_urls=max_urls, hosts=host_count, max_per_host=max_per_host
    )
    selection.per_host_limit = host_limit

    # Scope is decided once per host, before ordering: the same answer is then
    # used for the ranking and for the gate, so a URL cannot be prioritised as
    # in-scope and refused as out-of-scope in the same run.
    scope_cache: dict[str, tuple[str, str]] = {}

    def scope_of(host: str) -> tuple[str, str]:
        cached = scope_cache.get(host)
        if cached is not None:
            return cached
        if scope is None:
            scope_cache[host] = ("", "")
            return scope_cache[host]
        decision = scope.check_address(host) if _is_ip(host) else scope.check_host(host)
        scope_cache[host] = (decision.state, decision.reason)
        return scope_cache[host]

    def priority_of(item: norm.ParsedUrl) -> escalation.UrlPriority:
        return candidate_priority(
            item,
            scope_state=scope_of(item.host)[0],
            sources=source_map.get(item.url, 1),
            host_state=host_states_map.get(item.host, escalation.URL_HOST_UNKNOWN),
        )

    ordered = sorted(
        parsed,
        key=lambda candidate: priority_of(candidate).sort_key(
            path_length=len(candidate.path), url=candidate.url
        ),
    )
    ranks = {item.url: priority_of(item).rank for item in ordered}
    #: Candidates the gate allowed whose host's equal share was already spent.
    #: Held for the second pass rather than dropped, so a run with few hosts still
    #: spends the budget it was given (see :func:`per_host_limit`).
    deferred: list[norm.ParsedUrl] = []

    def admit(item: norm.ParsedUrl) -> None:
        per_host[item.host] = per_host.get(item.host, 0) + 1
        selection.selected.append(item)
        if len(selection.priorities) < explain:
            priority = priority_of(item)
            selection.priorities.append(
                {
                    "url": item.url,
                    "rank": priority.rank,
                    "reason": priority.reason,
                    "sources": source_map.get(item.url, 1),
                }
            )

    def budget_spent() -> bool:
        return bool(max_urls) and len(selection.selected) >= max_urls

    for item in ordered:
        if item.url in fresh:
            selection.already_validated.append(item.url)
            continue
        # Scope first: an out-of-scope host is never probed, and the refusal is
        # reported rather than being folded into "nothing to do".
        scope_state = ""
        if scope is not None:
            scope_state, scope_reason = scope_of(item.host)
            if scope_state == OUT_OF_SCOPE:
                selection.out_of_scope.append(item.url)
                selection.refused.append(
                    {"url": item.url, "reason": f"scope: {scope_reason}"}
                )
                continue

        evidence = escalation.AssetEvidence(
            asset_type="url",
            identity=item.url,
            scope_state=scope_state,
            # A URL from the passive union is a *historical* claim: archives say
            # it existed.  Nothing here has measured it yet, which is what the
            # whole stage is for.
            evidence_state=engine.EVIDENCE_HISTORICAL,
            historical=True,
            has_parameters=bool(item.params),
        )
        verdict = escalation.decide(
            evidence, escalation.OPERATION_URL_VALIDATION, policy=policy
        )
        if not verdict.eligible:
            selection.refused.append({"url": item.url, "reason": verdict.reason})
            continue
        if dispatcher is not None:
            gate = dispatcher.decide(
                item.host,
                asset_type="url",
                operation=escalation.OPERATION_URL_VALIDATION,
                hosting=escalation.HOSTING_UNKNOWN,
                evidence_state=evidence.evidence_state,
            )
            if not gate.allowed:
                selection.refused.append({"url": item.url, "reason": f"dispatch: {gate.reason}"})
                continue
        if host_limit and per_host.get(item.host, 0) >= host_limit:
            deferred.append(item)
            continue
        if budget_spent():
            selection.capped += 1
            selection.refused.append(
                {"url": item.url, "reason": f"run budget reached ({max_urls})"}
            )
            continue
        admit(item)

    # Second pass: the equal shares are guaranteed first, so whatever budget is
    # left over goes to the best-ranked candidates still waiting — on any host.
    # A chatty host therefore gets *its share plus leftovers*, never the whole run
    # before another host has had its share, and a run with many hosts is
    # unaffected because the first pass already spends the budget.
    for item in deferred:
        if budget_spent():
            selection.capped += 1
            selection.capped_per_host += 1
            selection.refused.append(
                {
                    "url": item.url,
                    "reason": f"per-host share spent ({host_limit}) for {item.host} and "
                    f"the run budget ({max_urls}) is allocated",
                }
            )
            continue
        admit(item)
    # Selected order is rank order, so the list handed to the tool is the same on
    # every run over the same candidate set.
    selection.selected.sort(key=lambda item: (-ranks[item.url], len(item.path), item.url))
    return selection


# --------------------------------------------------------------------------- #
# Parsing the tool's output
# --------------------------------------------------------------------------- #


def parse_httpx_jsonl(
    text: str,
    *,
    requested: Iterable[str] = (),
    validated_at: str = "",
    tool: str = probe_mod.NAME,
) -> list[ValidationRecord]:
    """Turn ``httpx -json`` output into validation records.

    ``input`` is the URL we asked about and ``url`` is where the request landed:
    keeping the two apart is what makes a redirect a first-class fact instead of
    a silent substitution.  A line that will not parse is skipped, and a URL the
    tool never reported is *not* invented — :func:`run_validate_stage` accounts
    for those separately.
    """
    records: list[ValidationRecord] = []
    known = {str(url) for url in requested}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            payload = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        requested_url = str(payload.get("input") or payload.get("url") or "").strip()
        # The tool reports the URL it landed on with the port spelled out
        # (``https://host:443/``), so it is canonicalized through *our* identity
        # function before it is compared or recorded.  Without this every
        # response would look like a redirect to a port-qualified twin of the
        # URL that was asked for — a false redirect, which is worse than none.
        raw_final = str(payload.get("final_url") or payload.get("url") or "").strip()
        final_url = norm.canonicalize_url(raw_final) or raw_final
        if not requested_url or (known and requested_url not in known):
            # A response for a URL we did not ask about is not ours to record.
            continue
        status = payload.get("status_code")
        status = int(status) if isinstance(status, int) and not isinstance(status, bool) else None
        failed = payload.get("failed") is True
        error = str(payload.get("error") or "")
        if failed and status is None:
            records.append(
                ValidationRecord(
                    url=requested_url,
                    state=STATE_UNREACHABLE,
                    alive=False,
                    error=error or "probe failed",
                    validated_at=validated_at,
                    tool=tool,
                )
            )
            continue
        state = state_for(status, error=error, final_url=final_url, url=requested_url)
        records.append(
            ValidationRecord(
                url=requested_url,
                state=state,
                alive=state in ANSWERED_STATES,
                status=status,
                final_url=final_url if final_url and final_url != requested_url else "",
                redirect_chain=_int_list(
                    payload.get("chain_status_codes") or payload.get("chain_status_code")
                ),
                content_type=str(payload.get("content_type") or ""),
                title=str(payload.get("title") or ""),
                server=str(payload.get("webserver") or payload.get("server") or ""),
                tech=_tech(payload),
                # ``host_ip`` is the address that answered; ``host`` is the name
                # we asked for, which the URL already carries.
                address=str(payload.get("host_ip") or payload.get("host") or ""),
                error=error,
                validated_at=validated_at,
                tool=tool,
            )
        )
    return _dedupe(records)


def _tech(payload: dict) -> list[str]:
    tech = payload.get("tech")
    values = _as_list(tech)
    if not values and payload.get("cdn_name"):
        values = [str(payload["cdn_name"])]
    return sorted({str(item).strip() for item in values if str(item).strip()})


def _dedupe(records: list[ValidationRecord]) -> list[ValidationRecord]:
    """One record per URL, keeping the strongest state when a tool reports twice.

    httpx emits one line per resolved address, so a URL on two A records arrives
    twice (measured: 50 lines for 25 inputs on a dual-address Cloudflare host),
    and it re-verifies the same way naabu does.  "Strongest" is ordered by how
    much the state tells a consumer: an answer beats no answer.
    """
    rank = {state: index for index, state in enumerate(ALL_STATES)}
    best: dict[str, ValidationRecord] = {}
    for record in records:
        current = best.get(record.url)
        if current is None or rank.get(record.state, 99) < rank.get(current.state, 99):
            best[record.url] = record
    return [best[url] for url in sorted(best)]


# --------------------------------------------------------------------------- #
# Idempotency — merging with what a previous run already measured
# --------------------------------------------------------------------------- #


def load_validations(path: Path | str) -> dict[str, ValidationRecord]:
    """Read the validation artifact into ``{url: record}`` (missing = empty)."""
    file = Path(path)
    if not file.is_file():
        return {}
    records: dict[str, ValidationRecord] = {}
    for line in file.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            payload = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        record = ValidationRecord.from_dict(payload)
        if record is not None:
            records[record.url] = record
    return records


def merge_validations(
    previous: dict[str, ValidationRecord],
    fresh: Iterable[ValidationRecord],
) -> dict[str, ValidationRecord]:
    """Fold new measurements into the previous ones, keyed on the URL.

    A URL can never appear twice, and only a *newer* measurement replaces an old
    one — so re-running the stage is idempotent, and running it against a
    partially-stale artifact updates exactly the URLs it re-checked.
    """
    merged = dict(previous)
    for record in fresh:
        existing = merged.get(record.url)
        if existing is None or _timestamp(record.validated_at) >= _timestamp(
            existing.validated_at
        ):
            merged[record.url] = record
    return merged


def fresh_urls(
    previous: dict[str, ValidationRecord], *, now: float, ttl: float
) -> set[str]:
    """URLs whose previous measurement is recent enough not to repeat."""
    return {
        url
        for url, record in previous.items()
        if record.validated_at and record.is_fresh(now=now, ttl=ttl)
    }


# --------------------------------------------------------------------------- #
# The stage
# --------------------------------------------------------------------------- #


@dataclass
class UrlValidationReport:
    """Machine-readable summary of one validation pass."""

    target: str
    started_at: str
    finished_at: str = ""
    seconds: float = 0.0
    ok: bool = True
    counts: dict[str, int] = field(default_factory=dict)
    by_state: dict[str, int] = field(default_factory=dict)
    selection: dict[str, object] = field(default_factory=dict)
    probe: dict[str, object] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    outputs: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(self.__dict__, indent=2, sort_keys=False)


def run_validate_stage(
    target: str,
    urls: Iterable[str],
    *,
    output_dir: Path | str = OUTPUT_DIR,
    scope=None,
    policy: escalation.EscalationPolicy | None = None,
    dispatcher=None,
    session=None,
    run=None,
    max_urls: int = VALIDATE_MAX_URLS,
    max_per_host: int = VALIDATE_MAX_PER_HOST,
    ttl: float = VALIDATE_TTL,
    now: float | None = None,
    enabled: bool = True,
    timeout: float | None = None,
    passive_dir: Path | str | None = None,
) -> UrlValidationReport:
    """Validate the URL candidates *urls* that the policy gate allows.

    Parameters
    ----------
    scope:
        A :class:`platform.scope.ScopeEngine`.  When omitted, one is built from
        *target* — the stage never probes without a scope verdict.
    run:
        Injected tool runner (tests use it to feed canned ``httpx`` output);
        production runs the tool out of the Docker image.
    ttl:
        Freshness window for reusing a previous measurement.  ``0`` disables
        reuse, so every candidate is re-checked.
    enabled:
        ``False`` records the pass as skipped — the artifact is left untouched,
        which is what an operator running a passive-only engagement wants.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    clock = time.time() if now is None else now
    validated_at = datetime.fromtimestamp(clock, tz=timezone.utc).isoformat(
        timespec="seconds"
    )

    report = UrlValidationReport(target=target, started_at=validated_at)
    validation_path = output_dir / VALIDATIONS_FILE

    if not enabled:
        report.counts = {"candidates": 0, "validated": 0}
        report.notes.append("URL validation is switched off (URL_VALIDATE=off)")
        report.probe = {"skipped": "validation disabled"}
        report.finished_at = _utc_now()
        report.outputs["report"] = str(_write_json(output_dir / REPORT_FILE, report))
        return report

    if scope is None:
        from service.recon_pipeline.platform.scope import ScopeEngine

        scope = ScopeEngine.from_domain(target)

    parsed = norm.parse_urls(list(urls), target)
    previous = load_validations(validation_path)
    reusable = fresh_urls(previous, now=clock, ttl=ttl)
    if reusable:
        report.notes.append(
            f"{len(reusable)} URL(s) were validated within the last {int(ttl)}s and "
            "were not re-probed (idempotent re-run; set URL_VALIDATE_TTL=0 to force)"
        )

    # Two measured ordering inputs, both read from what already exists on disk:
    # how many independent sources named each URL (the passive stage's own
    # per-source files) and what every previous measurement found per host (the
    # validation artifact).  Neither can change eligibility — only order.
    sources = source_counts(
        (item.url for item in parsed),
        passive_dir=passive_dir if passive_dir is not None else PASSIVE_OUTPUT_DIR,
    )
    states = host_states(previous.values())
    multi_source = sum(1 for count in sources.values() if count > 1)
    if multi_source:
        report.notes.append(
            f"priority: {multi_source} candidate(s) were named by more than one "
            "independent passive source and rank accordingly"
        )

    selection = select_candidates(
        parsed,
        scope=scope,
        policy=policy,
        known_fresh=reusable,
        max_urls=max_urls,
        max_per_host=max_per_host,
        dispatcher=dispatcher,
        sources=sources,
        host_state_map=states,
    )
    report.selection = selection.to_dict()

    probe_kwargs: dict[str, Any] = {
        "output_dir": output_dir,
        "session": session,
        "run": run,
    }
    if timeout is not None:
        probe_kwargs["timeout"] = timeout
    probe = probe_mod.probe([item.url for item in selection.selected], **probe_kwargs)
    report.probe = probe.to_dict()

    records = parse_httpx_jsonl(
        probe.stdout,
        requested=[item.url for item in selection.selected],
        validated_at=validated_at,
    )
    answered = {record.url for record in records}
    missing = [item.url for item in selection.selected if item.url not in answered]
    for url in missing:
        # A candidate the tool never reported is *unreachable*, not "alive": a
        # silent gap in a tool's output is not evidence of anything.
        records.append(
            ValidationRecord(
                url=url,
                state=STATE_UNREACHABLE,
                error="no response line from the validation tool",
                validated_at=validated_at,
                tool=probe_mod.NAME,
            )
        )

    kinds_by_url = {item.url: item.kind for item in parsed if item.kind}
    for record in records:
        kind = kinds_by_url.get(record.url, "")
        record.kinds = [kind] if kind else []

    merged = merge_validations(previous, records)
    write_jsonl(validation_path, [merged[url].to_dict() for url in sorted(merged)])

    by_state: dict[str, int] = {}
    for record in merged.values():
        by_state[record.state] = by_state.get(record.state, 0) + 1
    report.by_state = dict(sorted(by_state.items()))

    measured = [merged[url] for url in sorted(merged) if url in answered]
    report.counts = {
        "candidates": len(parsed),
        "selected": len(selection.selected),
        "already_validated": len(selection.already_validated),
        "out_of_scope": len(selection.out_of_scope),
        "refused": len(selection.refused),
        "capped": selection.capped,
        "probed": len(selection.selected),
        "measured": len(measured),
        "verified": sum(1 for record in measured if record.state == STATE_VERIFIED),
        "redirected": sum(1 for record in measured if record.state == STATE_REDIRECTED),
        "protected": sum(1 for record in measured if record.state == STATE_PROTECTED),
        "dead": sum(1 for record in measured if record.state == STATE_DEAD),
        "errored": sum(1 for record in measured if record.state == STATE_ERRORED),
        "unreachable": sum(
            1 for record in measured if record.state == STATE_UNREACHABLE
        ),
        "records": len(merged),
        "records_stale": sum(
            1
            for url, record in merged.items()
            if url not in answered and not record.is_fresh(now=clock, ttl=ttl)
        ),
        "multi_source_candidates": sum(1 for count in sources.values() if count > 1),
        "hosts_with_measurements": len(states),
        "per_host_limit": selection.per_host_limit,
        "capped_per_host": selection.capped_per_host,
    }
    if probe.error:
        report.ok = False
        report.notes.append(f"validation tool failed: {probe.error}")

    report.finished_at = _utc_now()
    report.seconds = time.monotonic() - started
    report.outputs = {
        "validations": validation_path.as_posix(),
        "report": str(_write_json(output_dir / REPORT_FILE, report)),
    }
    if probe.stdout_path is not None:
        report.outputs["raw"] = Path(probe.stdout_path).as_posix()

    log.info(
        "URL validation for %s: %d selected, %d measured (%d verified, %d redirected, "
        "%d dead, %d unreachable), %d record(s) on file",
        target,
        len(selection.selected),
        len(measured),
        report.counts["verified"],
        report.counts["redirected"],
        report.counts["dead"],
        report.counts["unreachable"],
        len(merged),
    )
    return report


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _write_json(path: Path, report: UrlValidationReport) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(report.to_json(), encoding="utf-8", newline="\n")
    tmp.replace(path)
    return path


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _timestamp(value: str) -> float:
    """Epoch seconds for an ISO-8601 timestamp; ``0`` when unparseable."""
    if not value:
        return 0.0
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def _int_list(value: object) -> list[int]:
    result: list[int] = []
    for item in _as_list(value):
        try:
            number = int(str(item))
        except (TypeError, ValueError):
            continue
        if number not in result:
            result.append(number)
    return result


def _as_list(value: object) -> list[Any]:
    if value in (None, "", [], {}):
        return []
    if isinstance(value, (list, tuple, set)):
        return [item for item in value if item not in (None, "")]
    return [value]


def _host_of(url: str) -> str:
    """The host a URL names, lowercased — ``""`` when it has none."""
    from urllib.parse import urlsplit

    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


__all__ = [
    "ALL_STATES",
    "ANSWERED_STATES",
    "CandidateSelection",
    "STATE_DEAD",
    "STATE_ERRORED",
    "STATE_PROTECTED",
    "STATE_REDIRECTED",
    "STATE_UNREACHABLE",
    "STATE_VERIFIED",
    "UrlValidationReport",
    "VALIDATIONS_FILE",
    "ValidationRecord",
    "KIND_RANK",
    "candidate_priority",
    "fresh_urls",
    "host_states",
    "per_host_limit",
    "source_counts",
    "load_validations",
    "merge_validations",
    "parse_httpx_jsonl",
    "run_validate_stage",
    "select_candidates",
    "state_for",
]
