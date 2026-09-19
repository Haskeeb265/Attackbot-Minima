"""The active probe: one GET per (name, provider), verdict by matrix.

Every probe touches a **provider** endpoint (``acme.s3.amazonaws.com``), never
the target's own infrastructure — the reason the manifest keeps
``passive_only=True`` (the same reading ``asn_cidr`` makes for RIPEstat/RDAP).

The matrices below are the pipeline's entire classification logic (DESIGN.md
§3, verified against provider documentation and live behaviour during R&D).
The one rule that keeps the report honest — the lesson
``url_endpoint/passive/errors.py`` learned from Common Crawl — is enforced
here: **"no such bucket" and "no answer" stay apart.**  A provider 404 is a
usable fact; a refused connection, a 5xx or a rate limit reports
``unavailable`` and counts as a source failure, never a false "absent".
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

import requests

from . import providers, settings
from .normalize import Candidate

log = logging.getLogger("cloud_resource.verify")

#: Verdict states, in the vocabulary the report and artifacts use.
STATE_OPEN = "open"
STATE_AUTH = "auth_required"
STATE_DANGLING = "dangling"
STATE_ABSENT = "absent"
STATE_EXISTS_OTHER_REGION = "exists_other_region"
STATE_UNAVAILABLE = "unavailable"

#: States that mean the name exists (the curated ``buckets.jsonl`` set).
EXISTING_STATES = frozenset({STATE_OPEN, STATE_AUTH, STATE_EXISTS_OTHER_REGION})

#: The evidence classes a verdict can carry: *why* we believe it.
EVIDENCE_CNAME_CLAIMED = "cname-claimed"
EVIDENCE_OBSERVED = "artifact-observed"
EVIDENCE_DERIVED = "derived"
EVIDENCE_DERIVED_GENERIC = "derived-generic"
EVIDENCE_EXPLICIT = "explicit"

#: A fetcher — injectable so tests never touch the network (the same seam
#: ``asn_cidr/sources.py`` uses).  Production passes :func:`http_get`.
Fetcher = Callable[..., "FetchResult"]


@dataclass(frozen=True)
class FetchResult:
    """The outcome of one GET, with the three transport states kept apart."""

    status: int | None
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    @property
    def failed(self) -> bool:
        return self.status is None


def http_get(url: str, *, timeout: float | None = None, retries: int | None = None) -> FetchResult:
    """GET *url*, returning a :class:`FetchResult` — never raising."""
    timeout = settings.HTTP_TIMEOUT if timeout is None else timeout
    retries = settings.HTTP_RETRIES if retries is None else retries
    headers = {
        "User-Agent": "attackbot-recon-cloud-resource/1.0 (+asset-pipeline)",
        "Accept": "*/*",
    }
    last_error = "unknown error"
    for attempt in range(1, max(1, retries) + 1):
        try:
            response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=False)
            if response.status_code in {429, 500, 502, 503, 504} and attempt < max(1, retries):
                last_error = f"HTTP {response.status_code}"
            else:
                return FetchResult(
                    status=response.status_code,
                    text=response.text[:4096],
                    headers=dict(response.headers),
                )
        except requests.RequestException as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        if attempt < max(1, retries):
            log.warning("%s attempt %d/%d failed (%s)", url, attempt, retries, last_error)
            time.sleep(0.5 * attempt)
    return FetchResult(status=None, error=last_error)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _is_resolution_failure(error: str) -> bool:
    """True when the transport error is a DNS resolution failure."""
    lowered = (error or "").lower()
    return "nameresolutionerror" in lowered or "getaddrinfo failed" in lowered or "name or service not known" in lowered


# --------------------------------------------------------------------------- #
# Body-code extraction (Azure keys on the body <Code>, GCS on either dialect)
# --------------------------------------------------------------------------- #

_XML_CODE_RE = re.compile(r"<Code>([^<]+)</Code>", re.IGNORECASE)
_JSON_ERROR_RE = re.compile(r'"(?:code|error)"\s*:\s*"([^"]+)"', re.IGNORECASE)
_JSON_REASON_RE = re.compile(r'"reason"\s*:\s*"([^"]+)"', re.IGNORECASE)
_LISTBUCKET_RE = re.compile(r"<ListBucketResult", re.IGNORECASE)


def body_code(text: str) -> str:
    """The provider error code from an XML ``<Code>``, a JSON ``"code"``, or a
    GCS JSON ``reason`` — the three error dialects the probes actually see."""
    match = _XML_CODE_RE.search(text)
    if match:
        return match.group(1).strip().lower()
    match = _JSON_ERROR_RE.search(text)
    if match:
        return match.group(1).strip().lower()
    match = _JSON_REASON_RE.search(text)
    if match:
        return match.group(1).strip().lower()
    return ""


# --------------------------------------------------------------------------- #
# The verdict matrices (DESIGN.md §3)
# --------------------------------------------------------------------------- #

#: S3 body codes that mean the name exists but lives elsewhere.  Both come with
#: a region hint (the ``Location`` header / ``<Region>`` element); P1 records
#: the fact and does not chase regions (one 301 kept, no 30-request retry loop).
_S3_EXISTS_ELSEWHERE = frozenset({"authorizationheadermalformed"})
_S3_ABSENT_CODES = frozenset({"nosuchbucket"})
_S3_REFUSED_CODES = frozenset({"slowdown", "internalerror", "requesttimeout"})

#: Azure codes.  The quirk the matrix exists for: a storage account that does
#: not exist answers **409 AccountNotFound**, while an existing account's
#: missing container answers 404.  Some existence classes answer 400.
_AZURE_AUTH_CODES = frozenset({"publicaccessnotpermitted", "authorizationfailure", "nodeniedinformation"})
_AZURE_ABSENT_CODES = frozenset({
    "accountnotfound",
    "containernotfound",
    "blobnotfound",
    "missingrequiredheader",
    "invalidqueryparametervalue",
    "invalidresourcename",
})
_AZURE_REFUSED_CODES = frozenset({"serverbusy", "internalerror", "operationtimedout"})

#: Azure has no wildcard DNS: a storage account that does not exist does not
#: resolve *at all*, while S3/GCS wildcard DNS answer HTTP 404 on the same
#: name.  So a transport-level resolution failure on an Azure probe is an
#: absence fact, not a source failure — but only when a sibling S3/GCS probe
#: answered (which proves the network was up).  Encoded after the first live
#: run measured it (DESIGN.md §9).
STATE_NXDOMAIN_ABSENT = "nxdomain_absent"

#: GCS codes (XML dialect: ``NoSuchBucket``; JSON dialect: ``notFound``).
_GCS_AUTH_CODES = frozenset({"denied", "unauthorized", "acces denied", "accessdenied"})
_GCS_ABSENT_CODES = frozenset({"nosuchbucket", "notfound"})
_GCS_INVALID_CODES = frozenset({"invalidargument", "invalidbucketname"})


def classify(provider: str, result: FetchResult, *, corroborated: bool = False) -> tuple[str, str]:
    """``(state, code)`` for one probe answer, by the provider's matrix.

    ``corroborated`` means a sibling provider's probe answered this run (the
    network was up).  It matters for exactly one case: an Azure probe that
    fails to *resolve* is an absence fact (Azure has no wildcard DNS), not a
    failure — but only when the network is provably up, otherwise it is the
    honest ``unavailable``.

    ``code`` is the provider error code (or ``Location``/``Region`` hint for
    the S3 exists-elsewhere verdict) — kept in the artifact so a verdict is
    always auditable against the raw answer.
    """
    code = body_code(result.text)
    status = result.status

    if result.failed or status is None:
        if (
            provider == providers.PROVIDER_AZURE
            and corroborated
            and _is_resolution_failure(result.error)
        ):
            return STATE_NXDOMAIN_ABSENT, (result.error or "nxdomain")
        return STATE_UNAVAILABLE, result.error or "no answer"

    if status == 200:
        return STATE_OPEN, ("listable" if _LISTBUCKET_RE.search(result.text) else "")

    headers = {str(key).lower(): str(value) for key, value in result.headers.items()}

    if provider == providers.PROVIDER_S3:
        if status == 301:
            hint = headers.get("location", "") or headers.get("x-amz-bucket-region", "")
            return STATE_EXISTS_OTHER_REGION, (hint or code or "301")
        if status == 400 and code in _S3_EXISTS_ELSEWHERE:
            region = ""
            match = re.search(r"<Region>([^<]+)</Region>", result.text, re.IGNORECASE)
            if match:
                region = match.group(1)
            return STATE_EXISTS_OTHER_REGION, (region or code)
        if status == 403:
            return STATE_AUTH, code
        if status == 404 and (code in _S3_ABSENT_CODES or not code):
            return STATE_DANGLING, (code or "404")
        if code in _S3_REFUSED_CODES:
            return STATE_UNAVAILABLE, code

    elif provider == providers.PROVIDER_AZURE:
        if status == 200:
            return STATE_OPEN, code
        if code in _AZURE_AUTH_CODES:
            return STATE_AUTH, code
        if code in _AZURE_ABSENT_CODES:
            return STATE_DANGLING, code
        if code in _AZURE_REFUSED_CODES:
            return STATE_UNAVAILABLE, code
        if status == 403:
            return STATE_AUTH, code
        if status in (404, 400, 409):
            return STATE_DANGLING, (code or f"HTTP {status}")

    elif provider == providers.PROVIDER_GCS:
        if status == 403 or code in _GCS_AUTH_CODES:
            return STATE_AUTH, code
        if code in _GCS_INVALID_CODES:
            return STATE_ABSENT, code
        if status == 404 and (code in _GCS_ABSENT_CODES or not code):
            return STATE_DANGLING, (code or "404")
        if code in ("internalerror", "backenderror", "ratelimitexceeded"):
            return STATE_UNAVAILABLE, code

    # Anything the matrices did not name: an honest unknown, not a guess.
    return STATE_UNAVAILABLE, (code or f"unclassified HTTP {status}")


@dataclass
class Verdict:
    """One probe's outcome, with its provenance and evidence class."""

    name: str
    provider: str
    state: str
    code: str
    probe_url: str
    evidence_class: str
    origins: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    #: The target hosts whose DNS claimed this resource (CNAME-origin only).
    claimants: list[str] = field(default_factory=list)
    http_status: int | None = None
    probed_at: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "provider": self.provider,
            "state": self.state,
            "code": self.code,
            "http_status": self.http_status,
            "probe_url": self.probe_url,
            "evidence_class": self.evidence_class,
            "origins": self.origins,
            "sources": self.sources,
            **({"claimants": self.claimants} if self.claimants else {}),
            "probed_at": self.probed_at,
        }


def evidence_class_for(candidate: Candidate) -> str:
    """Why this candidate is worth probing: a CNAME claim outranks observation,
    which outranks an operator's guess, which outranks derivation.  A derived
    name built only from generic tokens (``mail-app``) is the weakest class —
    provider names are globally namespaced, so it may belong to anyone (the
    live-run lesson: two ``mail-*`` GCS buckets answered 200, none of them the
    target's)."""
    if "cname" in candidate.origins:
        return EVIDENCE_CNAME_CLAIMED
    if candidate.origins & {"url", "javascript", "endpoint"}:
        return EVIDENCE_OBSERVED
    if "explicit" in candidate.origins:
        return EVIDENCE_EXPLICIT
    return EVIDENCE_DERIVED if candidate.distinctive else EVIDENCE_DERIVED_GENERIC


def probe_candidates(
    candidates: list[Candidate],
    *,
    fetcher: Fetcher | None = None,
    timeout: float | None = None,
    max_probes: int | None = None,
) -> tuple[list[Verdict], dict[str, int]]:
    """One GET per candidate (enabled providers only), classified by matrix.

    Returns ``(verdicts, counts)``.  The probe cap is first-come over the
    sorted candidate list; the report carries the truncation.
    """
    fetcher = fetcher or http_get
    max_probes = settings.MAX_PROBES if max_probes is None else max_probes

    enabled: dict[str, providers.Provider] = {}
    if settings.S3_ENABLED:
        enabled[providers.PROVIDER_S3] = providers.PROVIDERS[providers.PROVIDER_S3]
    if settings.AZURE_ENABLED:
        enabled[providers.PROVIDER_AZURE] = providers.PROVIDERS[providers.PROVIDER_AZURE]
    if settings.GCS_ENABLED:
        enabled[providers.PROVIDER_GCS] = providers.PROVIDERS[providers.PROVIDER_GCS]

    counts = {
        "probed": 0,
        "skipped_provider_disabled": 0,
        "truncated": 0,
        STATE_OPEN: 0,
        STATE_AUTH: 0,
        STATE_DANGLING: 0,
        STATE_ABSENT: 0,
        STATE_EXISTS_OTHER_REGION: 0,
        STATE_UNAVAILABLE: 0,
        STATE_NXDOMAIN_ABSENT: 0,
    }

    # Two phases, because the Azure NXDOMAIN rule needs to know whether a
    # sibling S3/GCS probe *answered anywhere in this run* — a fact only known
    # once every probe has fired (candidates are sorted by (provider, name),
    # so Azure's come before S3's).  Phase 1 probes and records; phase 2
    # classifies with full knowledge.  Classification is pure, so this is
    # deterministic: the same answers always produce the same verdicts.
    probed: list[tuple[Candidate, providers.Provider, str, FetchResult]] = []
    for candidate in candidates:
        spec = enabled.get(candidate.provider)
        if spec is None:
            counts["skipped_provider_disabled"] += 1
            continue
        if max_probes and counts["probed"] >= max_probes:
            counts["truncated"] += 1
            continue
        url = spec.probe_url(candidate.name)
        result = fetcher(url, timeout=timeout) if timeout else fetcher(url)
        counts["probed"] += 1
        probed.append((candidate, spec, url, result))
        log.debug("%s -> %s", url, result.status or result.error)

    corroborated = any(
        candidate.provider != providers.PROVIDER_AZURE and not result.failed
        for candidate, _, _, result in probed
    )

    verdicts: list[Verdict] = []
    for candidate, spec, url, result in probed:
        state, code = classify(
            candidate.provider, result, corroborated=corroborated
        )
        counts[state] = counts.get(state, 0) + 1
        verdicts.append(
            Verdict(
                name=candidate.name,
                provider=candidate.provider,
                state=state,
                code=code,
                probe_url=url,
                evidence_class=evidence_class_for(candidate),
                origins=sorted(candidate.origins),
                sources=sorted(candidate.sources),
                claimants=sorted(candidate.claimants),
                http_status=result.status,
                probed_at=_utc_now(),
            )
        )
    return verdicts, counts
