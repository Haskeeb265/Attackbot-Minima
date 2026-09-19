"""S25 — the subdomain-takeover detector, policy-gated.

The raw material has existed since the names pipeline first ran: every CNAME a
target's own DNS carries is in ``records.jsonl``.  What was missing is the
detector — the thing that says which of those claims point at *unclaimed*
resources.

Three rules shape this module, all inherited:

* **One GET per claim, read-only** — verifying "is this actually unclaimed"
  requires exactly one request to the CNAME target (never an attempt to claim
  the resource).  The claimant is the target's own DNS; the probe target is the
  provider's host.  Nothing else is ever requested.
* **The policy gate is the safety rail** (plan §7.2): a takeover finding is a
  scoring signal only when the program's weakness metadata says takeover is in
  scope.  The gate reads :data:`~.settings.TAKEOVER_POLICY`; until S4 program
  ingestion exists that knob is the operator's hand, and the report says which
  way the gate was set — a silently-informational finding would be worse than
  an explicitly-informational one.
* **The fingerprint list is versioned data, not code.**  Providers patch
  takeover vectors; the list ships with a version and an ISO date so a finding
  can always say which edition of the fingerprints produced it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from service.recon_pipeline.platform.common.io import read_jsonl, write_jsonl

from . import settings
from .verify import FetchResult, http_get

#: The versioned fingerprint list.  ``markers`` are substrings that appear on
#: the provider's "unclaimed" page (and *only* there, as of the version date);
#: ``status`` is the HTTP status the unclaimed page answers with when it
#: matters.  A claim is ``takeover_vulnerable`` when the probe hits a marker;
#: ``claimed`` when the resource answers like it exists; ``inconclusive``
#: otherwise — an honest unknown, never a guess in either direction.
FINGERPRINT_VERSION = "2026-09-19.2"

FINGERPRINTS: tuple[dict[str, object], ...] = (
    {"suffix": "storage.googleapis.com", "markers": ["NoSuchBucket"], "status": 404},
    {"suffix": "blob.core.windows.net", "markers": ["BlobNotFound", "AccountNotFound"], "status": 404},
    {"suffix": "azureedge.net", "markers": ["The requested content does not exist."], "status": 404},
    {"suffix": "github.io", "markers": ["There isn't a GitHub Pages site here."], "status": 404},
    {"suffix": "herokuapp.com", "markers": ["No such app"], "status": 404},
    {"suffix": "zendesk.com", "markers": ["Help Center Closed"], "status": 404},
    {"suffix": "s3.amazonaws.com", "markers": ["NoSuchBucket"], "status": 404},
    {"suffix": "azurewebsites.net", "markers": ["404 Web Site not found."], "status": 404},
    {"suffix": "cloudapp.azure.com", "markers": ["404 Web Site not found."], "status": 404},
    {"suffix": "firebaseio.com", "markers": ["Firebase error", "set to false"], "status": 404},
    {"suffix": "netlify.app", "markers": ["Not Found - Request ID"], "status": 404},
    {"suffix": "vercel.app", "markers": ["DEPLOYMENT_NOT_FOUND"], "status": 404},
    {"suffix": "pages.dev", "markers": ["DEPLOYMENT_NOT_FOUND"], "status": 404},
    {"suffix": "bitbucket.io", "markers": ["Repository not found"], "status": 404},
    {"suffix": "myshopify.com", "markers": ["Sorry, this shop is currently unavailable"], "status": 404},
    {"suffix": "tumblr.com", "markers": ["Whatever you were looking for doesn't currently exist"], "status": 404},
    {"suffix": "teamwork.com", "markers": ["Oops - We didn't find your site."], "status": 404},
    {"suffix": "helpjuice.com", "markers": ["We could not find what you're looking for"], "status": 404},
    {"suffix": "helpscoutdocs.com", "markers": ["The page you're looking for doesn't exist"], "status": 404},
)

#: The fingerprint suffixes as a compiled matcher — one pass over a CNAME
#: target's suffixes, longest first so ``acme.s3.amazonaws.com`` matches the
#: S3 entry rather than nothing.
_SUFFIXES_BY_LENGTH = sorted(FINGERPRINTS, key=lambda entry: -len(str(entry["suffix"])))

STATE_VULNERABLE = "takeover_vulnerable"
STATE_CLAIMED = "claimed"
STATE_INCONCLUSIVE = "inconclusive"

#: The policy gate's two settings.  ``enforced`` is what a program with
#: takeover in its weakness metadata gets; ``informational`` records the
#: finding but applies no scoring signal — which is what an operator sees until
#: S4 ingestion can decide it automatically.
POLICY_INFORMATIONAL = "informational"
POLICY_ENFORCED = "enforced"


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def fingerprint_for(target: str) -> dict[str, object] | None:
    """The fingerprint entry a CNAME target matches, longest-suffix first."""
    host = target.strip().rstrip(".").lower()
    for entry in _SUFFIXES_BY_LENGTH:
        suffix = str(entry["suffix"])
        if host == suffix or host.endswith("." + suffix):
            return entry
    return None


def classify_probe(result: FetchResult, entry: dict[str, object]) -> str:
    """One probe's verdict: the marker decides, the status corroborates."""
    raw_markers = entry.get("markers", ())
    markers = [str(marker) for marker in raw_markers] if isinstance(raw_markers, (list, tuple)) else []
    raw_status = entry.get("status", 0)
    expected = int(raw_status) if isinstance(raw_status, (int, float, str)) else 0
    if not markers:
        return STATE_INCONCLUSIVE
    if result.status is None:
        # Transport failure is not knowledge in either direction.
        return STATE_INCONCLUSIVE
    if expected and result.status != expected:
        return STATE_CLAIMED
    if any(marker in result.text for marker in markers):
        return STATE_VULNERABLE
    return STATE_CLAIMED


@dataclass
class TakeoverFinding:
    """One CNAME claim, its probe, and the gate's decision about it."""

    claimant: str
    target: str
    provider_suffix: str
    state: str
    probe_url: str
    http_status: int | None = None
    code: str = ""
    #: What the gate did with the finding — ``scored`` or ``informational``.
    #: Every finding carries this; a report row without it invites the reader
    #: to assume the boost was applied.
    policy: str = POLICY_INFORMATIONAL
    origins: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    probed_at: str = ""

    @property
    def vulnerable(self) -> bool:
        return self.state == STATE_VULNERABLE

    def to_dict(self) -> dict[str, object]:
        return {
            "claimant": self.claimant,
            "target": self.target,
            "provider_suffix": self.provider_suffix,
            "state": self.state,
            "probe_url": self.probe_url,
            "http_status": self.http_status,
            **({"code": self.code} if self.code else {}),
            "policy": self.policy,
            "origins": self.origins,
            "sources": self.sources,
            "probed_at": self.probed_at,
        }


def claims_from_records(rows: list[dict]) -> list[tuple[str, str]]:
    """``(claimant, cname target)`` pairs from the names stage's records.

    The claimant is the target's own name; the claim is what that name points
    at.  Both must survive lowercasing; anything else is noise the names stage
    never meant to emit.
    """
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        claimant = str(row.get("host", "")).strip().rstrip(".").lower()
        for value in row.get("cname") or ():
            target = str(value).strip().rstrip(".").lower()
            if claimant and target and (claimant, target) not in seen:
                seen.add((claimant, target))
                pairs.append((claimant, target))
    return pairs


def probe_claim(
    claimant: str,
    target: str,
    *,
    fetcher=http_get,
    policy: str = POLICY_INFORMATIONAL,
) -> TakeoverFinding | None:
    """Probe one CNAME claim — the module's single network action per claim.

    ``None`` when the target matches no fingerprint: a claim we cannot classify
    is not a finding, and probing outside the fingerprint list would be
    requesting hosts no rule named.
    """
    entry = fingerprint_for(target)
    if entry is None:
        return None
    suffix = str(entry["suffix"])
    probe_url = f"https://{target}/"
    result = fetcher(probe_url)
    state = classify_probe(result, entry)
    now = _utc_now()
    return TakeoverFinding(
        claimant=claimant,
        target=target,
        provider_suffix=suffix,
        state=state,
        probe_url=probe_url,
        http_status=result.status,
        code=(result.error or (result.text[:60] if state == STATE_VULNERABLE else "")),
        policy=policy if state == STATE_VULNERABLE else "",
        origins=["cname"],
        sources=["records.jsonl"],
        probed_at=now,
    )


def run_takeover(
    records_rows: list[dict],
    *,
    fetcher=http_get,
    policy: str | None = None,
    output_dir: Path | None = None,
) -> tuple[list[TakeoverFinding], dict[str, int]]:
    """The detector over the whole records stream: classify every claim.

    Returns ``(findings, counts)``.  Only fingerprint-matched claims are
    probed; the counts say how many claims were never probed for that reason
    so the report shows the boundary of what the detector looked at.
    """
    policy = policy if policy is not None else settings.TAKEOVER_POLICY
    claims = claims_from_records(records_rows)
    findings: list[TakeoverFinding] = []
    counts = {
        "claims": len(claims),
        "fingerprint_matched": 0,
        "no_fingerprint": 0,
        STATE_VULNERABLE: 0,
        STATE_CLAIMED: 0,
        STATE_INCONCLUSIVE: 0,
        "scored": 0,
        "informational": 0,
    }
    for claimant, target in claims:
        finding = probe_claim(claimant, target, fetcher=fetcher, policy=policy)
        if finding is None:
            counts["no_fingerprint"] += 1
            continue
        counts["fingerprint_matched"] += 1
        counts[finding.state] = counts.get(finding.state, 0) + 1
        if finding.vulnerable:
            if finding.policy == POLICY_ENFORCED:
                counts["scored"] += 1
            else:
                counts["informational"] += 1
        findings.append(finding)
    findings.sort(key=lambda finding: (finding.claimant, finding.target))
    if output_dir is not None:
        write_jsonl(Path(output_dir) / "takeover.jsonl", [f.to_dict() for f in findings])
    return findings, counts
