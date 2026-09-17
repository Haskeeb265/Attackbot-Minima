"""Recognising a block: WAF fingerprints, challenge pages and ``Retry-After``.

The recon itself does not change when a target pushes back — but the *response*
to it must.  A 403 that is actually a bot challenge means every further request
to that host is wasted work, inflates the DNS/HTTP footprint we are trying to
keep small, and is the exact behaviour that gets an engagement noticed.  So this
module turns a response into a verdict the runner can act on:

* ``ok`` — a normal answer (including honest 404s and 401s, which are findings);
* ``rate_limited`` — 429, honour ``Retry-After`` and slow down;
* ``challenge`` — a JS/CAPTCHA interstitial (Cloudflare's "Just a moment",
  Akamai's reference-number page, Imperva's ``_Incapsula_Resource``, DataDome,
  PerimeterX, Vercel's checkpoint, ...);
* ``blocked`` — an outright WAF denial;
* ``server_error`` / ``network_error`` — retryable transport failures.

Two deliberate biases:

1. **A block must be evidenced.**  Detection requires either a status code that
   is itself the evidence (429/403/503) *plus* a WAF or challenge marker, or a
   challenge-specific marker that normal pages simply do not contain
   (``__cf_chl``, ``_Incapsula_Resource``, "Pardon Our Interruption").  Generic
   words like "captcha" appear on ordinary login pages, so they only ever
   downgrade confidence — they never quarantine anything on their own.
2. **A 200 is not automatically fine.**  Anti-bot interstitials are increasingly
   served with 200, so a strong marker on a 200 is still reported (with lower
   confidence) rather than silently treated as content.

Every marker is data, not code, so a new WAF signature is a one-line addition
and the tests can feed real captured pages through :func:`classify`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

OK = "ok"
RATE_LIMITED = "rate_limited"
CHALLENGE = "challenge"
BLOCKED = "blocked"
SERVER_ERROR = "server_error"
NETWORK_ERROR = "network_error"

#: Verdict kinds that should stop us talking to a scope for a while.
QUARANTINE_KINDS = frozenset({CHALLENGE, BLOCKED})

#: Verdict kinds that should slow us down (and be retried).
BACKOFF_KINDS = frozenset({RATE_LIMITED, CHALLENGE, SERVER_ERROR, NETWORK_ERROR})

#: Confidence at which a challenge verdict is trusted enough to quarantine.
QUARANTINE_CONFIDENCE = 0.6


# --------------------------------------------------------------------------- #
# Signatures
# --------------------------------------------------------------------------- #

#: ``(waf name, header name, substring in the header value or "" for presence)``
WAF_HEADERS: tuple[tuple[str, str, str], ...] = (
    ("cloudflare", "cf-ray", ""),
    ("cloudflare", "cf-mitigated", ""),
    ("cloudflare", "server", "cloudflare"),
    ("akamai", "akamai-grn", ""),
    ("akamai", "x-akamai-request-id", ""),
    ("akamai", "x-akamai-transformed", ""),
    ("akamai", "server", "akamaighost"),
    ("imperva", "x-iinfo", ""),
    ("imperva", "x-cdn", "incapsula"),
    ("datadome", "x-datadome", ""),
    ("datadome", "set-cookie", "datadome"),
    ("perimeterx", "x-px", ""),
    ("perimeterx", "set-cookie", "_px"),
    ("sucuri", "x-sucuri-id", ""),
    ("sucuri", "server", "sucuri"),
    ("fastly", "x-fastly-request-id", ""),
    ("fastly", "via", "fastly"),
    ("cloudfront", "x-amz-cf-id", ""),
    ("cloudfront", "via", "cloudfront"),
    ("aws", "x-amzn-requestid", ""),
    ("azure-front-door", "x-azure-ref", ""),
    ("f5", "server", "big-ip"),
    ("f5", "set-cookie", "bigipserver"),
    ("netscaler", "server", "netscaler"),
    ("netscaler", "set-cookie", "nsc_"),
    ("barracuda", "set-cookie", "barra_counter_session"),
    ("fortiweb", "set-cookie", "fortiwafsid"),
    ("qrator", "server", "qrator"),
    ("varnish", "x-varnish", ""),
    ("vercel", "x-vercel-id", ""),
    ("envoy", "server", "envoy"),
)

#: Challenge-specific page markers.  These do not appear on ordinary pages, so
#: finding one is enough evidence to classify the response as a challenge even
#: on a 200 (``strong`` markers only).
STRONG_CHALLENGE_MARKERS: tuple[tuple[str, str], ...] = (
    ("cloudflare", "__cf_chl"),
    ("cloudflare", "cf-chl-"),
    ("cloudflare", "cdn-cgi/challenge-platform"),
    ("cloudflare", "just a moment"),
    ("cloudflare", "checking your browser before accessing"),
    ("cloudflare", "enable javascript and cookies to continue"),
    ("cloudflare", "error 1020"),
    ("akamai", "akamai bot manager"),
    ("imperva", "_incapsula_resource"),
    ("imperva", "incapsula incident id"),
    ("imperva", "request unsuccessful. incapsula"),
    ("datadome", "dd_cookie_test"),
    ("datadome", "please enable js and disable any ad blocker"),
    ("perimeterx", "px-captcha"),
    ("perimeterx", "please verify you are a human"),
    ("radware", "shieldsquare"),
    ("vercel", "vercel security checkpoint"),
    ("aws", "aws-waf-token"),
    ("sucuri", "sucuri website firewall - access denied"),
    ("f5", "the requested url was rejected"),
)

#: Words that show up on perfectly normal pages (login forms, marketing copy).
#: They only ever *lower* confidence — they can never quarantine a scope alone.
WEAK_CHALLENGE_MARKERS: tuple[str, ...] = (
    "captcha",
    "recaptcha",
    "hcaptcha",
    "unusual traffic",
    "verify you are human",
    "access denied",
    "request blocked",
    "attention required",
    "are you a robot",
)

#: Challenge pages are tiny; a real page with the same words is not.
CHALLENGE_MAX_BODY_BYTES = 24_000


@dataclass(frozen=True)
class Verdict:
    """What a response actually was, and how sure we are."""

    kind: str
    status: int | None = None
    waf: str | None = None
    confidence: float = 0.0
    evidence: tuple[str, ...] = field(default=())
    retry_after: float | None = None

    @property
    def is_ok(self) -> bool:
        return self.kind == OK

    @property
    def is_block(self) -> bool:
        return self.kind in QUARANTINE_KINDS

    @property
    def should_backoff(self) -> bool:
        return self.kind in BACKOFF_KINDS

    @property
    def should_quarantine(self) -> bool:
        return self.is_block and self.confidence >= QUARANTINE_CONFIDENCE

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "kind": self.kind,
            "status": self.status,
            "confidence": round(self.confidence, 2),
        }
        if self.waf:
            payload["waf"] = self.waf
        if self.evidence:
            payload["evidence"] = list(self.evidence)
        if self.retry_after is not None:
            payload["retry_after"] = round(self.retry_after, 2)
        return payload


def parse_retry_after(value: str | None, *, now: datetime | None = None) -> float | None:
    """Seconds to wait, from either form RFC 9110 allows.

    ``Retry-After`` is either a delay in seconds or an HTTP-date.  Ignoring the
    date form means hammering a host that explicitly asked us to wait, which is
    the surest way to turn a soft rate limit into a hard block.
    """
    if not value:
        return None
    raw = value.strip()
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    delta = (when - (now or datetime.now(timezone.utc))).total_seconds()
    return max(0.0, delta)


def fingerprint_waf(headers: dict[str, str]) -> tuple[str | None, tuple[str, ...]]:
    """Which WAF/CDN the response headers belong to, if any."""
    lowered = {str(name).lower(): str(value).lower() for name, value in headers.items()}
    hits: list[str] = []
    found: str | None = None
    for waf, header, needle in WAF_HEADERS:
        value = lowered.get(header)
        if value is None:
            continue
        if needle and needle not in value:
            continue
        found = found or waf
        hits.append(f"header:{header}" + (f"~{needle}" if needle else ""))
    return found, tuple(hits)


def challenge_markers(body: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return ``(strong, weak)`` marker hits from a response body."""
    if not body:
        return (), ()
    text = body.lower()
    strong: list[str] = []
    weak: list[str] = []
    for waf, marker in STRONG_CHALLENGE_MARKERS:
        if marker in text:
            strong.append(f"{waf}:{marker}")
    for marker in WEAK_CHALLENGE_MARKERS:
        if marker in text:
            weak.append(f"weak:{marker}")
    return tuple(strong), tuple(weak)


def classify(
    *,
    status: int | None,
    headers: dict[str, str] | None = None,
    body: str = "",
    error: str | None = None,
) -> Verdict:
    """Classify one response into a :class:`Verdict`.

    Precedence is deliberate: a transport failure beats everything, an explicit
    rate limit beats a WAF guess, and a challenge beats a bare denial.
    """
    if error:
        return Verdict(NETWORK_ERROR, status=status, confidence=0.9, evidence=(f"error:{error[:80]}",))

    headers = headers or {}
    waf, header_evidence = fingerprint_waf(headers)
    strong, weak = challenge_markers(body)
    small_body = len(body) <= CHALLENGE_MAX_BODY_BYTES
    retry_after = parse_retry_after(headers.get("retry-after") or headers.get("Retry-After"))

    evidence = list(header_evidence)
    evidence += [f"strong:{marker}" for marker in strong]
    evidence += [f"weak:{marker}" for marker in weak]
    if retry_after is not None:
        evidence.append(f"retry-after:{retry_after:g}s")
    strong_evidence = tuple(strong) + tuple(header_evidence)

    # 429 is the host telling us, in the protocol, to slow down.  Nothing is
    # ambiguous about it, so it wins over every marker-based guess.
    if status == 429:
        return Verdict(
            RATE_LIMITED,
            status=status,
            waf=waf,
            confidence=0.95,
            evidence=tuple(evidence[:6]),
            retry_after=retry_after,
        )

    # A denial *plus* a challenge or WAF signature: an interstitial, not content.
    # Challenge evidence outranks the status code, because the same interstitial
    # is served as 403, 503 and (increasingly) 200 depending on the vendor.
    if strong and small_body:
        return Verdict(
            CHALLENGE,
            status=status,
            waf=waf or strong[0].split(":", 1)[0],
            confidence=0.9 if status in {401, 403, 429, 503} else 0.7,
            evidence=tuple(evidence[:6]),
            retry_after=retry_after,
        )

    if status in {401, 403}:
        if waf:
            return Verdict(
                BLOCKED,
                status=status,
                waf=waf,
                confidence=0.7,
                evidence=tuple(evidence[:6]),
                retry_after=retry_after,
            )
        if status == 403 and weak:
            return Verdict(
                BLOCKED,
                status=status,
                waf=waf,
                confidence=0.5,
                evidence=tuple(evidence[:6]),
                retry_after=retry_after,
            )
        # A bare 403/401 with nothing behind it is a normal (if unfriendly)
        # answer: report it, do not quarantine the host for it.
        return Verdict(OK, status=status, waf=waf, confidence=0.6, evidence=tuple(evidence[:6]))

    # A 5xx that carried no challenge evidence is a server fault, not a block —
    # retry it, but do not treat the host as hostile.
    if status is not None and status >= 500:
        return Verdict(
            SERVER_ERROR,
            status=status,
            waf=waf,
            confidence=0.6,
            evidence=tuple(evidence[:6]),
            retry_after=retry_after,
        )

    if weak:
        # Ordinary page that merely mentions captcha/verification.
        return Verdict(OK, status=status, waf=waf, confidence=0.5, evidence=tuple(evidence[:6]))

    return Verdict(OK, status=status, waf=waf, confidence=0.9, evidence=strong_evidence[:6])
