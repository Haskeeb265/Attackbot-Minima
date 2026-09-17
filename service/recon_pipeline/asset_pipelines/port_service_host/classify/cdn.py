"""Decide what *kind* of address an IP is, before a single packet is sent at it.

This is the module that makes the stage safe.  Port-scanning a CDN edge node is
three mistakes at once: the results are meaningless (the edge answers, not the
origin), the traffic is noise on shared infrastructure that is not the target's,
and it is the fastest way to get the whole engagement noticed.  The ASM spec
agrees from the other direction — a pure-CDN address is a strongly *negative*
correction in scoring, because there is nothing of the target's to attack behind
it.

So every address gets exactly one verdict:

``cdn``
    Shared edge infrastructure (Cloudflare, Akamai, Fastly, CloudFront, Sucuri,
    ...).  Never port-scanned; at most an HTTP probe on 80/443, because that is
    what actually explains the site behind it.

``dedicated``
    No CDN signal, and the address is one our target's own names resolve to.
    This is the address class the scan ladder exists to spend budget on.

``unknown``
    Nothing to go on — no CDN signal, and no positive evidence tying it to the
    target.  Reported as such, and allowed to reach the top-N scan only when
    something else (passive intel, declared scope) justifies it.

The verdict always carries the evidence that produced it, because a bare label
is unauditable: "cdn (high)" is a claim, "cdn (high): PTR a1.edge.cloudflare.net
matches Cloudflare edge naming" is a fact someone can check.

Detection is deliberately layering-independent: naming and registry signals fire
without any network access at all, and the bundled range snapshot (see
``data/cdn_ranges.txt``) only ever *adds* confidence.  A stale range file can
therefore cause a missed classification, never a false one that scans a CDN.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from ..normalize import canonicalize_ip, read_text
from ..settings import CDN_RANGES_FILE

log = logging.getLogger("psh.classify.cdn")

VERDICT_CDN = "cdn"
VERDICT_HOSTED = "hosted"
VERDICT_DEDICATED = "dedicated"
VERDICT_UNKNOWN = "unknown"

#: CNAME suffixes that mean *the target's own name is served by a third party's
#: application platform* — shared tenant infrastructure (Microsoft 365, Heroku,
#: App Engine, ...), not the target's own server.  Measured motivation
#: (``qbsco.net``, 2026-09-17): ``autodiscover -> autodiscover.outlook.com`` put
#: 16 Microsoft addresses on the scan set, found port 80 on three of them, and
#: every finding was spent on Microsoft's fleet — including a 13-minute full-range
#: escalation that re-found nothing.  The CNAME chain naming the platform sat in
#: ``records.jsonl`` before the scan started; only the verdict to act on it was
#: missing.
#:
#: Deliberately a *naming* list, like the CDN suffix tables, and deliberately
#: narrow: a suffix goes here only when everything behind it is tenant-hosted
#: application infrastructure.  A hosting *provider* is not enough (Linode hosts
#: scanme.nmap.org; that address is still the target's own server) — the chain
#: must name the platform the service runs on.
HOSTED_SUFFIXES: tuple[str, ...] = (
    # Microsoft 365 / Exchange Online (autodiscover, mail, tenant endpoints).
    "outlook.com",
    "office.com",
    "office365.com",
    "sharepoint.com",
    "onmicrosoft.com",
    # Cloud application platforms: one tenant's app, third-party runtimes.
    "herokuapp.com",
    "azurewebsites.net",
    "elasticbeanstalk.com",
    "appspot.com",
    "web.app",
    "firebaseapp.com",
    "amazonaws.com",
    "pages.dev",
    "vercel.app",
    "netlify.app",
    "github.io",
)

CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"

#: Friendly name for a hosted platform, by the suffix that identified it.
_HOSTED_LABELS = {
    "outlook.com": "Microsoft 365",
    "office.com": "Microsoft 365",
    "office365.com": "Microsoft 365",
    "sharepoint.com": "Microsoft 365",
    "onmicrosoft.com": "Microsoft 365",
    "herokuapp.com": "Heroku",
    "azurewebsites.net": "Azure App Service",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "appspot.com": "Google App Engine",
    "web.app": "Google Firebase",
    "firebaseapp.com": "Google Firebase",
    "amazonaws.com": "AWS",
    "pages.dev": "Cloudflare Pages",
    "vercel.app": "Vercel",
    "netlify.app": "Netlify",
    "github.io": "GitHub Pages",
}

#: How a provider is recognised when only its *name* is visible.
_PROVIDER_LABELS = {
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "cloudfront": "Amazon CloudFront",
    "sucuri": "Sucuri",
    "imperva": "Imperva/Incapsula",
    "stackpath": "StackPath",
    "edgio": "Edgio/Limelight",
    "cdn77": "CDN77",
    "bunny": "Bunny",
    "gcore": "Gcore",
    "keycdn": "KeyCDN",
    "azure": "Azure Front Door",
    "google": "Google Cloud CDN",
}


#: Passive-intel tags that mean "this address is shared edge infrastructure".
#:
#: **``cloud`` is deliberately absent.**  Shodan tags a plain VPS "cloud" —
#: ``scanme.nmap.org`` on a Linode instance is the measured example — and treating
#: that as a CDN would silently *exclude a real host from being scanned* and label
#: it as somebody else's infrastructure.  The cost of the two errors is not
#: symmetric, so the tag set is kept to tags that are about to break, not to host.
#:
#: These tags are also never attributed to a *named* provider: "this is a CDN" and
#: "this is Cloudflare" are different claims, and only naming evidence supports the
#: second one.
EDGE_TAGS = frozenset({"cdn", "waf"})

#: Providers whose *entire* network is edge infrastructure, so an ownership
#: match alone is enough to call an address edge.
#:
#: Akamai, Microsoft/Azure and Google are deliberately absent: each of them sells
#: cloud or hosting products whose addresses are not their CDN, and a name match
#: cannot tell the two apart.  Their genuine edge addresses are still detected,
#: and detected better, by the naming signals a real edge always exhibits (a CNAME
#: into ``*.edgekey.net``/``*.akamaiedge.net``, or the provider's own PTR naming).
EDGE_NETWORKS = frozenset(
    {
        "cloudflare",
        "fastly",
        "cloudfront",
        "sucuri",
        "imperva",
        "stackpath",
        "edgio",
        "cdn77",
        "bunny",
        "gcore",
        "keycdn",
    }
)


@dataclass(frozen=True)
class Provider:
    """Everything that identifies one CDN/WAF provider.

    Note what is *not* here: a tag list.  An earlier revision gave every provider
    the same ``("cdn", "cloud", "waf")`` tags, which meant one generic tag could
    name a specific provider — the measured result was a Linode VPS reported as
    Cloudflare.  Generic tags are handled once, provider-less, by :data:`EDGE_TAGS`.
    """

    key: str
    #: Reverse-DNS suffixes used by the provider's edge nodes.
    ptr_suffixes: tuple[str, ...] = ()
    #: Substrings of the RDAP/RIR organisation name that identify the provider.
    org_patterns: tuple[str, ...] = ()
    #: Response-header names/markers that identify the edge (post-probe use).
    header_markers: tuple[str, ...] = ()

    @property
    def label(self) -> str:
        return _PROVIDER_LABELS.get(self.key, self.key)


#: The provider table.  Suffix matching is on whole labels, so
#: ``notcloudflare.net`` can never match ``cloudflare.net``.
PROVIDERS: tuple[Provider, ...] = (
    Provider(
        key="cloudflare",
        ptr_suffixes=("cloudflare.net", "cloudflare.com", "cdn.cloudflare.net"),
        org_patterns=("cloudflare",),
        header_markers=("cf-ray", "cf-cache-status", "server: cloudflare"),
    ),
    Provider(
        key="akamai",
        ptr_suffixes=(
            "akamai.net",
            "akamaiedge.net",
            "akamaitechnologies.com",
            "akamaiedge-staging.net",
            "edgekey.net",
            "edgesuite.net",
            "akamaihd.net",
        ),
        org_patterns=("akamai",),
        header_markers=("x-akamai-", "akamai-grn", "server: akamaighost"),
    ),
    Provider(
        key="fastly",
        ptr_suffixes=("fastly.net", "fastlylb.net", "fastly.com"),
        org_patterns=("fastly",),
        header_markers=("x-served-by", "x-cache", "x-fastly-"),
    ),
    Provider(
        key="cloudfront",
        ptr_suffixes=("cloudfront.net",),
        org_patterns=("amazon cloudfront", "cloudfront"),
        # ``Via: 1.1`` is deliberately NOT a marker: every caching proxy on the
        # internet emits it, so it would classify unrelated hosts as CloudFront.
        header_markers=("x-amz-cf-id", "x-amz-cf-pop", "server: cloudfront"),
    ),
    Provider(
        key="sucuri",
        ptr_suffixes=("sucuri.net", "cloudproxy.net"),
        org_patterns=("sucuri",),
        header_markers=("x-sucuri-id", "x-sucuri-cache", "server: sucuri"),
    ),
    Provider(
        key="imperva",
        ptr_suffixes=("incapdns.net", "impervadns.net", "incapsula.com"),
        org_patterns=("incapsula", "imperva"),
        header_markers=("x-iinfo", "x-cdn: incapsula"),
    ),
    Provider(
        key="stackpath",
        ptr_suffixes=("hwcdn.net", "stackpathdns.com", "stackpath.com"),
        org_patterns=("stackpath", "highwinds"),
        header_markers=("x-hw",),
    ),
    Provider(
        key="edgio",
        ptr_suffixes=("llnwd.net", "edgio.net", "edg.io"),
        org_patterns=("edgio", "limelight"),
    ),
    Provider(
        key="cdn77",
        ptr_suffixes=("cdn77.org", "cdn77.com"),
        org_patterns=("cdn77",),
        header_markers=("server: cdn77",),
    ),
    Provider(
        key="bunny",
        ptr_suffixes=("bunnycdn.com", "b-cdn.net"),
        org_patterns=("bunny",),
        header_markers=("server: bunnycdn",),
    ),
    Provider(
        key="gcore",
        ptr_suffixes=("gcorelabs.net", "gcdn.co", "gcore.com"),
        org_patterns=("gcore",),
        header_markers=("server: gcore",),
    ),
    Provider(
        key="keycdn",
        ptr_suffixes=("kxcdn.com",),
        org_patterns=("keycdn",),
        header_markers=("server: keycdn",),
    ),
    Provider(
        key="azure",
        ptr_suffixes=("azureedge.net", "azurefd.net", "cloudapp.azure.com"),
        org_patterns=("microsoft", "azure"),
    ),
    Provider(
        key="google",
        ptr_suffixes=("googleusercontent.com", "googlehosted.com", "1e100.net"),
        org_patterns=("google",),
        header_markers=("server: gws", "x-goog-"),
    ),
)

PROVIDER_BY_KEY: dict[str, Provider] = {provider.key: provider for provider in PROVIDERS}


@dataclass(frozen=True)
class CdnVerdict:
    """The classification of one address, with the evidence behind it."""

    ip: str
    verdict: str = VERDICT_UNKNOWN
    confidence: str = CONFIDENCE_LOW
    provider: str = ""
    evidence: tuple[str, ...] = ()

    @property
    def is_cdn(self) -> bool:
        return self.verdict == VERDICT_CDN

    @property
    def is_hosted(self) -> bool:
        """The target's own name is served by a third party's platform here."""
        return self.verdict == VERDICT_HOSTED

    @property
    def labelled(self) -> str:
        """``cdn``/``dedicated``/``unknown`` plus the provider when known."""
        if self.provider:
            return f"{self.verdict} ({self.provider})"
        return self.verdict

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "ip": self.ip,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
        }
        if self.provider:
            payload["provider"] = self.provider
        return payload


# --------------------------------------------------------------------------- #
# Range snapshot
# --------------------------------------------------------------------------- #


@dataclass
class RangeTable:
    """The parsed bundled range snapshot, plus what could not be parsed."""

    networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = field(
        default_factory=list
    )
    unparsed: list[str] = field(default_factory=list)

    def match(self, address: str) -> tuple[str, str] | None:
        """``(provider_key, network)`` when *address* falls in a known range."""
        canonical = canonicalize_ip(address)
        if canonical is None:
            return None
        parsed = ipaddress.ip_address(canonical)
        for network, provider in self.networks:
            if parsed.version == network.version and parsed in network:
                return provider, str(network)
        return None

    def to_dict(self) -> dict[str, object]:
        return {
            "networks": len(self.networks),
            "providers": sorted({provider for _, provider in self.networks}),
            "unparsed": self.unparsed[:10],
        }


#: Parsed lazily and cached — the file is static for a process's lifetime.
_RANGE_CACHE: dict[str, RangeTable] = {}


def load_ranges(path: Path | str | None = None) -> RangeTable:
    """Parse a range file into a :class:`RangeTable` (cached per path).

    Unknown provider names and malformed networks are *collected*, not raised:
    a hand-edited range file must be able to carry a stale row without taking the
    stage down, and the report shows what was ignored.
    """
    target = Path(path or CDN_RANGES_FILE)
    key = str(target)
    if key in _RANGE_CACHE:
        return _RANGE_CACHE[key]

    table = RangeTable()
    for line in read_text(target).splitlines():
        stripped = line.split("#", 1)[0].strip()
        if not stripped:
            continue
        parts = stripped.split()
        if len(parts) < 2:
            table.unparsed.append(stripped)
            continue
        provider, network = parts[0].lower(), parts[1]
        if provider not in PROVIDER_BY_KEY:
            table.unparsed.append(f"unknown provider {parts[0]!r}: {network}")
            continue
        try:
            table.networks.append((ipaddress.ip_network(network, strict=False), provider))
        except ValueError:
            table.unparsed.append(f"invalid network {network!r}")

    if table.unparsed:
        log.warning(
            "CDN range file %s: %d unparsed line(s) ignored (%s)",
            target,
            len(table.unparsed),
            "; ".join(table.unparsed[:3]),
        )
    _RANGE_CACHE[key] = table
    return table


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #


def _matches_suffix(name: str, suffixes: Iterable[str]) -> bool:
    """Whole-label suffix match — ``a.b.cloudflare.net`` matches, ``xcloudflare.net`` does not."""
    lowered = name.strip().rstrip(".").lower()
    return any(lowered == suffix or lowered.endswith("." + suffix) for suffix in suffixes)


def _hosted_target(name: str) -> str | None:
    """The hosted-platform suffix when *name* is a tenant name, else ``None``.

    Whole-label matching, same rule as the CDN suffixes, so
    ``notoutlook.com`` can never match ``outlook.com``.  The suffixes are tried
    in :data:`HOSTED_SUFFIXES` order and the first hit wins, which matters only
    for the display label (``_HOSTED_LABELS``) — the verdict is the same either
    way.
    """
    lowered = name.strip().rstrip(".").lower()
    if not lowered:
        return None
    for suffix in HOSTED_SUFFIXES:
        if lowered == suffix or lowered.endswith("." + suffix):
            return suffix
    return None


def classify(
    ip: str,
    *,
    intel: object | None = None,
    ownership: object | None = None,
    ptr_names: Iterable[str] = (),
    cname_targets: Iterable[str] = (),
    ranges: RangeTable | None = None,
    headers: Mapping[str, str] | None = None,
    in_scope: bool = False,
) -> CdnVerdict:
    """Classify one address from whatever evidence exists.

    Every argument except *ip* is optional: the function is a fold over the
    available signals, so it works identically during the pre-scan pass (names,
    registry, ranges) and after an HTTP probe (headers).

    *cname_targets* is separate from *ptr_names* on purpose.  Both are "a name
    that points at this address", but they are different facts: a PTR is the
    address's own reverse name, while a CNAME target is the alias our target's
    name resolves *through* — and the second is far stronger evidence, because it
    is the target's own DNS telling us it sits behind an edge.

    *in_scope* means "one of our target's names resolves to this address".  It is
    the positive evidence that separates ``dedicated`` from ``unknown``.
    """
    canonical = canonicalize_ip(ip)
    if canonical is None:
        return CdnVerdict(ip=str(ip), verdict=VERDICT_UNKNOWN, evidence=("not an IP literal",))

    evidence: list[str] = []
    provider = ""
    confidence = CONFIDENCE_LOW

    table = ranges if ranges is not None else load_ranges()
    match = table.match(canonical)
    if match is not None:
        key, network = match
        provider = key
        confidence = CONFIDENCE_HIGH
        evidence.append(f"{canonical} falls in {PROVIDER_BY_KEY[key].label} range {network}")

    # Hosted-platform CNAME targets, before the CDN loop: a target's own name
    # resolving *through* ``autodiscover.outlook.com`` says the address is a
    # third party's tenant infrastructure.  It does not say it is a CDN — the two
    # verdicts lead to different rungs (L2 allowed / escalation forbidden vs the
    # web-probe-only rung), so they are kept apart even when a suffix table could
    # theoretically match both.
    hosted_hits: list[str] = []
    for name in cname_targets:
        if _hosted_target(str(name)) is not None:
            hosted_hits.append(str(name))

    for name in cname_targets:
        for candidate in PROVIDERS:
            if _matches_suffix(str(name), candidate.ptr_suffixes):
                if not provider:
                    provider = candidate.key
                    confidence = CONFIDENCE_HIGH
                evidence.append(
                    f"CNAME chain passes through {name}, which is {candidate.label} edge "
                    f"naming (*.{candidate.ptr_suffixes[0]})"
                )
                break

    for name in ptr_names:
        for candidate in PROVIDERS:
            if _matches_suffix(str(name), candidate.ptr_suffixes):
                if not provider:
                    provider = candidate.key
                    confidence = CONFIDENCE_HIGH
                evidence.append(
                    f"PTR {name} matches {candidate.label} edge naming (*.{candidate.ptr_suffixes[0]})"
                )
                break

    # Ownership is treated differently from every signal above, and the reason is
    # measured rather than theoretical: Linode is now owned by Akamai, so Team
    # Cymru reports the AS name of ``scanme.nmap.org`` as "AKAMAI-LINODE-AP -
    # Akamai Connected Cloud".  A substring match on "akamai" therefore classified
    # a plain cloud-hosting VPS as CDN edge.  "This address is in the provider's
    # network" and "this address is the provider's CDN edge" are different claims:
    # several providers sell cloud and hosting products under the same name.
    #
    # So an ownership match is *conclusive* only for providers whose whole network
    # is edge (see EDGE_NETWORKS) and is otherwise recorded as a note that needs
    # corroboration — which genuine edge addresses always provide, because their
    # names resolve through the provider's edge naming (CNAME/PTR).
    org = str(getattr(ownership, "org", "") or "")
    as_name = str(getattr(ownership, "as_name", "") or "")
    notes: list[str] = []
    ownership_provider = ""
    ownership_note = ""
    for candidate in PROVIDERS:
        haystack = f"{org} {as_name}".lower()
        for pattern in candidate.org_patterns:
            if pattern and pattern in haystack:
                ownership_provider = candidate.key
                ownership_note = (
                    f"ownership record names {candidate.label} "
                    f"(org={org or '-'}, as_name={as_name or '-'})"
                )
                break
        if ownership_provider:
            break

    if ownership_provider:
        if provider:
            evidence.append(ownership_note)  # corroborates a signal we already have
        elif ownership_provider in EDGE_NETWORKS:
            provider = ownership_provider
            confidence = CONFIDENCE_HIGH
            evidence.append(ownership_note)
        else:
            notes.append(
                f"{ownership_note} - not treated as CDN edge evidence on its own, "
                "because this provider also operates non-edge cloud/hosting addresses"
            )

    tags = {str(tag).lower() for tag in getattr(intel, "tags", ()) or ()}
    edge_tags = tags & EDGE_TAGS
    if edge_tags:
        # Provider-less on purpose (see EDGE_TAGS): the tag says "edge", not "whose
        # edge", so it raises the verdict without inventing an attribution.
        evidence.append(
            "passive intel tags this address as edge infrastructure "
            f"({', '.join(sorted(edge_tags))})"
        )

    for name in getattr(intel, "hostnames", ()) or ():
        for candidate in PROVIDERS:
            if _matches_suffix(str(name), candidate.ptr_suffixes):
                if not provider:
                    provider = candidate.key
                    confidence = CONFIDENCE_MEDIUM
                evidence.append(f"passive intel hostname {name} matches {candidate.label} naming")
                break

    if headers:
        lowered = {str(key).lower(): str(value).lower() for key, value in headers.items()}
        for candidate in PROVIDERS:
            matched = False
            for marker in candidate.header_markers:
                name, separator, expected = marker.partition(":")
                name = name.strip()
                if separator:
                    # ``x-amz-cf-id`` — an exact header name.
                    value = lowered.get(name)
                    if value is None or (expected and expected.strip() not in value):
                        continue
                    detail = f"{name}: {value}"
                else:
                    # ``x-akamai-`` — a header-name *prefix*, because providers
                    # emit families of headers and only the prefix is stable.
                    actual = next((key for key in lowered if key.startswith(name)), None)
                    if actual is None:
                        continue
                    detail = f"{actual}: {lowered[actual]}"
                if not provider:
                    provider = candidate.key
                    confidence = CONFIDENCE_HIGH if not separator else CONFIDENCE_MEDIUM
                evidence.append(f"response header {detail}")
                matched = True
                break
            if matched:
                break

    if evidence:
        if not provider and confidence == CONFIDENCE_LOW:
            # Only a generic tag fired, which is the weakest form of evidence.
            confidence = CONFIDENCE_MEDIUM
        return CdnVerdict(
            ip=canonical,
            verdict=VERDICT_CDN,
            confidence=confidence,
            provider=PROVIDER_BY_KEY[provider].label if provider else "",
            evidence=tuple(dict.fromkeys([*evidence, *notes])),
        )

    if hosted_hits:
        # The CNAME chain is the target's own DNS naming the platform the service
        # runs on — the strongest possible "this is not our server" signal that
        # stops short of a CDN verdict.  The ladder still grants this address the
        # top-N rung (a hosted endpoint can expose the tenant's own ports), but
        # escalation to a full-range sweep is refused: what an L2 finding means
        # here is "Microsoft's/Heroku's edge answered", not "the target's server
        # is worth 65,535 probes".
        platform = _HOSTED_LABELS.get(_hosted_target(hosted_hits[0]) or "", "hosted platform")
        return CdnVerdict(
            ip=canonical,
            verdict=VERDICT_HOSTED,
            confidence=CONFIDENCE_HIGH,
            provider=platform,
            evidence=tuple(
                dict.fromkeys(
                    [
                        *(
                            f"the target's name resolves through {name} - a {platform} "
                            "tenant name (CNAME chain), so this is third-party hosted "
                            "application infrastructure"
                            for name in hosted_hits
                        ),
                        *notes,
                    ]
                )
            ),
        )

    if in_scope:
        positives = []
        if getattr(intel, "indexed", False):
            positives.append("passive intel has a record for it")
        if getattr(ownership, "resolved", False):
            positives.append("ownership record resolved")
        return CdnVerdict(
            ip=canonical,
            verdict=VERDICT_DEDICATED,
            confidence=CONFIDENCE_MEDIUM if positives else CONFIDENCE_LOW,
            evidence=tuple(
                dict.fromkeys(
                    [
                        "no CDN/WAF signal",
                        "one of the target's names resolves here",
                        *positives,
                        *notes,
                    ]
                )
            ),
        )

    return CdnVerdict(
        ip=canonical,
        verdict=VERDICT_UNKNOWN,
        confidence=CONFIDENCE_LOW,
        evidence=tuple(
            dict.fromkeys(
                [
                    "no CDN/WAF signal",
                    "no in-scope name resolves here",
                    "no positive ownership evidence",
                    *notes,
                ]
            )
        ),
    )


def classify_all(
    ips: Iterable[str],
    *,
    intel_by_ip: Mapping[str, object] | None = None,
    ownership_by_ip: Mapping[str, object] | None = None,
    ptr_by_ip: Mapping[str, list[str]] | None = None,
    cname_by_ip: Mapping[str, list[str]] | None = None,
    headers_by_ip: Mapping[str, Mapping[str, str]] | None = None,
    in_scope: Iterable[str] = (),
    ranges: RangeTable | None = None,
) -> list[CdnVerdict]:
    """Classify many addresses, looking each one's evidence up by address."""
    intel_by_ip = intel_by_ip or {}
    ownership_by_ip = ownership_by_ip or {}
    ptr_by_ip = ptr_by_ip or {}
    cname_by_ip = cname_by_ip or {}
    headers_by_ip = headers_by_ip or {}
    scope = set(in_scope)
    table = ranges if ranges is not None else load_ranges()
    return [
        classify(
            address,
            intel=intel_by_ip.get(address),
            ownership=ownership_by_ip.get(address),
            ptr_names=ptr_by_ip.get(address, ()),
            cname_targets=cname_by_ip.get(address, ()),
            headers=headers_by_ip.get(address),
            ranges=table,
            in_scope=address in scope,
        )
        for address in dict.fromkeys(ips)
    ]


def summarise(verdicts: Iterable[CdnVerdict]) -> dict[str, object]:
    """Counts per verdict and provider, for the report."""
    verdicts = list(verdicts)
    by_verdict: dict[str, int] = {}
    by_provider: dict[str, int] = {}
    for verdict in verdicts:
        by_verdict[verdict.verdict] = by_verdict.get(verdict.verdict, 0) + 1
        if verdict.provider:
            by_provider[verdict.provider] = by_provider.get(verdict.provider, 0) + 1
    return {
        "classified": len(verdicts),
        "by_verdict": dict(sorted(by_verdict.items())),
        "by_provider": dict(sorted(by_provider.items(), key=lambda item: (-item[1], item[0]))),
    }


__all__ = [
    "CONFIDENCE_HIGH",
    "CONFIDENCE_LOW",
    "CONFIDENCE_MEDIUM",
    "CdnVerdict",
    "EDGE_NETWORKS",
    "EDGE_TAGS",
    "PROVIDERS",
    "PROVIDER_BY_KEY",
    "Provider",
    "RangeTable",
    "VERDICT_CDN",
    "VERDICT_DEDICATED",
    "VERDICT_HOSTED",
    "VERDICT_UNKNOWN",
    "classify",
    "classify_all",
    "load_ranges",
    "summarise",
]
