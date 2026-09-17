"""Derive the assets inside a URL set: endpoints, parameters, scripts, findings.

The passive stage produces *URLs*.  Almost nobody downstream wants URLs — they
want the things a URL is evidence of, and those are different assets:

* an **endpoint** is a URL with its query removed, because
  ``/api/v2/user?id=7`` and ``/api/v2/user?id=9`` are one place to look, not two;
* a **parameter** is a name the application reads, and the set of names across a
  target is what a fuzzing pass is built from;
* a **javascript bundle** (and its **source map**) is where the client-side API
  surface, hidden routes and feature flags live — the same material plan-v2's
  S24 stage crawls for, obtained here without touching the target;
* an **interesting file** is a path that a human should read first: ``.git``
  directories, ``.env`` files, database dumps, editor backups, admin consoles.

This module turns one list of canonical URLs into exactly those four things plus
the counts a report needs.  It is pure — no network, no Docker, no clock — so the
relationship between input URLs and derived assets is unit-testable, which is the
only way the counts in ``report.json`` can be trusted to mean what they say.

Design notes
------------
* **Nothing is inferred that the input does not support.**  A URL is only a JS
  bundle if its canonical form says so; nothing here guesses that ``/assets/x``
  is a script because it lacks an extension.
* **Ordering is deterministic** (sorted, everywhere), so two runs over the same
  URL set produce byte-identical artifacts.
* **Counts are of distinct assets, not of URLs.**  ``endpoints`` counts endpoint
  identities and ``javascript`` counts distinct bundle URLs; the report keeps
  both the raw URL count and the asset counts so a reader can see the collapse.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from .normalize import (
    KIND_API,
    KIND_JS,
    KIND_SOURCEMAP,
    ParsedUrl,
    group_by_kind,
    is_plausible_parameter,
    parse_urls,
)

#: How many of each asset class the report embeds as examples.  The full lists
#: are always written to disk; the report carries a sample so it stays readable.
REPORT_SAMPLE = 20


@dataclass
class UrlExtraction:
    """The assets derived from one URL set."""

    apex: str
    urls: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    javascript: list[str] = field(default_factory=list)
    source_maps: list[str] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    interesting: list[str] = field(default_factory=list)
    by_kind: dict[str, int] = field(default_factory=dict)
    #: ``{parameter: [url, ...]}`` — the reverse index, full (not sampled).
    parameter_index: dict[str, list[str]] = field(default_factory=dict)

    @property
    def counts(self) -> dict[str, int]:
        """The scalar counts every consumer reads."""
        return {
            "urls": len(self.urls),
            "hosts": len(self.hosts),
            "endpoints": len(self.endpoints),
            "parameters": len(self.parameters),
            "javascript": len(self.javascript),
            "source_maps": len(self.source_maps),
            "api_endpoints": len(self.api_endpoints),
            "interesting": len(self.interesting),
        }

    def to_dict(self) -> dict[str, object]:
        """Report payload: counts plus bounded samples of each asset class."""
        return {
            "apex": self.apex,
            "counts": self.counts,
            "by_kind": self.by_kind,
            "hosts": self.hosts,
            "endpoints_sample": self.endpoints[:REPORT_SAMPLE],
            "parameters_sample": self.parameters[:REPORT_SAMPLE],
            "javascript_sample": self.javascript[:REPORT_SAMPLE],
            "source_maps_sample": self.source_maps[:REPORT_SAMPLE],
            "api_endpoints_sample": self.api_endpoints[:REPORT_SAMPLE],
            "interesting_sample": self.interesting[:REPORT_SAMPLE],
        }


def extract(urls: Iterable[str], apex: str) -> UrlExtraction:
    """Derive every asset class from a list of raw URLs.

    Raw (not necessarily canonical) URLs are accepted: they are canonicalized
    and scope-filtered here through :func:`..normalize.parse_urls`, so a caller
    can hand over a source file without pre-cleaning it.
    """
    parsed = parse_urls(list(urls), apex)
    return extract_parsed(parsed, apex)


def extract_parsed(parsed: list[ParsedUrl], apex: str) -> UrlExtraction:
    """Derive every asset class from already-parsed URLs.

    Split out from :func:`extract` so the orchestrator can parse once and use the
    result for several purposes without paying for a second parse.
    """
    by_kind = {kind: len(items) for kind, items in group_by_kind(parsed).items()}

    endpoints = sorted({item.endpoint for item in parsed})
    # Parameter *names* are filtered to identifier shapes: a historical harvest
    # contains query strings that are pasted commands and documentation prose, and
    # both are real evidence of a URL but neither is a name an application reads.
    parameter_names = sorted(
        {
            name
            for item in parsed
            for name in item.parameter_names
            if is_plausible_parameter(name)
        }
    )
    javascript = sorted({item.url for item in parsed if item.kind == KIND_JS})
    source_maps = sorted({item.url for item in parsed if item.kind == KIND_SOURCEMAP})
    api_endpoints = sorted(
        {item.endpoint for item in parsed if item.kind == KIND_API}
    )
    interesting = sorted({item.url for item in parsed if item.interesting})
    hosts = sorted({item.host for item in parsed})

    index: dict[str, set[str]] = {}
    for item in parsed:
        for name in item.parameter_names:
            if is_plausible_parameter(name):
                index.setdefault(name, set()).add(item.url)

    return UrlExtraction(
        apex=apex,
        urls=sorted({item.url for item in parsed}),
        hosts=hosts,
        endpoints=endpoints,
        parameters=parameter_names,
        javascript=javascript,
        source_maps=source_maps,
        api_endpoints=api_endpoints,
        interesting=interesting,
        by_kind=by_kind,
        parameter_index={name: sorted(urls) for name, urls in sorted(index.items())},
    )
