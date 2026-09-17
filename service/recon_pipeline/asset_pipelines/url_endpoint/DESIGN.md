# URLs / Endpoints — Design & Research

**Status:** passive + extract **implemented**; light-active crawl and graph writes
designed, not built (see *Phases*).

**Problem.** The names pipeline answers "what hosts exist" and the ports pipeline
answers "what is listening". Neither answers the question a web attacker asks
second: **what can I request?** Historical archives are the cheapest source of
that answer, because *"organizations clean the present while leaving the past
intact"* (`recon.md` §2) — an endpoint deleted from a site in 2019 is still in the
Wayback Machine, still routable often enough to matter, and invisible to a DNS or
port scan.

This document records the source and tool choices and the evidence behind them.

---

## 1. Source selection

| Source | Cost / auth | What it uniquely contributes | Known limits |
|---|---|---|---|
| **Wayback CDX** | keyless | Highest coverage of *linked* URLs; long retention; `collapse=urlkey` dedups server-side | Best-effort public service; ordered by capture time, so large limits are apex/`www`-heavy; occasional HTML error page instead of JSON |
| **Common Crawl index** | keyless | Independent crawl; columnar index is queryable at scale; survives Wayback gaps | 404 + prose body means "never crawled" (a fact, not a failure); newest index must be discovered via `collinfo.json` |
| **urlscan.io search** | keyless (small quota) / key | Already-scanned pages **and their subresources**; regularly catches live SPA routes | Documented rate limits (429 is normal); response properties may be missing; pagination needs `search_after` |
| **`gau`** (Docker) | keyless | Aggregates Wayback + Common Crawl + **AlienVault OTX** + urlscan in one pass; independent implementation | One process for four upstreams is a single point of slowness (measured: ~6.5 min on `example.com`; on `hackerone.com` it hit a 240 s budget and was reported as a failed source) |

Sources **not** chosen, and why:

- **`waymore`** — richer than `gau` (it also pulls the CDX *capture* metadata), but
  it is a wrapper around the same APIs with a heavier config surface. Revisit if
  per-capture status/mimetype filtering becomes a requirement.
- **`waybackurls`** — Wayback only, superseded by `gau`.
- **Archive.today / Memento aggregators** — no stable public API; scraping them is
  exactly what this pipeline's polite-source policy avoids.
- **Google/Bing dorking** — violates the search engines' terms and is not a
  passive source in any defensible sense.

### Why redundancy is deliberate

The two archives disagree constantly (retention windows, rate limits, crawl
schedules), and `gau`'s parsing differs from ours by construction. A URL reported
by two independent harvesters is corroboration; the same argument the names stage
makes for running seven overlapping CT sources. The union is the product, and the
per-source raw files are kept so a disagreement is auditable.

## 2. Tool comparison (`gau` vs. a native-only harvest)

| | `gau` | native (Wayback + CC + urlscan) |
|---|---|---|
| Upstreams | 4 (+OTX) | 3 |
| Runs without Docker | no | yes |
| Time on `example.com` | 393 s (291 210 URLs) | 29 s at an 800-row cap |
| Parsing we control | no (partially) | yes |
| OTX coverage | yes | no |

Decision: **both**. The native sources are the always-available floor (no Docker,
no image build, and their parsing is ours to fix), and `gau` is the coverage
ceiling. `--skip gau` gives a working keyless-only run.

## 3. Design principles

1. **Identity before counting.** A URL is reduced to one canonical string
   (lowercase/IDNA host, default ports dropped, path normalized, tracking
   parameters stripped, remaining parameters sorted, fragment dropped). Every
   count in the report is a count of *canonical* assets — without this, one
   endpoint with a campaign string becomes hundreds.
2. **Scope is enforced at the boundary.** Out-of-scope hosts are written to
   `foreign.txt` and counted, never merged. Public archives legitimately contain
   unrelated hosts, so this is reported rather than treated as an error.
3. **Honest states.** "The source said no" (404 from Common Crawl), "the source
   did not answer" (transport failure) and "the source was rate-limited" (429) are
   three different outcomes and stay three different outcomes. Collapsing them
   makes the report lie about coverage, and it did: a live run against `qbsco.net`
   recorded `commoncrawl ok=True urls=0` while `collinfo.json` had refused every
   connection — indistinguishable from "Common Crawl has never crawled this
   domain". The rule is now enforced rather than documented: a source that cannot
   obtain an answer raises (`passive/errors.py`), the stage records it as
   **failed** with the reason, and the union is still built from the sources that
   did answer.
4. **Only this run's sources count.** The merge reads only sources that succeeded
   in this run, so a stale raw file cannot contaminate the union — the same
   guarantee `run_recon.py` provides with its mtime snapshot.
5. **Debris is dropped and counted.** A live run against `example.com` produced
   template placeholders (`${P}-doc.tar.bz2`), shell fragments (`ngx_stream_module.so:127.0.0.1:80:/bin/sh`)
   and pasted address bars. Junk URLs are excluded from the union and counted
   (`report.json` → `junk`); parameter names are filtered to identifier shapes so
   `parameters.txt` means "names the application reads". A second live run, at
   scale (49 000 URLs), added two rejection rules: a top-level dot (`?hackddos.com`,
   `?index.html` — spam injection and broken links put hostnames and filenames in
   the key position) and an over-long token (prose that happens to be
   identifier-shaped). Bracketed members keep their dots, where a dot is nested,
   not a filename.
6. **Deterministic output.** Sorted at every step; two runs over one URL set
   produce byte-identical artifacts.

## 4. Extraction model

Four asset classes are derived, each from a different property of the URL:

| Asset | Derivation | Why it is a separate asset |
|---|---|---|
| Endpoint | URL minus query | `/user?id=1` and `/user?id=9` are one place to look |
| Parameter | query names, identifier-shaped | the set of names across a target is what a fuzzing pass is built from |
| JavaScript / source map | extension (`.js`, `.mjs`, `.map`, …) | bundled JS and published maps expose routes, feature flags and client logic |
| Interesting file | extension, path segment, or whole-path suffix | the operator's first-five-minutes triage queue (`.git`, `.env`, dumps, backups, archives, admin consoles) |

Classification is extension-first, then an API-shaped path, then `page`. Nothing
is inferred that the URL does not say — a path without an extension is a page, not
a guessed script.

## 5. Phases

| Phase | Scope | Status |
|---|---|---|
| **P1** | Keyless passive harvest (Wayback, Common Crawl, urlscan) + `gau` + canonical union | **built** |
| **P2** | Extraction: endpoints, parameters, JS, source maps, findings | **built** |
| **P3** | Light-active crawl of confirmed hosts (`katana`) for additional routes | not built — needs the S10 dispatcher/stealth chokepoint |
| **P4** | Graph writes (`URL`, `Endpoint` nodes with provenance) | not built — the whole recon suite is file-only today |
| **P5** | urlscan pagination and multi-index Common Crawl sweeps | not built |

## 6. References

- `recon.md` §2 (historical depth), §3 (URL asset type), §5.3 (stream-extract-discard).
- `recon_v2.md` §3 sources 9 & 11 (JS bundle crawl, content discovery) — P3's
  design targets.
- crt.sh / Wayback behaviour inherited from the names stage's measured findings
  (`../subdomain_domain_wildcards/passive/README.md`).
- Tool documentation read for this design: `gau` (github.com/lc/gau),
  urlscan.io API docs (rate limits, optional `api-key`, missing-property
  warning), Common Crawl index (`collinfo.json`, index query API),
  `katana` (flags for `-jc`/`-jsl` JS parsing and scope control).
