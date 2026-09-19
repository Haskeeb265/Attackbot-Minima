# URLs, Endpoints & Parameters

Historic-URL recon stage: **what did the target expose over HTTP, ever?** A
subdomain is a name and an open port is a socket; `/api/v2/internal/export?debug=1`
is a *thing you can request*. That third layer of surface is what this pipeline
maps.

It is the third built asset pipeline:

| Pipeline | Question it answers | Output |
|---|---|---|
| `subdomain_domain_wildcards` | what names exist? | live hosts |
| `port_service_host` | what is listening? | ports + services |
| **`url_endpoint`** | **what was exposed over HTTP?** | URLs, endpoints, parameters, JS bundles, findings |

It exists because the names stage already harvests archived URLs and then throws
the paths away: `passive/wayback.py` keeps `legacy-internal.example.com` from
`https://legacy-internal.example.com/admin` and discards `/admin`. A forgotten
API route, an old backup path or a javascript bundle never appears in a DNS or
port scan, and it is exactly the asset class bug-bounty programs pay for.

```bash
# from the project root (imports are absolute)

# the default run: keyless archives + gau, then extraction
python -m service.recon_pipeline.pipelines.url_endpoint.main -t example.com

# keyless only (no Docker needed): Wayback + Common Crawl + urlscan
python -m service.recon_pipeline.pipelines.url_endpoint.main -t example.com --skip gau

# re-derive assets from an existing harvest (fast; the common iteration loop)
python -m service.recon_pipeline.pipelines.url_endpoint.main -t example.com --stages extract

# what is in the registry
python -m service.recon_pipeline.pipelines.url_endpoint.passive.pipeline --list
```

Build the tool image (needed only for the `gau` source):

```bash
docker build -t url_endpoint_image \
  service/recon_pipeline/pipelines/url_endpoint/
```

---

## Stages

```
passive   Wayback CDX · Common Crawl index · urlscan.io search · gau (Docker)
   ↓      → canonical, in-scope, deduplicated URLs        passive/output/urls.txt
extract   URLs → endpoints, parameters (with their URLs), JS bundles, source maps
   ↓      → parameters.jsonl: one row per (url, parameter) observation
validate  policy-gated live HTTP check of the candidates that deserve it
   ↓      → url_validation.jsonl: alive / status / final URL / chain / title /
            content-type / server / tech / timestamp, per URL
```

`passive` sends **no traffic to the target**: every source reads a third party's
stored dataset, which is what makes the stage passive in the same sense the names
stage's crt.sh source is. `extract` is pure local computation.

`validate` is the one stage that sends requests, and it is deliberately last and
separate: an archived URL is **never** treated as live, a historical claim and a
current measurement travel as two different statements about the same URL, and
the stage only asks about what passed the scope engine and the platform's
escalation policy. It is idempotent — a URL measured within `URL_VALIDATE_TTL` is
not probed again — and it can be switched off entirely (`--no-validate`, or
`URL_VALIDATE=off`), which leaves the pipeline exactly as passive as it was
before the stage existed and records that it was skipped.

```bash
# validate the top 100 candidates (ranked by the platform policy: sensitive
# paths and API surface first, then independent-source corroboration, then the
# host's own measured state), reusing measurements from the last 24 hours
python -m service.recon_pipeline.pipelines.url_endpoint.main -t example.com \
    --stages validate --max-validate 100

# passive-only, for an engagement that must not touch anything
python -m service.recon_pipeline.pipelines.url_endpoint.main -t example.com \
    --no-validate
```

## Sources

| Source | Flavour | What it adds |
|---|---|---|
| `wayback` | keyless HTTP | the Wayback Machine's archive: what people linked and saved |
| `commoncrawl` | keyless HTTP | Common Crawl's independent crawl, across many index versions |
| `urlscan` | keyless HTTP (optional `URL_URLSCAN_KEY`) | pages and subresources, including live SPA routes |
| `gau` | Docker | the same four datasets (plus **AlienVault OTX**) via a different implementation |

Redundancy is the point, exactly as it is in the names stage: the two archives
disagree constantly (retention, crawl windows, rate limits), and a URL that two
independent harvesters report is corroboration. `gau` is the only source that
reaches OTX and the only one whose parsing is not ours, so agreement between it
and a native source is evidence rather than a tautology.

Every source is recorded as **succeeded**, **failed** *with its reason*, or
**skipped** *with its reason*. A source that could not be reached never
contributes a silent zero: an unreachable API, a rate limit, a refused query or a
body that is an error page instead of data all fail the source and leave a trace
in `report.json`. "This archive has no coverage for the domain" and "this archive
did not answer" are different facts, and only a source can tell them apart.

## Outputs

`passive/output/`

| File | Contents |
|---|---|
| `<source>.urls.txt` | that source's raw URLs, exactly as it emitted them |
| `urls.txt` | the canonical, in-scope, deduplicated union — **the stage's product** |
| `foreign.txt` | out-of-scope URLs found in a source's output (public archives contain unrelated hosts; this is normal) |
| `report.json` | counts, timings, per-source status, foreign/invalid/junk accounting |

`output/` (derived)

| File | Contents |
|---|---|
| `endpoints.txt` | URLs with the query removed — one line per place to look |
| `parameters.txt` | distinct, plausible parameter *names* across every endpoint |
| `parameters.jsonl` | **provenance**: one row per `(url, parameter, location)` observation — which URLs expose a parameter, and which parameters a URL exposes. Values are deliberately not recorded (archived query strings are full of real tokens) |
| `javascript.txt` | JS bundles (`.js`, `.mjs`, `.ts`, …) |
| `source_maps.txt` | `.map` files — source code, when the map is still published |
| `interesting.txt` | triage queue: `.git` directories, `.env`, dumps, backups, archives, admin consoles |
| `hosts.txt` | the hosts the URLs live on |
| `urls.jsonl` | one record per URL (`host`, `path`, `kind`, `extension`, `interesting`, `query`) |
| `report.json` | extraction counts plus bounded samples of each asset class |
| `url_validation.jsonl` | **live verification**: one record per validated URL (`state`, `alive`, `status`, `final_url`, `redirect_chain`, `content_type`, `title`, `server`, `tech`, `address`, `validated_at`, `validation_tool`) |
| `validation.json` | the validation run's own report: selection counts, the effective `per_host_limit`, per-state counts, refusals with reasons, the ranking reasons for the first few selected candidates, tool status |
| `validation-httpx.jsonl` / `-input.txt` / `.log` | the tool's raw stream, the exact URL list it was given, and its stderr |
| `summary.json` | combined per-stage status, counts and timings |

## Flags

| Flag | Purpose |
|---|---|
| `-t, --target` | apex domain (default: `TARGET` from `.env`) |
| `--stages` | `passive`, `extract`, `validate`, or any subset (default: all three) |
| `--only` / `--skip` | select passive sources (e.g. `--skip gau`) |
| `--max-urls` | cap the URL union after dedup (`0` = no cap) |
| `--timeout` | per-source wall-clock budget in seconds (600) |
| `--no-validate` | skip the live validation stage (the run is then passive-only) |
| `--max-validate` | URL candidates validated per run (`0` = no cap; 200) |
| `--max-validate-per-host` | candidates validated per host (25) |
| `--output-dir` / `--passive-output-dir` | where derived / raw artifacts land |
| `--list` | list the stages and exit |
| `-v` | debug logging |

Environment overrides: `URL_TIMEOUT`, `URL_WAYBACK_LIMIT`, `URL_COMMONCRAWL_LIMIT`,
`URL_COMMONCRAWL_INDEX`, `URL_URLSCAN_LIMIT`, `URL_URLSCAN_KEY`, `URL_GAU_IMAGE`,
`URL_MAX_URLS`, `URL_HTTP_MAX_BYTES`, `URL_HTTP_RETRIES`, `URL_VALIDATE`,
`URL_VALIDATE_MAX_URLS`, `URL_VALIDATE_MAX_PER_HOST`, `URL_VALIDATE_TTL`,
`URL_VALIDATE_RATE_LIMIT`, `URL_VALIDATE_THREADS`, `URL_HTTPX_IMAGE`.

Exit codes: `0` clean; `1` completed with a failed stage; `2` refused (bad target).

---

## Design

The stage's hard problem is **identity**: an archive spells one resource a dozen
ways, and every count downstream depends on folding them together. The rules
(`normalize.py`) are each tied to a failure that actually occurs in archived data:

- host lowercased / IDNA / trailing-dot stripped — via the **names stage's**
  `canonicalize_host`, so a host here and a subdomain there cannot disagree;
- default ports removed (`https://h:443/x` ≡ `https://h/x`);
- path normalized (`//`, `.`, `..` collapsed — crawls record all three spellings);
- campaign parameters stripped and the rest **sorted** (`utm_*`, `fbclid`, `gclid`
  …), so one endpoint cannot masquerade as two hundred;
- fragments dropped (they never reach a server);
- out-of-scope hosts recorded, never merged.

Two filters exist because a live run demanded them, not by speculation:

- **Junk.** `example.com`'s archive is full of template placeholders (`${P}.tar.bz2`),
  shell fragments and pasted address bars. These parse as URLs and are not
  addresses, so they are flagged, excluded from the union and **counted**
  (`report.json` → `junk`) rather than silently merged.
- **Plausible parameter names.** Query strings in a historical harvest contain
  sentences, file paths and regex fragments. `parameters.txt` keeps only
  identifier-shaped names, because that file's job is to say which names the
  application reads. Two further rejections came from the 49 000-URL harvest
  below: a **top-level dot** (spam injection and broken links put hostnames and
  filenames in the key position — `?hackddos.com`, `?index.html`) and an
  **over-long token** (prose that happens to be identifier-shaped). Bracketed
  members keep their dots (`filter[user.name]`), which is the case where a dot is
  meaningful.

Everything is deterministic: sorted at every step, so two runs over one URL set
produce byte-identical artifacts.

## Measured (2026-09-18)

Real targets, all four sources, default limits:

| Target | Sources ok | Raw URLs | Union | Endpoints | Params | JS | Interesting | Junk | Time |
|---|---|---|---|---|---|---|---|---|---|
| `qbsco.net` | 3/4 | 5 697 | 2 851 | 2 577 | 3 | 137 | 19 | 302 | 94 s |
| `hackerone.com` (`--timeout 240`) | 2/4 | 49 771 | 49 769 | 47 543 | 82 | 5 422 | 11 | 170 | 308 s |

On both runs **`commoncrawl` failed rather than reporting an empty success**: this
host cannot resolve or reach `index.commoncrawl.org`, which the report records as
`ok=false` with the reason instead of `ok=true urls=0`. On `hackerone.com` `gau`
also hit the 240 s budget and was reported as a failed source. The union is still
produced from the sources that answered — that is the whole point of the
per-source status in `report.json`, and it is why a degraded run is still usable
and legible.

Against `example.com` — a **documentation** domain whose archived data is far
noisier than a real target's, which is why it is a useful stress case:

| Run | Raw URLs | Union | Endpoints | Params | JS | Interesting | Junk dropped | Time |
|---|---|---|---|---|---|---|---|---|
| `--only wayback` (limit 800) | 800 | 782 | 774 | 9 | 4 | 5 | 18 | 29 s |
| `--only gau` (defaults) | 291 210 | 291 209 | 207 458 | 6 117 | 928 | 5 188 | 4 449 | 393 s |

`gau` is the slow source (~6.5 min here) because it queries four upstream datasets
itself; the keyless sources finish in tens of seconds. Cache the union and iterate
with `--stages extract` (25 s for 291 k URLs, 3 s for 50 k).

### `validate` — measured live, 2026-09-19

One real run against `qbsco.net` (3 207 archived URLs, declared scope = the apex),
`--max-validate 140`, on the stage image's `httpx`:

| | |
|---|---|
| selected / measured | 56 URLs in 25.5 s (≈ 5 req/s, 10 workers) |
| verified | **2** (`https://www.qbsco.net/` 200, `"QBS - Let's get better!"`, `robots.txt` 200) |
| redirected | **1** (`http://www.qbsco.net/` → `https://www.qbsco.net/`, chain `[301, 200]`) |
| dead | **47** (404) |
| errored | **3** (`ocac.qbsco.net`, Cloudflare 523 = origin unreachable) |
| unreachable | **3** (`app.`/`mail.` have no A record) |
| refused before probing | 0 scope failures (the union is apex-filtered), 59 already measured |

The finding is the point: every one of the 25 `.well-known/*` URLs permissive
harvesting had found — `ai-plugin.json`, `openid-configuration`, `security.txt`,
`nodeinfo` — answers **404** today, because the site now runs Next.js. Before this
stage existed those were 25 "assets"; they are 25 dead links and 2 live ones, and
the graph now records exactly that difference.

Two behaviours worth knowing when reading a run:

- **`httpx` reports one line per resolved address**, so a dual-A host yields two
  lines per URL (measured: 50 lines for 25 inputs). The parser deduplicates on the
  canonical URL; the raw stream keeps both lines as evidence.
- **A 404 counts as *answered*, not as *serving*.** The artifact's `alive` means a
  server replied; `serving` (in the graph) means 2xx/3xx. The report counts them
  separately so "53 alive" can never be read as "53 working endpoints".

### Selection — what the budget is spent on (2026-09-19)

The ranking rule is the platform policy (`platform.escalation.url_validation_priority`),
not a local table, so the stage cannot drift away from the gate the rest of the
pipeline uses. Six inputs, all available before a request is sent:

| Input | Effect | Source of truth |
|---|---|---|
| sensitive path (`.env`, `.git/config`, dumps, admin consoles) | +40, the strongest signal | the URL's own classification |
| kind | API +30 … CSS +0 | same |
| parameters | +6 — an input surface | `normalize.ParsedUrl.params` |
| independent sources | +4 each, capped at +12 | the passive stage's `<source>.urls.txt` |
| host state **this run** | +15 if the host has answered, −25 if every measurement on it failed | the validation artifact |
| in-scope host | +5, a tie-break (it is already required to be selected) | the scope engine |

Measured effect on the same union: the old rule (interesting paths, then path
length) put **0 API endpoints** in a 200-URL budget; the policy ranks **83**, and
196 of the 200 are corroborated by more than one archive (was 174).

Two settings, two jobs, and conflating them cost real coverage:

* `URL_VALIDATE_MAX_URLS` is the run's **budget** (200);
* `URL_VALIDATE_MAX_PER_HOST` is a **floor under an equal share of that budget**
  (25), not a ceiling. A host's share is `ceil(budget / hosts)`; the first pass
  guarantees every host its share, the second spends any leftover on the
  best-ranked candidates still waiting.

On this target (3 207 URLs, but only 5 hosts and 2 408 of them on the apex) a flat
per-host ceiling of 25 selected **50** URLs out of a budget of 200 and refused
3 061 as "cap reached" — the budget was never the constraint. With the share rule
the same run selects **200** (`qbsco.net` 154, `www` 40, the three small hosts 1–3)
while still guaranteeing the small hosts their share first. The total is unchanged:
the operator's budget is what bounds traffic.

## Not built

- **Light-active crawling** (`katana`) — crawling *confirmed live* URLs for the
  routes they reference. Designed but deliberately absent: `validate` answers
  "is this URL there?" with one request per candidate, while a crawl multiplies
  requests per page, so it belongs behind the same dispatcher/stealth chokepoint
  with per-host sequencing rather than a bounded batch.
- **Graph writes** — like the other two pipelines, results are files; nothing
  reaches Neo4j yet.
- **urlscan pagination** (`search_after`) and **Common Crawl multi-index sweeps** —
  single page / newest index by default; both are documented extension points.

## Related

- [`DESIGN.md`](DESIGN.md) — the research behind the source and tool choices.
- [`commands.txt`](commands.txt) — raw per-tool commands for reproducing one source by hand.
- `../subdomain_domain_wildcards/README.md` — the upstream stage that discovers the names this harvest covers.
- `../port_service_host/README.md` — the sibling pipeline that maps what is listening on those names.
- [`../../../stealth/README.md`](../../../stealth/README.md) — the shared shaping layer (used by the other stages; the passive sources here never touch the target).
