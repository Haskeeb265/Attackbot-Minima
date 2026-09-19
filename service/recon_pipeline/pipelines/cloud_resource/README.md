# cloud_resource — storage-bucket discovery (S3 / Azure / GCS)

**What it answers:** which cloud-storage buckets exist under names the target
would plausibly use — and which of them its own DNS has *claimed* but the
provider says are **absent** (dangling references, the takeover detector's
raw material). Asset type **CloudResource** (`recon.md` §3 via the v2 plan's
S22; the graph schema's `LABEL_CLOUD_RESOURCE` is the node it would feed).

Like the sibling pipelines, it is **keyless, Docker-free and never scans the
target** — the probe stage's one GET per candidate goes to a **provider**
endpoint (`acme.s3.amazonaws.com`), which is why the manifest keeps
`passive_only=True` on the same reading `asn_cidr` makes for RIPEstat/RDAP.

## Pipeline

```
seeds      sibling artifacts (CNAMEs, URLs, JS, endpoints) + --name overrides
   ↓
harvest    match provider host patterns      → claimed names  (strongest)
           brand tokens × name shapes        → derived names  (capped)
           (all pure file reading — zero network)
   ↓
probe      one GET per (name, provider), classified by the response matrix:
           open · auth_required · dangling · absent ·
           exists_other_region · unavailable
   ↓
emit       output/verdicts.jsonl · output/buckets.jsonl · output/dangling.jsonl
           output/report.json · passive/output/candidates.{jsonl,txt} + report.json
```

## Providers and verdicts

| Provider | Exists, open | Exists, denies anon | Absent | Quirk |
|---|---|---|---|---|
| AWS S3 | 200 (`ListBucketResult` = listable) | 403 | 404 `NoSuchBucket` | 301 / 400-with-region = **exists elsewhere** (recorded, not chased in P1) |
| Azure Blob | 200 | 403 `PublicAccessNotPermitted` | 404 `ContainerNotFound` | **absent account answers 409 `AccountNotFound`** — body `<Code>` keys the verdict |
| GCS | 200 | 403 | 404 `NoSuchBucket`/`notFound` | two error dialects (XML/JSON) |

The one honesty rule: **"no such bucket" and "no answer" stay apart.** A
provider 404 is a usable fact; a refused connection or 5xx is
`unavailable`, counted as a failure, never a false "absent"
(the lesson `../url_endpoint/passive/errors.py` learned from Common Crawl).

## Outputs

| File | Contents |
|---|---|
| `passive/output/candidates.jsonl` | one row per candidate: name, provider, origin(s), sources, evidence |
| `passive/output/candidates.txt` | bare names — the human-readable twin |
| `passive/output/report.json` | per-origin counts, per-artifact states, refusals with reasons |
| `output/verdicts.jsonl` | every probe: state, code, http status, probe URL, evidence class |
| `output/buckets.jsonl` | **only names that exist** (open / auth_required / other-region) |
| `output/dangling.jsonl` | CNAME-claimed names the provider says are absent — **S25 raw material** |
| `output/report.json` | counts by state and evidence class, caps, ok |
| `output/summary.json` | the combined run summary (both stages) |

## Flags

| Flag | Purpose |
|---|---|
| `-t, --target` | apex domain (default: `TARGET` from `.env`) |
| `--stages` | `harvest`, `probe`, or both (default) |
| `--name` | explicit candidate name, repeatable (probed against every enabled provider) |
| `--no-sibling-input` | ignore sibling artifacts; explicit `--name` seeds only |
| `--output-dir` / `--passive-output-dir` | output directories |
| `--max-derived` / `--max-probes` | cap overrides |
| `--timeout` | per-probe seconds |
| `-v` | debug logging |

Exit codes: `0` clean; `1` completed with unavailable probes; `2` refused (bad target/stage).

Environment: `CLOUD_S3_ENABLED`, `CLOUD_AZURE_ENABLED`, `CLOUD_GCS_ENABLED`,
`CLOUD_MAX_DERIVED` (default 128), `CLOUD_MAX_PROBES` (default 512),
`CLOUD_HTTP_TIMEOUT`, `CLOUD_HTTP_RETRIES`.

## Where the candidates come from

| Origin | Artifact | Strength |
|---|---|---|
| `cname` | names stage `active/output/records.jsonl` | strongest — the target's own DNS claimed the name |
| `url` / `javascript` / `endpoint` | URL stage union, JS, endpoint lists | observed in the target's artifacts |
| `derived` | brand tokens × ~36 name shapes | capped (`CLOUD_MAX_DERIVED`), weakest |
| `explicit` | `--name` | operator-supplied |

Names are validated against each provider's own rules and **refused, never
sanitized**: S3 3–63 `[a-z0-9.-]`; Azure 3–24 lowercase alnum; GCS 3–63
`[a-z0-9._-]`. Refusals are counted in the harvest report with reasons.

## Measured

(filled after the first live run — see DESIGN.md §9)

## Not built

- **S3 region chase** (P2) — a 301 is kept as "exists elsewhere"; following it
  across ~30 region endpoints is a request-budget decision.
- **Fourth/fifth providers** (P2) — DigitalOcean Spaces, Backblaze B2, Firebase.
- **Azure account/container splitting** (P2) — CNAMEs point at account-shaped
  hosts; no sibling artifact separates the container name.
- **Graph writes** — done at the platform seam: `graph_normalize`'s `publish`
  stage journals every bucket and `cname_points_to` edge through `GraphSink`.
- **Takeover handoff** (P3) — built: `takeover.py` probes fingerprint-matched
  CNAME claims (S25); `dangling.jsonl` remains the detector's raw material.

## Related

- [`DESIGN.md`](DESIGN.md) — provider matrices, name rules, why this asset type
  was next, phases.
- `../subdomain_domain_wildcards/README.md` — the CNAME records this reads.
- `../url_endpoint/README.md` — the URL/JS/endpoint artifacts this reads.
- `../graph_normalize/README.md` — the consumer that will carry
  `CloudResource` nodes once its vocabulary grows a kind for them.
