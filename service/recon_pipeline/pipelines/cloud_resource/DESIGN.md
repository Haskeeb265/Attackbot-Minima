# `cloud_resource` — R&D and design

**Asset type:** CloudResource (`recon.md` §3 has no numbered row for buckets;
the v2 plan's **S22 "cloud bucket enumeration"** is the stage this implements;
the graph schema's `LABEL_CLOUD_RESOURCE` is the node it would feed).
**Status:** implemented as designed; deltas recorded at the bottom.

---

## 1. Why this asset type was next

The coverage table in `progress.md` counts **11 asset types with no collection
logic at all**. `cloud_resource` was chosen over the other candidates on the
same grounds the sibling pipelines were chosen — by what it closes, not by what
it adds:

| Criterion | Evidence |
|---|---|
| **Best-fed seeds in the tree** | `url_endpoint` harvested 291 k URLs (hackerone.com) including JS bundle URLs — bucket names appear verbatim in JS. `records.jsonl` carries CNAME answers nobody interprets (a `<name>.s3.amazonaws.com` CNAME *is* a bucket claim). `live_hosts.txt` / `endpoints.txt` give brand tokens for name derivation. |
| **A real passive AND active phase** | Passive: harvest + derive candidate names from sibling artifacts — zero network. Active: provider existence probes against **provider** endpoints (never the target's own infrastructure). |
| **Closes a loop a sibling left open** | `graph_normalize` defines no `cloudresource` kind (0 mentions); the S25 takeover detector needs dangling-bucket facts as raw material; `records.jsonl` CNAMEs already point at provider hosts no pipeline reads. |
| **Keyless** | All three provider probes are unauthenticated HTTP GETs to the provider. No API keys, no Docker image, no tools. |

Not chosen this round: **Certificate clustering (S20)** — highest raw value, but
its passive source (crt.sh) already exists in the names pipeline, so it is
mostly re-plumbing; and it has no meaningful active phase short of
certificate-grabbing (touching the target). **Secrets (S21/S23)** needs the
Secret Handling Contract signed before anything writes an artifact.

## 2. The claim model — *found* vs *dangling*

A bucket is never just "exists". The design keeps four states apart, because
the difference between them is exactly what makes a bucket interesting:

| State | Meaning | Evidence |
|---|---|---|
| `open` | Answers 200 — content readable (and listable, when `<ListBucketResult>` comes back) | 200 body |
| `auth_required` | **Exists, but denies anonymous reads** — the most common state and the most commonly misread as "not found" | S3 403, GCS 403, Azure 403/409 `PublicAccessNotPermitted` |
| `dangling` | **CNAME points here but the bucket does not answer** — a takeover-eligible dangling reference (S25's raw material) | S3 404 + `NoSuchBucket`, GCS 404, Azure 404/409 `AccountNotFound` |
| `absent` | The *derived candidate* never existed — a negative, kept apart from failures | provider 404 with no prior CNAME claim |

And the one rule that keeps the report honest — the same lesson
`url_endpoint/passive/errors.py` learned from Common Crawl:

> **"no such bucket" and "no answer" stay apart.** A provider 404 is a usable
> fact; a refused connection, a 5xx, or a rate limit is nothing. A probe that
> cannot obtain an answer reports `status=unavailable` and contributes
> `source_failures`, never a false "absent".

## 3. Provider response matrices (the active probe's brain)

Verified against provider documentation and live behaviour during R&D
(2026-09). These tables are the *entire* classification logic — encoded in
`verify.py`, mirrored in `commands.txt` for hand-checking.

### AWS S3 — virtual-hosted style (`https://<bucket>.s3.<region>.amazonaws.com/`)

| HTTP | Body signal | Verdict |
|---|---|---|
| 200 | `<ListBucketResult>` | `open` + listable |
| 200 | anything else | `open` |
| 301 | `Location` header | **exists** — bucket lives in another region; `dangling` excluded, follow region is a P2 |
| 403 | — | `auth_required` (exists, denies anonymous) |
| 404 | `<Code>NoSuchBucket</Code>` | `dangling` if a CNAME claimed it, else `absent` |
| 400 | `<Code>AuthorizationHeaderMalformed</Code>` + region hint | **exists** — wrong region spelling; `dangling` excluded |
| 5xx / refused | — | `unavailable` — a failure, not a verdict |

### Azure Blob — `https://<account>.blob.core.windows.net/<container>`

Azure's quirk, learned during R&D and the reason the matrix is body-aware: a
**storage account that does not exist answers HTTP 409** with
`<Code>AccountNotFound</Code>` (status body from the account-level endpoint),
while an existing account's missing container answers **404**. Azure also
answers some existence classes with **400**. So Azure verdicts key on the body
`<Code>` first, status code second:

| HTTP | Body `Code` | Verdict |
|---|---|---|
| 200 | — | `open` |
| 403 / 409 | `PublicAccessNotPermitted` | `auth_required` |
| 409 | `AccountNotFound` | `dangling` (CNAME claimed it) / `absent` |
| 404 / 400 | `ContainerNotFound`, `BlobNotFound`, `MissingRequiredHeader`, `InvalidQueryParameterValue`, … | `dangling` / `absent` |
| 5xx / refused | — | `unavailable` |

### Google Cloud Storage — `https://<bucket>.storage.googleapis.com/`

| HTTP | Body | Verdict |
|---|---|---|
| 200 | — | `open` |
| 400 | `InvalidArgument` (bad bucket name) | `absent` (name never valid) |
| 403 | — | `auth_required` (exists, denies anonymous) |
| 404 | `NoSuchBucket` (XML) / `notFound` (JSON) | `dangling` / `absent` |
| 5xx / refused | — | `unavailable` |

**Deliberate non-features:**
- **No listing of open buckets beyond existence.** A `GET /` that answers is
  recorded; a recursive object walk is the vulnerability finder's job, not a
  recon pipeline's.
- **No upload probes.** Write tests change the target's state; a recon tool
  never does.
- **No DigitalOcean/DO Spaces, Backblaze B2, Firebase** — a fourth provider
  doubles the matrix for a fraction of the coverage; P2.

## 4. Passive phase — where candidate names come from

The pipeline never invents names blindly. Every candidate is **derived** from a
sibling artifact and carries the artifact as its provenance:

| Origin | Artifact | Extraction |
|---|---|---|
| `cname` (strongest) | names stage `active/output/records.jsonl` | a CNAME whose target matches a provider host pattern (`*.s3.amazonaws.com`, `*.blob.core.windows.net`, `*.storage.googleapis.com`) — *the target's own DNS already claimed this name* |
| `url` | URL stage `output/urls.jsonl` (falls back to `passive/output/urls.txt`) | host or path segments matching provider host patterns |
| `javascript` | URL stage `output/javascript.txt` | JS bundle URLs whose host matches a provider pattern |
| `endpoint` | URL stage `output/endpoints.txt` | same, from the derived endpoint list |
| `derived` | names stage `output/live_hosts.txt` + URL stage `output/endpoints.txt` | brand tokens (`qbsco`, `qbsco-net`, `qbsco_net`) × a small name-shape vocabulary (`{brand}`, `{brand}-assets`, `{brand}-static`, `{brand}-backups`, …) × provider host template |
| `explicit` | CLI `--name` | operator-supplied, repeatable |

Every row keeps `origin`, `sources` (artifact + provider pattern that matched),
and `evidence` (the exact string that gave the name away).  A candidate that
two artifacts both produced is one row with two origins — the merge discipline
every sibling enforces.

**Name hygiene** (each rule tied to a real spam-injection class, the same class
the URL stage's parameter filter met):
- bucket names are lowercased; provider-invalid characters are *rejected, not
  sanitized* (a sanitized name would be probed at the provider's cost for a
  bucket nobody could own);
- S3: 3–63 chars, `[a-z0-9.-]`, alnum start/end (dots kept — they are legal and
  common);
- Azure/GCS: 3–63 chars, `[a-z0-9-]`, alnum start/end (no dots — candidates
  with dots are S3-only);
- tokens shorter than 3 chars or longer than 63 are refused with a reason,
  counted in the report.

## 5. Active phase — the probe loop

```
candidates.jsonl (passive output)
   ↓  dedupe by canonical name, one probe per (name, provider)
GET <provider URL>            ← provider endpoint, never target infrastructure
   ↓  matrix above
verdicts.jsonl / buckets.jsonl / report.json
```

- **One request per name per provider.** The name-shape vocabulary is capped
  (`CLOUD_MAX_DERIVED`, default 128) so a brand can never explode into
  thousands of probes; the cap-bite is reported.
- **No region guessing in P1:** a S3 301/400-with-region-hint is recorded as
  *exists, other region* rather than retried across 30 region endpoints. The
  retry loop would be 30× the request volume for names that already exist.
- **Injectable transport:** `verify.py` takes a `fetcher` callable — the same
  seam `asn_cidr/sources.py` uses — so tests never touch the network and the
  live transport is one function.
- **`passive_only=True` in the manifest stays true.** The probes touch the
  *providers*, never the target; the same reading the `asn_cidr` manifest makes
  for RIPEstat/RDAP. The dispatcher may still gate it; the flag is what the
  report reads.

## 6. Outputs

| File | Contents |
|---|---|
| `passive/output/candidates.jsonl` | one row per candidate: name, provider, origin(s), sources, evidence |
| `passive/output/candidates.txt` | bare names — the human-readable twin |
| `passive/output/report.json` | per-origin counts, per-artifact presence, refusals with reasons, cap-bites |
| `output/verdicts.jsonl` | one row per probe: name, provider, state, http status, body code, evidence class |
| `output/buckets.jsonl` | **only names that exist** (`open` / `auth_required` / exists-in-another-region) with their evidence class — the curated artifact |
| `output/dangling.jsonl` | CNAME-claimed names the provider says are absent — **S25 takeover raw material** |
| `output/report.json` | counts (candidates, probed, by verdict, unavailable, refusals), probe caps |

Determinism: both stages sort every emitted set; two runs over the same
artifacts produce byte-identical outputs (tested).

## 7. Honest limits (recorded, not hidden)

- **Candidate recall is bounded by sibling artifacts.** If the URL harvest
  missed the JS bundle naming the bucket, nothing will find it here. The
  name-shape derivation is deliberately small; a wordlist `cloud_enum`-style
  run is a P2 with a request budget behind it.
- **S3 region ambiguity is recorded, not resolved** (one 301 kept, no region
  chase) — see §5.
- **Azure container vs account naming** — probes key on account-level answers;
  a container-per-candidate model would need the account name separated from
  the container name, which no sibling artifact carries in P1 (CNAMEs point at
  account-shaped hosts; URLs sometimes at `/container/` paths — kept as
  evidence, not split).
- **No graph writes** — file-only like every sibling today; the schema's
  `LABEL_CLOUD_RESOURCE` stays empty until the schema finalizes (the standing
  platform-wide decision).

## 8. Phases

- **P1 (this build):** the three big providers, CNAME + URL/JS/endpoint
  extraction, brand × name-shape derivation, existence matrix, dangling set.
- **P2:** S3 region chase on 301/400, fourth/fifth providers, wordlist-mode
  derivation with a request budget, Azure account/container splitting,
  `graph_normalize` kind + edges (`stored_in`, `points_to`).
- **P3:** takeover handoff to S25 (dangling.jsonl is already its shape),
  per-bucket permission probing behind an explicit operator flag.

## 9. Measured

(filled after the first live run — see README.md's measured section once the
run completes)
