# Active Subdomain Resolution

Active stage of the `subdomain_domain_wildcards` asset pipeline: takes the
passive stage's candidate names and establishes **which of them exist in DNS, and
what is behind them**. It is the first stage that sends traffic anywhere, so it is
also the first stage with an authorization boundary (see
*Footprint and authorization*).

It answers four questions in one run:

| Question | Technique | Why it is needed |
|---|---|---|
| Which known names resolve? | `puredns resolve` (+ wildcard filter) | passive lists are historical; a name in a CT log is not a live host |
| Which names were never published? | `puredns bruteforce` over a wordlist | no OSINT source can leak a host nobody ever mentioned |
| Which names sit under live hosts? | bounded recursive bruteforce | only a second pass finds `api.dev.example.com` after `dev.example.com` |
| Does a nameserver leak its zone? | `dig AXFR` per nameserver | a misconfigured NS hands over the authoritative name list outright |

Record enrichment (`dnsx`) and an **opt-in** HTTP probe (`httpx`) follow.

```bash
# from the project root (imports are absolute)
python -m service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.active.pipeline
```

That runs: validate resolvers → gather candidates → resolve → bruteforce →
recurse → AXFR → wildcard filter → enrich → write `active/output/`.

Results feed the `permutation/` stage and, through the orchestrator, the
downstream IP/service stages.

---

## Quick start

```bash
# passive candidates + bruteforce + recursion + AXFR + enrichment (default)
python -m ...active.pipeline -t example.com

# cheap run: resolve what passive already found, nothing else
python -m ...active.pipeline -t example.com --no-bruteforce --no-recursion --no-axfr --no-enrich

# bigger wordlist, plus a stage-specific one
python -m ...active.pipeline -t example.com --wordlist seclists/subdomains-top1million-110000.txt

# see the engines and tools this stage can drive
python -m ...active.pipeline --list
```

| Flag | Purpose |
|---|---|
| `-t, --target` | apex domain (default: `TARGET` from `.env`, else `qbsco.net`) |
| `--engine` | `puredns` (default) or `shuffledns` |
| `--candidates` | extra candidate file (repeatable) |
| `--no-passive` | do not seed from `passive/output/subdomains.txt` |
| `--wordlist` | extra wordlist file (repeatable) |
| `--no-builtin-wordlist` | use only `--wordlist` files |
| `--no-bruteforce` / `--no-recursion` / `--no-axfr` / `--no-enrich` | skip that step |
| `--no-wildcards` | skip wildcard detection and suppression |
| `--http` | **opt-in** HTTP probe (sends application traffic to the target) |
| `--resolvers` / `--trusted-resolvers` | probe these instead of the curated seed (repeatable) |
| `--strict-foreign` / `--lenient-foreign` | foreign-domain policy (default: abort above 50%) |
| `--timeout` | per-tool wall-clock budget in seconds (default 900) |
| `--output-dir`, `--list`, `-v` | output location, inventory, debug logging |

Exit codes: `0` clean; `1` completed with a failed step (reported per step);
`2` aborted (bad target, missing image, unusable resolver pool, foreign leakage).

---

## Layout

```
active/
├── README.md          <- this file
├── settings.py        paths, limits, ACTIVE_* env overrides
├── tools.py           THE TOOL REGISTRY: images, argument builders, Docker runner
├── resolvers.py       resolver probing + validation (dnspython, no Docker)
├── wordlist.py        pluggable wordlist providers + label validation
├── resolve.py         engines (puredns/shuffledns), bruteforce, recursion
├── axfr.py            per-nameserver zone-transfer attempts + record parsing
├── enrich.py          dnsx record enrichment + opt-in httpx probe
├── pipeline.py        end-to-end runner + CLI + report.json   <- entry point
├── wordlists/
│   └── generic.txt    bundled list: 809 lines -> 755 valid unique labels
├── resolvers/
│   ├── public.txt     curated resolver *candidates* (probed at run time)
│   └── trusted.txt    curated high-trust subset for poisoning validation
└── output/            (gitignored) raw tool output, derived lists, report.json
```

There are deliberately **no per-tool wrapper modules** here (the leftovers were
empty 0-byte stubs and were removed). Unlike the passive stage — where each
source is genuinely a different program with a different output shape — every
active tool is a different *command line over the same registry*, and the stage
never runs a tool "on its own": `puredns` is driven by `resolve.py` with the
resolver pool, candidate file and wildcard settings that `pipeline.py` prepared.
`pipeline.py --list` prints the registry plus the selectable engines.

---

## Requirements

- **The stage image must exist.** All active tools are co-packaged in
  `subdomain_domain_wildcards_image`, built from the stage's own `Dockerfile`:
  `puredns` and `shuffledns` *exec* `massdns`, so the binary has to be on `PATH`
  next to them, and no upstream image ships that combination (plus `dnsgen`,
  which the permutation stage shares). The stage checks for the image before doing
  any work and aborts with the exact build command:

  ```bash
  docker build -t subdomain_domain_wildcards_image \
    service/recon_pipeline/asset_pipelines/subdomain_domain_wildcards/
  ```

- **Docker running.** Resolver validation is pure dnspython (no Docker), but
  every resolution step is a container.
- **Python 3** with `python-dotenv` (via `../config.py`) and **`dnspython`** for
  resolver validation: without it the stage cannot build a trustworthy pool and
  aborts rather than resolving against whatever is handy.

---

## Resolvers: curated seeds are candidates, not truth

Every technique here is only as good as the resolvers it queries, and the
well-known public resolver lists rot fast:

- the list bundled with **massdns** (8,477 addresses, ~2019 vintage) resolved
  **none** of three test names, and a hand-checked sample of 60 was ~88% dead —
  which is why this stage does not use it;
- a **hijacking** resolver (captive portal, ISP search page, ad-blocking
  wildcard) answers names that do not exist, and that failure is worse than slow:
  the wildcard heuristics of `puredns` work by probing a random label and
  expecting NXDOMAIN, so a resolver that answers everything makes the tool
  conclude the entire zone is a wildcard and **discard real results**.

So each candidate must prove both halves of the contract:

1. **Positive** — it resolves a name that definitely exists.
2. **Negative** — it returns a clean NXDOMAIN for a random label under
   `.invalid`, the TLD RFC 6761 reserves and forbids from ever resolving. Any
   answer at all is a fabrication; a slow or failed answer is equally
   disqualifying, because the contract being relied on is *prompt* NXDOMAIN.

Measured on the live `tesla.com` run below: **32 of 45 candidates accepted, 6
trusted, in 10.8 s**. The accepted set is what the tools are pointed at
(`output/resolvers.txt`, `output/resolvers-trusted.txt`); the curated seed files
are never what the tools read, and rejects are written with their reason to
`output/resolvers_rejected.txt`. Availability varies run to run — a later probe
of the same seed accepted 38 of 45 — which is exactly why validation is per-run
rather than baked into the files.

Below `ACTIVE_RESOLVER_MIN_VALID` (3) working resolvers the stage **aborts**:
with an untrustworthy pool, "no such host" and "no working resolver" are
indistinguishable, and a half-resolved list that looks complete is worse than an
obvious failure.

---

## Wordlists

Bruteforce needs two halves: the engine and the list. `wordlist.py` owns the list
and makes sourcing **pluggable** (per `IMPLEMENTATION_PLAN_V2` §S16), so a future
stage registers one function and the bruteforce loop never changes:

```python
register_provider(WordlistProvider("wayback", wayback_words, "..."))
```

Two providers ship: `builtin` (`wordlists/generic.txt`) and `file` (any
`--wordlist`, repeatable). The bundled list is **809 lines, of which 755 are
valid unique labels** — the 54 dropped lines are comments/blanks.

Words are validated *here*, not in the engine, because a wordlist is hostile
input in a practical sense: real lists contain full hostnames, URLs, wildcard
cert names (`*.example.com`), CSV columns and UTF-8 junk, and any of those
reaching a DNS tool is a wasted query or a malformed name. A word must be a
single syntactically valid DNS label (`api`, `api-v2`, `s3` pass; `-api`,
`api-`, `api.example.com`, `*.api`, `api_v2` do not).

---

## Engines

| Engine | Mechanics | When |
|---|---|---|
| `puredns` *(default)* | massdns + heuristic wildcard filtering + trusted-resolver poisoning validation | normal use |
| `shuffledns` | massdns wrapper with its own wildcard checks | fallback when puredns' heuristic disagrees with a target |

Level-1 bruteforce uses `puredns bruteforce` (the tool streams the wordlist, so a
110k-word SecLists list runs without materialising a giant file). Recursion
cannot: `puredns bruteforce` accepts exactly one apex, while recursion
brute-forces *many* parents at once — so parents are expanded to `word.parent`
names locally and resolved in a single `puredns resolve` call. Same query count,
one container instead of one per parent.

Recursion is bounded three ways — `RECURSION_MAX_DEPTH` (2),
`RECURSION_MAX_PARENTS` (25), `RECURSION_WORD_LIMIT` (250) — so it stays a
widening step rather than an open-ended sweep: at most 25 × 250 = 6,250 extra
queries per level.

Only names strictly **below the apex** become recursion parents. The apex itself is
excluded because its direct children are the level-1 candidate set, which step 6
already queried — offering it back would spend a wordlist's worth of requests
re-asking questions that were just answered. Names outside the apex are excluded
because they are not ours to query at all; without that rule the ancestor walk
would climb out of scope one label at a time (`a.other.test` → `other.test`).

---

## Footprint and authorization

The first two steps are DNS queries; the third is not. That distinction is
enforced in code, not just documented:

| Step | Traffic | Default |
|---|---|---|
| resolve / bruteforce / recursion | DNS queries to public resolvers | **on** |
| AXFR | one DNS query per nameserver of the target's own zone | **on** |
| record enrichment | DNS queries | **on** |
| HTTP probe (`httpx`) | **HTTP requests to the target's hosts** | **off** (`--http`) |

AXFR is left on because it is the highest value per query: one query per
nameserver occasionally returns the entire authoritative zone (validated live
against `zonetransfer.me`: **32 names** straight from the zone, no heuristics and
no wildcard false positives). Refusal is the normal outcome and is recorded per
nameserver, so "AXFR found nothing" is always distinguishable from "AXFR was
never attempted".

Hostile-by-design input is handled as such: the nameserver name in an AXFR target
comes from a DNS answer, so it is validated against a strict hostname pattern and
passed as a single `argv` element — no shell is ever involved, which makes
`ns1.example.com; rm -rf /` a parse failure rather than a command.

---

## Output contract

Everything lands in `active/output/` (gitignored — reproduce by re-running):

| File | Contents |
|---|---|
| `resolved.txt` | **consume this**: live, wildcard-filtered, in-scope hostnames |
| `domains.txt` | the in-scope apex — the "domain" layer |
| `candidates.txt` | every candidate name fed to resolution |
| `resolvers.txt` / `resolvers-trusted.txt` | the validated pool the tools were pointed at |
| `resolvers_rejected.txt` | rejected candidates with reasons (auditable) |
| `wildcards.txt` | confirmed wildcard records, merged with the passive stage's |
| `wildcard_suppressed.txt` | names dropped as wildcard noise (auditable) |
| `records.txt` / `records.jsonl` | per-host DNS records (`a, aaaa, cname, ns, mx, txt`) — always includes the **apex** and `_dmarc.<apex>`, where MX/SPF/DMARC live |
| `axfr.txt` | names recovered from a successful zone transfer |
| `foreign.txt` | out-of-scope names seen in the inputs (excluded) |
| `http.jsonl` | opt-in HTTP probe results (**never** merged into `resolved.txt`) |
| `report.json` | counts, timings, per-step status, per-nameserver AXFR outcome |
| `<tool>.log` | per-tool stderr, for when something looks wrong |

Every resolved host is tagged with the step(s) that found it
(`passive`/`bruteforce`/`recursive`/`axfr`). That is not decoration: the wildcard
filter keeps a name outright when two independent steps corroborate it, so
provenance is what stops a genuinely live host that a wildcard happens to explain
from being discarded.

Record enrichment always covers the **apex** and the DMARC policy name
(`_dmarc.<apex>`) alongside the live hosts, even when the live list is empty.
Mail policy (MX, the SPF record inside TXT, DMARC inside `_dmarc` TXT) lives on
the apex, not on subdomains — a measured run (qbsco.net, 2026-09-17) queried
MX/TXT for four subdomains that had none while the M365 MX records answering for
the apex went unasked. An NXDOMAIN `_dmarc` row is kept as an answered-empty
record, so "no DMARC policy" is a recorded fact rather than missing evidence.

### Measured run

`tesla.com`, 2026-09-16, Docker Desktop / Windows, defaults (Docker reuse):

| Step | Candidates | Live hosts | Time |
|---|---|---|---|
| resolve (passive names) | 1,378 | 491 | 5.4 s |
| bruteforce (755 labels) | 755 | 26 | 3.4 s |
| recursive level 1 (25 parents × 250 words) | 6,250 | 0 | 6.2 s |
| AXFR (6 nameservers) | 6 | 0 (all refused) | ~4 s |
| record enrichment | 415 hosts | — | 42.9 s |
| **total** | **8,327** | **494 unique** | **79.2 s** |

Resolvers: 45 probed → 32 valid, 6 trusted (10.8 s). Wildcard DNS: none
(correct: `tesla.com` publishes no wildcard). Foreign names: 0.

A second run of the same configuration 30 minutes later produced the **same 494
hosts** (provenance 492 passive / 25 bruteforce) in 106.2 s. So: the *result* is
stable, the *clock* is not — that run was slower purely on Docker/machine load
(6.2 s of recursion became ~30 s). Treat the timings above as a good case, not a
promise.

Honest caveats:

- **Corroboration is why the per-step numbers sum to more than the total.**
  491 + 26 > 494: 23 hosts were found by both, and provenance records that.
- **Recursive bruteforce returning 0 is a real result, not a failure.** It costs
  ~6 s and is the step that finds unmonitored staging hosts when they exist;
  `tesla.com` fronts its services with Akamai edge names that have no children.
- **Bruteforce yield depends heavily on the wordlist.** 26 of 755 on this
  target; the permutation stage then found 5 *more* names the wordlist did not
  cover (see `../permutation/README.md`), which is the argument for running both.
- **Enrichment dominates the runtime.** 415 hosts × 6 record types took 42.9 s of
  the 79.2 s. Skip it with `--no-enrich` when only the host list is wanted.

---

## Stealth & resilience (spec §5.1)

The stage runs under the shared stealth layer
([`service/recon_pipeline/stealth/`](../../../stealth/README.md)) by default. What that
changes here, concretely:

* **Candidate order is shuffled** (keyed on the target) before resolution, and the work is
  split into **budget-sized batches** with a jittered pause between them, sized so that no
  single resolver sees more unique names than the volume budget allows.
* **The resolver tools are rate-limited** from the same budget when the operator has not set
  `ACTIVE_PUREDNS_RATE_LIMIT` explicitly.
* **AXFR attempts are spaced** (jittered, `ACTIVE_AXFR_SPACING`, default 5s) instead of fired
  back to back.
* **The HTTP probe stops looking like a stock Go client**: `-random-agent=false` plus one
  coherent identity (user agent, Client Hints, `-tlsi` ClientHello). Measured: the CLI's own
  default randomiser sends user agents such as `Firefox/3.6.13` or a `Chrome/134` string for
  `Kubuntu; Linux i686`, and `-tlsi chrome` produces the real Chrome JA4
  (`t13d1516h2_8daaf6152771_...`).
* **Blocks are recorded.** The probe captures response headers (`-irh`), so a challenge or WAF
  block is detected, the host is quarantined, and later steps skip it. Repeated blocks from one
  WAF degrade the run to passive-only.
* **`PASSIVE_ONLY=1` refuses active technique outright** — before Docker, DNS or HTTP.
* Every run records its stealth state under `"stealth"` in `output/report.json` (transport and
  its real capabilities, identities, pacing, the DNS plan, verdicts, quarantine).

### Measured cost

Live run against `tesla.com` (2,083 candidates, 755 brute-force labels):

| | Stealth on | Stealth off |
|---|---|---|
| Wall clock | **193 s** | ~64 s |
| Live hosts | **493** | 493 |
| Deliberate waiting | 48 s (3 resolve batches, 2 pauses) | 0 |
| Names per resolver | up to **111** | ~81 |

Same hosts, ~3× wall clock. The run also reported that the current resolver pool is too small
for the volume budget (111 per resolver against a 60 budget; 23 resolvers or two hourly windows
would be needed) — reported as a note rather than silently exceeded, and never by dropping names.

Stealth can be turned off with `ACTIVE_STEALTH=0` (it then behaves exactly as it did before this
layer existed). The `STEALTH_*` knobs and the evidence behind them are documented in
[`stealth/README.md`](../../../stealth/README.md).

## Settings

Every knob reads an `ACTIVE_*` environment variable (see `settings.py` for the
full table with defaults). The ones that change behaviour most:

| Variable | Default | Effect |
|---|---|---|
| `ACTIVE_TIMEOUT` | 900 | per-tool wall-clock budget (s) |
| `ACTIVE_BRUTEFORCE` / `ACTIVE_RECURSION` / `ACTIVE_AXFR` | 1 | enable/disable a step |
| `ACTIVE_RECURSION_MAX_PARENTS` | 25 | ceiling on recursive passes |
| `ACTIVE_RECURSION_WORD_LIMIT` | 250 | words per recursive pass |
| `ACTIVE_AXFR_MAX_NAMESERVERS` | 6 | nameservers tried per zone |
| `ACTIVE_RESOLVER_MIN_VALID` | 3 | abort threshold for the pool |
| `ACTIVE_HTTP` | 0 | opt-in HTTP probe |
| `SUBDW_IMAGE` | `subdomain_domain_wildcards_image` | image tag |

The wildcard tunables are **imported from the passive stage on purpose**: the two
stages must agree on what a wildcard is, or this stage would "rediscover" every
wildcard the passive stage already recorded — or disagree about which names it
explains.

---

## Testing

Hermetic — no Docker, no DNS, no dependence on `output/`:

```bash
python -m pytest tests/recon/test_active_resolvers.py \
                 tests/recon/test_active_wordlist.py \
                 tests/recon/test_active_tools.py \
                 tests/recon/test_active_axfr.py \
                 tests/recon/test_active_pipeline.py -q     # 113 tests
```

Covers the observable contract only: which resolvers are admitted and why, word
normalisation, argument construction for every tool (including the timeout and
container-cleanup path), AXFR record parsing with hostile nameserver input, and
the full stage contract with a fake engine — pool preparation, step ordering,
provenance, wildcard suppression, and the abort paths.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `image ... not found` | Build it — the message contains the exact `docker build` line. |
| Stage aborts: too few working resolvers | The curated seed is stale for your network, or outbound DNS is blocked. Point `--resolvers` at your own list. |
| Every candidate looks unresolvable | A hijacking resolver slipped in, or the pool is dead. Check `resolvers_rejected.txt` for the rejection reasons. |
| A name you know exists is missing | Check `wildcard_suppressed.txt`; if it is there, the parent is a confirmed wildcard and the name was not corroborated. |
| `puredns` exits non-zero | `output/puredns-*.log` has its stderr. A missing resolver file is the usual cause when paths were overridden. |
| Bruteforce found little | The wordlist is the ceiling. Add SecLists via `--wordlist`, and let the permutation stage cover target-specific naming. |
| Recursion finds nothing | Expected on CDN-fronted targets. Lower `ACTIVE_RECURSION_MAX_PARENTS` to keep the cost down. |
| Container left running after Ctrl-C | `docker rm -f $(docker ps -q --filter ancestor=subdomain_domain_wildcards_image)`; the pipeline removes its own containers on timeout, but an interrupted parent cannot. |

## Related

- `../passive/README.md` — the upstream stage that supplies candidates.
- `../permutation/README.md` — the downstream stage that consumes `resolved.txt`.
- `../README.md` — the whole pipeline, the stage image, and how to run all three.
- `../commands.txt` — raw per-tool Docker commands.
- `docs/recon_docs/IMPLEMENTATION_PLAN_V2.md` — stage S16 (DNS brute force +
  resolver handling), whose *techniques* this stage implements ahead of the
  graph-based design; its implementation-status section tracks the rest.
