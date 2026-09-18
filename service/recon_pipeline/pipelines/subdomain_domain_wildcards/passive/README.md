# Passive Subdomain Enumeration

Passive stage of the `subdomain_domain_wildcards` asset pipeline: enumerates
subdomains of a configured target using OSINT / certificate-transparency sources
only — no traffic to the target's own web surface. Results feed the `active/` and
`permutation/` stages.

The stage produces three asset classes, one per word in the pipeline's name:

| Layer | Output | Meaning |
|---|---|---|
| **subdomain** | `output/subdomains.txt` | normalized, deduplicated subdomains — the artifact downstream stages consume |
| **domain** | `output/domains.txt` | the in-scope apex itself |
| **wildcard** | `output/wildcards.txt` | DNS wildcard records (`*.parent`) that would otherwise flood the graph with false positives |

Run it as a module **from the project root** (imports are absolute):

```bash
python -m service.recon_pipeline.pipelines.subdomain_domain_wildcards.passive.pipeline
```

That one command runs every source, normalizes and merges with provenance,
detects wildcard DNS, suppresses wildcard noise, and writes `passive/output/`.

---

## Quick start

```bash
# everything, default target from .env (TARGET) or qbsco.net
python -m ...passive.pipeline

# a specific target, with a per-source timeout
python -m ...passive.pipeline -t example.com --timeout 300

# fast run: keyless sources only, no Docker needed at all
python -m ...passive.pipeline -t example.com --only crtsh,wayback

# see what is available
python -m ...passive.pipeline --list
```

| Flag | Purpose |
|---|---|
| `-t, --target` | apex domain (default: `TARGET` from `.env`, else `qbsco.net`) |
| `--only` / `--skip` | comma-separated source selectors |
| `--timeout` | per-source wall-clock budget in seconds (default 900) |
| `--no-wildcards` | skip DNS wildcard detection and suppression |
| `--strict-foreign` | abort on a *single* out-of-scope host (CI / paranoia) |
| `--lenient-foreign` | never abort on out-of-scope hosts; only record and warn |
| `--output-dir` | write outputs somewhere other than `passive/output/` |
| `--list` | list the registered sources |
| `-v, --verbose` | debug logging |

Exit codes: `0` clean; `1` completed but not cleanly (a source failed, or every
source failed); `2` aborted (bad target, or disqualifying foreign-domain
leakage).

---

## Layout

```
passive/
├── README.md            <- this file
├── settings.py          paths, timeouts, wildcard tunables (env-overridable)
├── sources.py           THE SOURCE REGISTRY — add coverage here, not in wrappers
├── docker_tool.py       docker run plumbing: timeouts, cleanup, log capture
├── httpget.py           resilient GET for the keyless HTTP sources
├── normalize.py         canonicalization, validation, provenance merge, amass relations
├── wildcard.py          DNS wildcard detection + wildcard-flood suppression
├── pipeline.py          end-to-end stage runner + CLI + report.json   <- entry point
├── crtsh.py             source: Certificate Transparency (keyless, no image)
├── wayback.py           source: archived URLs naming hosts (keyless, no image)
├── subfinder.py         source: 30+ passive sources (Docker)
├── assetfinder.py       source: 7 CT/web sources (Docker)
├── findomain.py         source: 54 CT/API sources (Docker)
├── chaos.py             source: ProjectDiscovery Chaos dataset (Docker, needs CHAOS_KEY)
├── amass.py             source: graph relations, not a host list (Docker)
├── config/              (gitignored) amass config.yaml + datasources.yaml (API keys)
└── output/              (gitignored) raw per-source files + derived lists + report.json
```

Each per-tool module is a **thin facade** over the registry — it exists so a
single source can be run or debugged in isolation, and all of them share one
implementation in `sources.py`:

```bash
python -m ...passive.subfinder          # one tool, prints where it wrote
python -m ...passive.chaos
python -m ...passive.amass
```

> Historical note: the chaos wrapper was `chaos-client.py`. Python module names
> cannot contain a hyphen, so it is now `chaos.py` (the *image* is still
> `projectdiscovery/chaos-client`). Update any
> `python -m ...passive.chaos-client` invocation.

---

## Requirements

- **Docker running** for the Docker-backed sources. Images are pulled on first
  use: `projectdiscovery/subfinder:v2.14.0`, `lotuseatersec/assetfinder:latest`,
  `edu4rdshl/findomain:latest`, `projectdiscovery/chaos-client:latest`,
  `caffix/amass` (v4.2.0 — see `../Dockerfile` for why v4 is pinned).
- **Python 3** with `python-dotenv` (via `../config.py`), plus `requests` and
  `dnspython` for the keyless HTTP sources and wildcard detection.
- Project-root `.env` with `TARGET=<domain>` and any optional keys (`CHAOS_KEY`,
  and the amass datasource keys — see *amass notes*).

`crtsh` and `wayback` need **neither Docker nor an API key**, so the stage still
works with no Docker at all:

```bash
python -m ...passive.pipeline -t example.com --only crtsh,wayback
```

## Target configuration

The target comes from `service/recon_pipeline/platform/common/config.py`:

- `.env` `TARGET=...` takes precedence,
- fallback default is `qbsco.net`.

`--target` overrides both, and every wrapper's `run(domain: str = TARGET)`
accepts an explicit domain, e.g. `subfinder.run("example.com")`.

> **Watch out:** a stale `TARGET` in `.env` makes every tool silently enumerate
> the wrong domain. The stage now detects that: hosts outside the target go to
> `output/foreign.txt` and are reported, and when they dominate the results the
> run **aborts** instead of emitting wrong-domain data. Check
> `grep '^TARGET' .env` before trusting results.

---

## Sources and measured yields

Redundancy is deliberate: CT-log harvesters disagree constantly (rate limits,
source outages, differing retention), and a name that two independent sources
report is exactly the corroboration the wildcard layer relies on.

| Source | Flavour | What it adds |
|---|---|---|
| `subfinder` | Docker | 30+ passive sources; usually the highest yield |
| `crtsh` | keyless HTTP | Certificate Transparency logs, queried directly |
| `chaos` | Docker (key) | ProjectDiscovery Chaos dataset |
| `assetfinder` | Docker | 7 CT/web sources |
| `findomain` | Docker | 54 CT/API sources queried in parallel |
| `wayback` | keyless HTTP | hosts named in archived URLs (historical surface) |
| `amass` | Docker | graph relations (MX/NS/CNAME/ASN); hosts are extracted from them |

Measured on `tesla.com` (2026-09-16, Docker Desktop / Windows, per-source cap
300 s, amass cap 3 min):

| Source | Runtime | Hosts contributed |
|---|---|---|
| subfinder | 16.7 s | 1049 |
| crtsh | 8.6 s | 534 |
| chaos | 1.9 s | 883 |
| assetfinder | 7.9 s | 59 |
| findomain | 30.0 s | 528 |
| wayback | 10.1 s | 1 |
| amass | 218.5 s | 55 (from 58 relations) |
| **union** | **316.7 s total** | **1378 unique** |

On the small target `qbsco.net`: crtsh 11, subfinder 12, union 12.

Two honest caveats from those numbers:

- **Per-source yields vary run to run.** findomain returned 91 hosts on one
  `tesla.com` run and 528 on the next; that is upstream source availability, not
  pipeline nondeterminism.
- **wayback is low-value on very large targets.** Its CDX row budget is consumed
  by the apex and `www` (49,889 of the first 50,000 rows on `tesla.com`), so it
  adds ~1 host there. It stays useful for medium/small targets and for historical
  hosts that no longer hold a certificate. Row cap: `wayback.DEFAULT_LIMIT`.

---

## Output contract

Everything lands in `passive/output/` (gitignored — reproduce it by re-running):

| File | Contents |
|---|---|
| `<source>.txt` | raw per-source output, exactly as the tool printed it |
| `<source>.log` | per-tool stderr (Docker sources) |
| `domains.txt` | the in-scope apex |
| `subdomains.txt` | **normalized, deduplicated subdomains — consume this** |
| `wildcards.txt` | confirmed wildcard records (`*.parent`) |
| `wildcard_suppressed.txt` | names dropped as wildcard noise (auditable) |
| `foreign.txt` | out-of-scope hosts found in a source's output |
| `report.json` | counts, timings, per-source status, wildcards, suppression |

`report.json` is the machine-readable record of the run:

```json
{
  "target": "tesla.com",
  "ok": true,
  "foreign_abort": false,
  "counts": {
    "sources_selected": 7, "sources_succeeded": 7, "sources_failed": 0,
    "amass_relations": 58, "subdomains_raw": 1378, "subdomains": 1378,
    "wildcards": 0, "wildcard_suppressed": 0, "foreign": 1
  },
  "sources": [{"name": "subfinder", "ok": true, "hosts": 1049, "seconds": 16.67}]
}
```

Two guarantees worth relying on:

1. **Only sources that succeeded in this run are merged.** A leftover file from
   an earlier run cannot contaminate the output, and `--only crtsh` really means
   "crtsh only".
2. **Out-of-scope hosts never reach `subdomains.txt`.** They are reported in
   `foreign.txt` and counted in the report.

### Normalization rules

Applied to every source's output before merging (`normalize.py`):

- CRLF stripped; blank lines dropped.
- lowercased; `*.` wildcard prefix stripped; trailing root dot stripped.
- URLs reduced to their host; `host:port` and `user@host` handled.
- IDN → punycode (`münchen.example.com` → `xn--mnchen-3ya.example.com`).
- rejected as junk: IP literals, single-label names, labels > 63 chars, names
  > 253 chars, leading/trailing hyphens, empty labels, and amass relation lines.
- the **apex is excluded** from `subdomains.txt` (it is carried by `domains.txt`);
  names outside `*.apex` are foreign (see below).
- deduplicated across every source, keeping the set of reporting sources as
  **provenance** — which is what lets the wildcard layer tell a real host from a
  wildcard artifact.

---

## Wildcard detection

`recon.md` §2 calls robust wildcard detection *mandatory to avoid false-positive
floods*, and it is right: a published `*.example.com` makes every random label
resolve, so CT logs and list-based sources alike return thousands of hosts that
are not assets at all.

**How it works** (`wildcard.py`):

1. Candidate parents are the apex plus every parent with at least
   `WILDCARD_MIN_CHILDREN` (4) discovered children — 68 parents on `tesla.com`.
2. Each candidate is probed with `WILDCARD_SAMPLES` (3) random 16-character
   labels. A parent is a wildcard only when **every** sample resolves and all of
   them return the **same** answer set (A, AAAA and CNAME are all considered, so
   wildcard *CNAMEs* are caught too).
3. A name whose **immediate** parent is a confirmed wildcard is suppressed only
   when all of: it is reported by fewer than 2 sources, it resolves, and its
   answers are a subset of the wildcard's answers.

**Why suppression is deliberately conservative.** A name survives when it is
corroborated by two or more sources, when it resolves to something the wildcard
does not answer, or when it does not resolve at all. In other words it is only
discarded when nothing distinguishes it from a random label, and every discarded
name is still written to `wildcard_suppressed.txt`. Detection is *sampling*, not
exhaustive — a false positive needs three random labels to coincidentally exist.

**Bounded by construction.** All DNS access goes through one choke point that
enforces both a query cap (`WILDCARD_MAX_QUERIES`, 300) and a wall-clock budget
(`WILDCARD_MAX_SECONDS`, 120). A cap alone is not enough — a slow or blackholed
resolver could stretch 300 queries into hours. When either limit is hit the
remaining lookups return "no answers", which fails **open**: nothing is
suppressed without a confirmed verdict, and a warning is logged.

**Graceful degradation.** With dnspython missing or DNS unreachable, no wildcard
is detected and nothing is suppressed; the stage never fails because of this
layer. Skip it entirely with `--no-wildcards` or `PASSIVE_WILDCARD_PROBE=0`.

Live validation (2026-09-16):

```
github.io    -> *.github.io        tumblr.com   -> *.tumblr.com
netlify.app  -> *.netlify.app      tesla.com    -> (none)   <- correct
herokuapp.com / vercel.app / pages.dev -> (none)
```

---

## Foreign-domain leakage policy

A host outside the apex in a source's output is either a real problem (a stale
`TARGET` enumerating an entirely different domain) or a tool quirk (a lookalike
such as `one-tesla.com`, which `assetfinder` returns for `tesla.com`). Both get
reported; only the first should throw the run away.

| Policy | Behaviour |
|---|---|
| `threshold` *(default)* | record and warn; abort only if out-of-scope hosts are ≥ 50% of everything the sources returned |
| `strict` | abort on a single out-of-scope host |
| `lenient` | never abort; record and warn |

On abort the derived output is **not** written, but `foreign.txt` and
`report.json` are, so the cause is diagnosable without re-reading raw files.

Measured on `tesla.com`: 1 out-of-scope host out of 1,379 → recorded, run
completed, exit 0.

---

## Why the passive stage does not recurse

The ASM spec's recursion engine ("new findings become new seeds until nothing
new comes out") applies to **active** discovery, where candidate generation is
level-by-level (bruteforce and permutation expand one apex into candidates,
then their results into more candidates). Passive sources are a different
shape, and the difference is verifiable:

- **One query, whole subtree.** `crt.sh` is queried with `q=%.apex` — the `%`
  suffix wildcard matches every label depth at once. Wayback uses
  `matchType=domain`, which the CDX API defines as "this domain and all
  subdomains". The Docker tools (subfinder, assetfinder, findomain, chaos,
  amass) likewise take one `-d <apex>` and return whatever their datasets hold
  beneath it. Measured on `tesla.com`: the single-pass passive output contains
  depth-6 names (e.g. `account.apf-api.prd.vn.cloud.tesla.com`) whose
  intermediate parents were never enumerated.
- **Re-seeding finds nothing new — measured.** Feeding the deepest
  "orphan" names from a real run back into crt.sh and Wayback with the same
  query shapes returned **0 names outside the apex result set**. Their
  subtrees were already covered; a passive recursion loop would only re-query
  subsets of a set we already hold, at API rate-limit cost.
- **Where recursion does live:** the active stage recurses over
  resolved-host-derived parents (`active/README.md`), and the spec's
  cross-source, score-gated loop is a graph-layer concern (spec §5.2, S10),
  not a stage concern.

The sources query shapes are pinned by tests (`test_crtsh_query_is_subtree_wide`,
`test_wayback_query_is_subtree_wide`,
`test_every_source_takes_exactly_one_seed_domain`) so a future "optimisation"
that narrows a query to a single host fails loudly instead of silently costing
the stage its depth coverage.

---

## amass notes

`amass.py` mounts `config/` read-only at `/home/user/.config/amass` inside the
container and passes `-config /home/user/.config/amass/config.yaml`.

**Critical:** `config/config.yaml` must reference the datasources file by
**absolute container path**:

```yaml
options:
  datasources: "/home/user/.config/amass/datasources.yaml"
```

amass resolves that path relative to its **own working directory** (`/` in the
`caffix/amass` image), not relative to the config file. A bare
`datasources.yaml` fails *silently* — the run exits 0 and outputs only
keyless-source data (3 sources instead of ~50). Symptom: verbose output lists
only keyless sources (Sublist3rAPI, RapidDNS, PKey...).

If `config.yaml` is **absent**, the wrapper omits `-config` entirely rather than
passing a dangling path: amass exits 1 ("failed to load the main configuration
file") when pointed at a missing one, and a thin amass run beats a failed one.
Either way a warning is logged.

`amass.txt` holds one graph relation per line, e.g.:

```
tesla.com (FQDN) --> mx_record --> tesla-com.mail.protection.outlook.com (FQDN)
autodiscover.tesla.com (FQDN) --> cname_record --> autodiscover.outlook.com (FQDN)
```

That file is **never merged as a host list**. Hosts appearing on either side of a
relation are extracted instead — 55 of the 1,378 `tesla.com` subdomains came from
amass relations alone, which is why amass is worth running even though it prints
no plain subdomain list.

amass gets its own `-timeout` (minutes, `PASSIVE_AMASS_TIMEOUT_MINUTES`, default
5), deliberately shorter than the container timeout: amass streams relations to a
buffered stdout and only flushes reliably on a clean exit, so a container kill
would discard the run.

Sanity check that sources load (expect ~50 "Querying ..." lines):

```bash
# from the project root - verified on Git Bash / Windows
MSYS_NO_PATHCONV=1 docker run --rm --dns 8.8.8.8 --dns 1.1.1.1 \
  -v "$(pwd -W)/service/recon_pipeline/pipelines/subdomain_domain_wildcards/passive/config:/home/user/.config/amass:ro" \
  --entrypoint /bin/sh caffix/amass -c "ls /home/user/.config/amass/"
```

On macOS/Linux `$(pwd -W)` is just `$(pwd)`, and `MSYS_NO_PATHCONV=1` is
unnecessary (the pipeline sets it for its own calls on Windows).

The `caffix/amass` image's entrypoint is `/bin/amass`, so ad-hoc commands need
`--entrypoint /bin/sh` (see Troubleshooting).

---

## Testing / verification

The stage is covered by hermetic tests — no Docker, no network, and no dependence
on whatever happens to sit in `output/`:

```bash
python -m pytest tests/recon/test_passive_normalize.py \
                 tests/recon/test_passive_wildcard.py \
                 tests/recon/test_passive_sources.py \
                 tests/recon/test_passive_pipeline.py -q
```

117 tests: canonicalization edge cases, provenance merge, foreign handling for
every policy, amass relation parsing, Docker argument construction and
timeout/cleanup behaviour, crt.sh and Wayback response parsing (including
truncated and non-JSON bodies), every wildcard detect/suppress branch, and the
full output contract end to end.

For a live run, beyond reading `report.json`:

1. **Leakage check** — `foreign.txt` should be empty or hold a handful of
   lookalikes; a large file means a stale `TARGET`:

   ```bash
   wc -l service/recon_pipeline/pipelines/subdomain_domain_wildcards/passive/output/foreign.txt
   ```

2. **Ground-truth cross-check** against crt.sh — the `crtsh` source should be a
   superset of this:

   ```bash
   curl -s --max-time 60 "https://crt.sh/?q=%25.example.com&output=json" \
     | python -c "import json,sys; d=json.load(sys.stdin); n=set(); [n.update(x['name_value'].split('\n')) for x in d]; print(len(n))"
   ```

3. **Liveness** — passive lists contain historical names that no longer resolve;
   that is expected. Resolve candidates before acting on them:

   ```python
   import socket
   socket.gethostbyname("www.example.com")   # raises OSError if dead
   ```

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| A source reports a timeout / `exit code 124` | It hit `--timeout`. Raise it (`--timeout 1800`) or `--skip` the source. The container is removed automatically; nothing is left running. |
| Orphaned containers accumulate | `docker rm -f $(docker ps -q --filter ancestor=<image>)`. The pipeline removes its own containers on timeout, but containers launched by hand (or by an older revision) can survive. |
| `Docker is not available`, every Docker source skipped | Start Docker Desktop, or run keyless-only with `--only crtsh,wayback`. |
| amass output too thin / only 2–3 relations | `config.yaml` datasources path — must be absolute (see *amass notes*). |
| amass exits 1 with "failed to load the main configuration file" | Old behaviour when `config.yaml` was missing. The wrapper now omits `-config` instead. |
| `exec: "C:/Program Files/Git/usr/bin/sh"` from Git Bash | Git Bash mangles absolute container paths. The pipeline sets `MSYS_NO_PATHCONV=1` for its own calls; prefix ad-hoc commands with it. |
| chaos reports nothing | Domain not in the Chaos dataset (exit 0, not an error). Verify the key against a known-populated domain, e.g. `hackerone.com`. |
| chaos is skipped | `CHAOS_KEY` is not set. A missing optional key skips the source; it never fails the run. |
| Results contain the wrong domain | Stale `TARGET` in `.env`. The stage aborts on systemic leakage — check `foreign.txt`. |
| `-v "$PWD:/workspace"` fails to mount on Windows | Use `-v "$(pwd -W):/workspace"` (Git Bash) or `MSYS_NO_PATHCONV=1`. |
| A subdomain that `dig` resolves is missing | It may have been suppressed as wildcard noise — check `wildcard_suppressed.txt` and `wildcards.txt`. |

## Related

- `../commands.txt` — raw per-tool docker commands for the all-in-one
  `subdomain_domain_wildcards_image` (built from `../Dockerfile`), the active &
  permutation stages, and one-liner chains.
- `../active/`, `../permutation/` — downstream stages consuming these outputs.
- `docs/recon_docs/IMPLEMENTATION_PLAN.md` §5 (S3 normalization, S5 crt.sh +
  wildcard detection) — the plan stages this stage implements. The plan is intent,
  not inventory: its implementation-status section is the current picture.
- `docs/README.md` — the documentation index.
- `docs/codebase/ARCHITECTURE.md` — how this stage fits the wider system.
