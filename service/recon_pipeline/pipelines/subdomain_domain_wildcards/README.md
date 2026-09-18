# `subdomain_domain_wildcards`

The subdomain / domain / wildcard asset pipeline: three independently runnable
stages that together produce the live-host inventory the rest of the recon
pipeline works from.

```
passive        OSINT + certificate transparency      -> known names
   |           (no traffic to the target)
   v
active         DNS resolution, wordlist bruteforce,  -> live hosts + records
   |           bounded recursion, AXFR attempts
   v
permutation    names derived from the names above    -> more live hosts
```

| Stage | Entry point | Consumes | Produces |
|---|---|---|---|
| **passive** | `python -m ...passive.pipeline` | the target, third-party data | `passive/output/subdomains.txt` |
| **active** | `python -m ...active.pipeline` | passive's names | `active/output/resolved.txt` |
| **permutation** | `python -m ...permutation.pipeline` | active's + passive's names | `permutation/output/resolved.txt` |

Each stage owns its own `output/` directory, its own `report.json`, its own
README with measured numbers, and can be run on its own. The orchestrator adds
only what belongs to the whole pipeline.

---

## Quick start

```bash
# from the project root; imports are absolute
python -m service.recon_pipeline.pipelines.subdomain_domain_wildcards.main -t example.com
```

That runs all three stages in order and writes:

- **`output/live_hosts.txt`** — the deduplicated union of every live host the
  stages found. This is what a downstream consumer should read.
- **`output/summary.json`** — per-stage status, counts and timings, so a partial
  run is legible without opening three reports.

| Flag | Purpose |
|---|---|
| `-t, --target` | apex domain (default: `TARGET` from `.env`, else `qbsco.net`) |
| `--stages` | comma-separated stages to run, in order (default: all three) |
| `--engine` | resolution engine for active + permutation (`puredns` default) |
| `--wordlist` | extra bruteforce wordlist (repeatable) |
| `--no-bruteforce` / `--no-recursion` / `--no-axfr` | skip that active step |
| `--http` | enable the opt-in HTTP probe (sends application traffic) |
| `--max-candidates` | cap on generated permutation candidates |
| `--resolvers` / `--trusted-resolvers` | probe these instead of the curated seed |
| `--timeout` | per-tool wall-clock budget in seconds (default 900) |
| `--output-dir`, `--list`, `-v` | union output location, inventory, debug logging |

A useful pattern: run the stages separately when iterating, then the orchestrator
(or `--stages active,permutation`) to refresh the union.

```bash
# refresh only the parts whose inputs changed
python -m ...main -t example.com --stages active,permutation
```

**One stage failing does not stop the pipeline.** A failed stage is recorded and
skipped, and the exit code reflects it — a partial union is still useful, and
re-running everything to recover one failed stage is wasteful.

---

## The three asset layers

The pipeline's name is the contract; each layer is written by the stage that can
observe it:

| Layer | Artifact | Written by | Meaning |
|---|---|---|---|
| **subdomain** | `passive/output/subdomains.txt`, `active/output/resolved.txt`, `permutation/output/resolved.txt`, `output/live_hosts.txt` | all stages | hostnames under the apex |
| **domain** | `passive/output/domains.txt`, `active/output/domains.txt` | passive, active | the in-scope apex itself |
| **wildcard** | `passive/output/wildcards.txt`, `active/output/wildcards.txt`, `permutation/output/wildcards.txt` | all stages | DNS wildcard records (`*.parent`) that would otherwise flood the graph with false positives |

Wildcard handling is one implementation used by all three stages
(`passive/wildcard.py`): the active and permutation stages import the passive
stage's definition and tunables on purpose, so no stage can disagree about what a
wildcard is or which names it explains. Every suppressed name is written to
`wildcard_suppressed.txt` — suppression is never silent.

---

## Stealth and resilience (spec §5.1)

All three stages share one stealth layer at
[`service/recon_pipeline/platform/stealth/`](../../stealth/README.md): coherent per-host browser
identities, per-host pacing with jitter and backoff, WAF/challenge detection, persistent
quarantine (escalating to a passive-only run), and a per-resolver DNS volume budget. The active
and permutation stages apply it to every resolve, brute force, zone-transfer sequence and HTTP
probe; the passive stage is unchanged (it never touches the target directly).

It is on by default. `PASSIVE_ONLY=1` refuses all active technique; `ACTIVE_STEALTH=0` reverts to
the previous unshaped behaviour. Each stage's `output/report.json` carries a `"stealth"` block
saying which transport actually ran, and what the target did about it.

The design, the measurements behind it (real Chrome JA4 from `httpx -tlsi chrome`, the CLI's
header-order limitation, the volume thresholds) and the honest limits are all in
[`stealth/README.md`](../../stealth/README.md).

## Requirements

- **Docker.** The passive stage pulls upstream images per tool; the active and
  permutation stages need the locally built all-in-one image:

  ```bash
  docker build -t subdomain_domain_wildcards_image \
    service/recon_pipeline/pipelines/subdomain_domain_wildcards/
  ```

  The Dockerfile builds all 11 tools from source/releases and **fails the build if
  any of them is missing or broken** (build-time smoke test). `amass` is pinned to
  v4.2.0 on purpose: v5 removed the streaming graph-relations output the passive
  stage parses.

- **Python 3** with `python-dotenv` (via `../config.py`), **`dnspython`** (active
  resolver validation + all wildcard probing) and **`requests`** (passive's
  keyless HTTP sources). All three are already used elsewhere in the repo.

- **`.env`** at the project root with `TARGET=<domain>`, plus optional keys:
  `CHAOS_KEY` (the only key any source needs) and the amass datasource keys
  (`SHODAN_KEY`, `CENSYS_KEY`, `VIRUS_TOTAL_KEY`, `SECURITY_TRAILS_KEY`,
  `GITHUB_KEY`) if you provision amass's config. No key is needed by the active or
  permutation stages.

- Outbound Docker networking. On Git Bash / Windows the stages set
  `MSYS_NO_PATHCONV=1` for their own calls; ad-hoc `docker run` commands that mount
  container paths need it too (see `commands.txt`).

---

## Layout

```
subdomain_domain_wildcards/
├── README.md            <- this file
├── env.py               shared env parsing (env_flag / env_int)
├── main.py              orchestrator: runs the stages, writes the union + summary
├── Dockerfile           the all-in-one tool image (11 tools, smoke-tested)
├── commands.txt         raw per-tool Docker commands for every bundled tool
├── passive/             stage 1 — see passive/README.md
├── active/              stage 2 — see active/README.md
├── permutation/         stage 3 — see permutation/README.md
└── output/              (gitignored) live_hosts.txt + summary.json
```

---

## Measured end-to-end run

`tesla.com`, 2026-09-16, Docker Desktop / Windows, all defaults:

| Stage | Time | Result |
|---|---|---|
| passive | 316.7 s | 1,378 unique subdomains from 7/7 sources |
| active | 79.2 s | 494 live hosts from 8,327 candidates (491 passive, 26 bruteforce, 0 recursion, 0 AXFR; all 6 zones refused), 415 hosts enriched with records |
| permutation | 52.1 s | 5 genuinely new live hosts from 100,000 candidates (111,613 generated) |
| **union** | **~448 s** | **499 unique live hosts** |

Re-running `--stages active,permutation` reproduced **the same 499 hosts** (`active
∪ permutation`, verified against the union artifact) — the per-stage yields are
stable, while the wall-clock numbers roughly doubled on a loaded machine. Each
stage's README records both runs.

The three stages find materially different things, which is the argument for
running all of them: passive reaches names nobody published but that exist in DNS,
bruteforce reaches names in the shared vocabulary, and permutation reaches
target-specific variations of names that already exist (`origin-pay` from
`origin-*`, `xai-api`). Each stage's README documents its own caveats — resolver
and source availability vary between runs, so treat these as orders of magnitude,
not fixed yields.

---

## Testing

All three stages are covered by hermetic tests: **no Docker, no DNS, no network,
and no dependence on whatever happens to sit in `output/`** (which is why they can
run in CI and why a stale artifact cannot make them pass).

```bash
python -m pytest tests/recon -q          # the whole recon suite (972 tests)
```

`tests/recon/test_repository.py` is deliberately **not** part of that count: it is
a pre-existing standalone integration *script* for the Neo4j recon graph (it
imports `neo4j` at module level and defines a `main()`, not test functions), so
pytest collects it without running it. Run it directly against a live instance:

```bash
docker compose up -d neo4j
python tests/recon/test_repository.py
```

## Related

- [`docs/README.md`](../../../../docs/README.md) — the documentation index: which
  doc is authoritative for what.
- `docs/recon_docs/recon.md` — the spec (wildcard detection as a mandatory layer,
  provenance for corroboration scoring). It is **intent**: read the plan's status
  section alongside it.
- `docs/recon_docs/IMPLEMENTATION_PLAN.md` / `IMPLEMENTATION_PLAN_V2.md` — the
  staged plan this pipeline follows (pluggable wordlist providers, validated
  resolver pools, wildcard reuse). Each carries an **implementation status**
  section stating what exists; this pipeline is the part that does, and it is
  deliberately not wired into the graph yet.
- `commands.txt` — how to reproduce any single tool by hand.
