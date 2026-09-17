# Permutation Subdomain Discovery

Permutation stage of the `subdomain_domain_wildcards` asset pipeline: derives
**new** candidate hostnames from names that already exist, then hands them to the
active stage's resolution engine.

The premise is that naming is systematic. Given `api.example.com`, the names that
matter next are `api-v2`, `api-dev`, `api2`, `staging-api`, `api.staging` — and
`dnsgen` derives exactly those by recombining the words and separators it finds
in the known set. This stage finds names that neither passive enumeration (nobody
published them) nor a generic wordlist (the vocabulary is target-specific) can
reach.

```
known hosts -> generate candidates (dnsgen) -> resolve (active stage's engine)
            -> wildcard filter -> permutation/output/
```

```bash
# from the project root (imports are absolute)
python -m service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.permutation.pipeline
```

---

## Quick start

```bash
# the default: seed from active + passive output, generate, resolve, filter
python -m ...permutation.pipeline -t example.com

# candidates only, no resolution (and no Docker lookups beyond the generator)
python -m ...permutation.pipeline -t example.com --max-candidates 0

# seed from an explicit file instead of the other stages' output
python -m ...permutation.pipeline -t example.com --no-active --no-passive \
    --known-file my-hosts.txt

# generate only, as a library-style one-liner
python -m ...permutation.dnsgen -t example.com

python -m ...permutation.pipeline --list      # generators + engines
```

| Flag | Purpose |
|---|---|
| `-t, --target` | apex domain (default: `TARGET` from `.env`, else `qbsco.net`) |
| `--generator` | candidate generator (default `dnsgen`) |
| `--engine` | resolution engine — the active stage's (`puredns` default) |
| `--known-file` | extra known-host file (repeatable) |
| `--no-active` / `--no-passive` | do not seed from that stage's output |
| `--max-candidates` | cap on generated candidates (default 100,000; `0` = no cap) |
| `--no-wildcards` | skip wildcard detection and suppression |
| `--no-reuse-resolvers` | re-probe resolvers instead of reusing the active pool |
| `--resolvers` / `--trusted-resolvers` | probe these instead of the curated seed |
| `--timeout`, `--output-dir`, `--list`, `-v` | as in the other stages |

Exit codes: `0` clean; `1` the generator failed; `2` aborted (bad target, missing
image, unusable resolver pool, or no known hosts to permute).

---

## Layout

```
permutation/
├── README.md          <- this file
├── settings.py        paths, caps, PERMUTATION_* env overrides
├── generate.py        generator registry, normalisation, novelty, caps
├── dnsgen.py          thin facade: generate candidates and stop
├── pipeline.py        end-to-end runner + CLI + report.json   <- entry point
└── output/            (gitignored) raw generation, candidates, resolved hosts
```

The stage owns **generation and nothing else**. Resolution is delegated to the
active stage's engine and wildcard handling to the passive stage's detector, so
all three stages share one definition of "resolves" and one definition of
"wildcard". The validated resolver pool the active stage wrote is reused by
default rather than re-probed (it is copied into *this* stage's output directory,
because only the mounted directory is visible inside the container).

There is **no foreign-domain abort here, on purpose**: this stage cannot import a
stale target the way the other two can. Its inputs are names already normalized
into the apex's scope and candidates it synthesises from those names, which are
re-normalised against the apex before anything is queried. A stale known-host
file yields *no* known hosts, which is reported as an explicit fatal condition.

---

## What is new, and what is not

**Novelty is judged against every known host.** This is the stage's one
non-obvious correctness rule, and getting it wrong is easy: `dnsgen` is handed
only the shallowest `MAX_KNOWN` (100) hosts, because its output grows
combinatorially in its input — so filtering candidates against *that* slice
instead of the full known set lets the stage re-discover names the active stage
already found and report them as its own.

That is exactly what happened in this stage's first live runs, and the numbers
were convincing: on `tesla.com` the stage reported "9 new live hosts" from a
100,000-candidate pool, and **all 9 were already sitting in
`active/output/resolved.txt`**. The novelty filter now runs against the whole
known set (1,380 hosts on that target) with the generator input still capped at
100, and the same configuration afterwards reported **5 genuinely new hosts**
that appear in neither the active nor the passive output:

```
epc-support.tesla.com    origin-edr-eu.tesla.com    origin-pay.tesla.com
origin-shop.tesla.com    xai-api.tesla.com
```

`tests/recon/test_permutation_pipeline.py::test_novelty_is_judged_against_every_known_host`
pins the behaviour.

---

## Determinism

`dnsgen` (DNSGen 2.x) is a Python program that shuffles its input through sets,
so **by default its output order changes on every run**: three runs over one
identical input file produced three different files with different MD5s. Since
the candidate cap keeps a prefix of that output, an unseeded generator made this
stage a lottery — one measured pair of runs over the same 1,380 known hosts found
34 "new" hosts once and 3 the next time, on the same 20,000-name budget. (Those
counts were also inflated by the novelty bug above; the ordering problem was real
either way.)

The generator container therefore runs with `PYTHONHASHSEED=0`, which makes
repeated runs byte-identical (verified: three runs, one MD5). Determinism here is
not about reproducibility for its own sake — it is what makes the cap a decision
instead of a coin flip.

---

## Caps, and why they are set where they are

Two caps, with different jobs:

| Cap | Default | Job |
|---|---|---|
| `PERMUTATION_MAX_KNOWN` | 100 | bounds the generator **input**, which is what bounds the pool |
| `PERMUTATION_MAX_CANDIDATES` | 100,000 | safety valve for pathological generation |

Measured on `tesla.com` (1,380 known hosts):

| Inputs | `dnsgen` output | Unique candidates | Generation time |
|---|---|---|---|
| 25 | 60,439 | 50,520 | 1 s |
| 50 | 138,755 | 110,502 | 3 s |
| 100 | 353,615 raw → 111,613 | 107,667 | 4 s |
| 300 | 794,815 | 552,194 | 20 s |
| 1,380 | 19,907,617 | — | ~420 s |

The input cap is what keeps the pool a bounded size; `MAX_KNOWN=100` keeps a rich
shared vocabulary (which is what makes a permutation recognisable) while
generating in seconds. The output cap is **not** a budget: resolution runs at
~1,300 candidates/s, so covering the whole 107,667-name pool costs ~83 s versus
~16 s for 20,000 — and the earlier 20,000 default was discarding 82% of an
already-computed pool to save about a minute. It now sits high enough that an
ordinary run resolves everything the generator produced.

Re-ranking the pool was tried and **rejected on evidence**: depth-first,
distance-to-known-host and known-vocabulary orderings *each* pushed live hits out
of a 20,000-name budget, while the generator's own confidence order kept them.
The cap stays a prefix of generator order, and the report records exactly how
many candidates were dropped when it does bind.

---

## Output contract

Everything lands in `permutation/output/` (gitignored):

| File | Contents |
|---|---|
| `resolved.txt` | **consume this**: generated candidates that resolve and are genuinely new |
| `candidates.txt` | generated candidates that are in scope and not already known |
| `known.txt` | the known hosts handed to the generator (shallowest first, capped) |
| `dnsgen-raw.txt` | the generator's raw output, before filtering |
| `wildcards.txt` | wildcard records confirmed while filtering |
| `wildcard_suppressed.txt` | generated names dropped as wildcard noise (auditable) |
| `resolvers.txt` / `resolvers-trusted.txt` | the pool this stage resolved against |
| `dnsgen.log` | generator stderr |
| `report.json` | counts, timings, generator/cap accounting, wildcards |

The report is where truncation is made visible:

```json
"counts": { "known": 1380, "generated": 111613, "candidates": 100000,
            "truncated": 7606, "resolved": 5,
            "wildcards": 0, "wildcard_suppressed": 0 }
```

`generated` (everything `dnsgen` printed) versus `candidates` (what survived
scope/dedup/novelty filtering and the cap) versus `resolved` (what actually
answered) is the whole story of a run, and each number can be traced to a file
above.

### Measured run

`tesla.com`, 2026-09-16, defaults, resolver pool reused from the active stage
(same run as the active README's table):

| Stage of the work | Value |
|---|---|
| known hosts | 1,380 (active 494 ∪ passive 1,378) |
| generator inputs | 100 (shallowest) |
| generated | 111,613 raw names in 4.1 s |
| candidates | every candidate resolved → 100,000 after filtering |
| **genuinely new live hosts** | **5**, in 52.1 s total |

Wildcard DNS: none detected on `tesla.com`.

A second, independent run of the same configuration produced **the same 5 hosts**
(same generator output, same candidates, same resolutions) in 112.2 s. That is
the determinism above showing up where it matters: the stage's *answer* is stable
across runs even though its wall-clock time is not.

### Why this stage is worth its 52 seconds

The 5 names it found are absent from both other stages' output, and they are the
kind a generic wordlist misses for a reason: `origin-pay`, `origin-shop` and
`origin-edr-eu` are variations on `origin-*` names that the passive stage had
already found, and `xai-api` is a target-specific compound. That is precisely the
gap permutation exists to close, and it is why the three stages are run together
rather than picking one.

---

## Stealth & resilience (spec §5.1)

Permutations are generated names resolved by brute force — the most clearly *enumerating*
traffic this stage produces — so it runs under the same shared stealth layer as the active stage
([`service/recon_pipeline/stealth/`](../../../stealth/README.md)):

* `PASSIVE_ONLY=1` (or a WAF quarantine left behind by an earlier run) **refuses to resolve
  permutations at all**, rather than resolving them and reporting an abort.
* Candidates are resolved in **budget-sized batches** with a jittered pause, so no single
  resolver sees more unique names than the volume budget allows; the plan is recorded in
  `output/report.json` under `"stealth"`.
* The resolver tools are rate-limited from that same budget unless overridden.

The batch size and spacing are the wall-clock levers: `STEALTH_DNS_BATCH_SIZE` (500) and
`STEALTH_DNS_BATCH_SPACING` (20s). Set them lower for a quieter run and a longer one; set
`ACTIVE_STEALTH=0` to use the pre-stealth behaviour.

## Settings

| Variable | Default | Effect |
|---|---|---|
| `PERMUTATION_TIMEOUT` | 900 | wall-clock budget for the generator (s) |
| `PERMUTATION_MAX_KNOWN` | 100 | known hosts fed to the generator |
| `PERMUTATION_MAX_CANDIDATES` | 100000 | cap on generated candidates (`0` = none) |
| `PERMUTATION_WORDLEN` | 0 (generator default) | `dnsgen --wordlen` |
| `PERMUTATION_FAST` | 0 | `dnsgen --fast` — less coverage, faster |
| `PERMUTATION_REUSE_RESOLVERS` | 1 | reuse the active stage's validated pool |

A future generator registers itself and is selectable by name, with no change to
the pipeline:

```python
register_generator(Generator("mksub", mksub_generate, "..."))
```

---

## Testing

Hermetic — no Docker, no DNS, no dependence on `output/`:

```bash
python -m pytest tests/recon/test_permutation_pipeline.py -q     # 15 tests
```

Covers candidate normalisation (scope, dedup, comments, junk), shallowest-first
input selection, the novelty rule, the cap and its accounting, generator failure
being reported rather than raised, wildcard filtering being applied only to
generated names, and resolver-pool reuse versus re-validation.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `no known hosts to permute` | Run the passive and/or active stage first — this stage paraphrases names that already exist. |
| Report shows `"truncated": N` | The generator produced more than `PERMUTATION_MAX_CANDIDATES`. Raise it, or accept that the tail of the confidence ordering is being dropped (the warning names the variable). |
| Generation is slow | Raise `PERMUTATION_MAX_KNOWN`? No — *lower* it. Generation is combinatorial in the input; 1,380 hosts produce ~19.9M names and ~7 minutes. |
| Yields nothing | Expected on some targets (a flat namespace with no systematic naming). Check `candidates.txt`: if it is large but `resolved.txt` is empty, the naming really is random. |
| Candidates resolve to the same wildcard | The wildcard layer should have caught it — check `wildcards.txt`; `--no-wildcards` disables the suppression that keeps them out. |
| Missing image | Build the stage image (the message contains the `docker build` line); this stage shares the active stage's image. |

## Related

- `../passive/README.md` — upstream stage: the known names.
- `../active/README.md` — upstream stage: resolution, bruteforce, engines.
- `../README.md` — the whole pipeline and how to run all three stages.
- `docs/recon_docs/IMPLEMENTATION_PLAN_V2.md` — stage S16's permutation
  technique, which this stage implements ahead of the graph-based design.
- `docs/README.md` — the documentation index.
