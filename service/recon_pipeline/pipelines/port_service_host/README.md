# Ports, Services & Hosts

Recon stage that answers the question the DNS stages only set up: **what is
listening, on which address, speaking what protocol?** A `dev.` subdomain is a
name; `dev.example.com → 203.0.113.7 :8443 → "Jetty 9.4 on an admin API"` is
attack surface.

It is the first stage in the pipeline that *chooses* whether to send packets, so
most of it is about not sending them: passive intel first, CDN/WAF addresses
classified before anything touches them, and a per-address scan ladder that only
grants the expensive rungs to addresses that earned them.

```bash
# from the project root (imports are absolute)
python -m service.recon_pipeline.pipelines.port_service_host.pipeline
```

That runs: build seeds → passive intel → ownership → reverse DNS → classify →
ladder → scan → service identification → write `port_service_host/output/`.

Design and research: [`DESIGN.md`](DESIGN.md). Raw per-tool commands:
[`commands.txt`](commands.txt).

---

## Quick start

```bash
# the default run: intel + classify + top-N scan + service identification
python -m ...port_service_host.pipeline -t example.com

# no packets at any address (intel, ownership, reverse DNS only)
python -m ...port_service_host.pipeline -t example.com --scan-level passive

# declared CIDR/IP scope — the only input that grants reach beyond our own DNS data
python -m ...port_service_host.pipeline -t example.com --scope program-scope.txt

# what is in the image, and which CDN providers are recognised
python -m ...port_service_host.pipeline --list
```

| Flag | Purpose |
|---|---|
| `-t, --target` | apex domain (default: `TARGET` from `.env`) |
| `--records` | the subdomain stage's `records.jsonl` — the address source |
| `--host-file` | host list used to fill address gaps (repeatable) |
| `--scope` | declared-scope file of CIDRs/IPs (repeatable) |
| `--address` | an address to include explicitly (repeatable) |
| `--scan-level` | `passive` \| `l2` (default) \| `full` |
| `--rate` / `--scan-type` | packets/second (500) and `auto`\|`syn`\|`connect` |
| `--max-ips` | cap on the scan-set size (default: no cap) |
| `--no-intel` / `--no-ownership` / `--no-ptr` | skip that passive layer |
| `--no-services` | skip nmap service identification |
| `--no-cdn-probe` | do not probe CDN addresses at all |
| `--no-escalate` | never promote an L2 finding to a full-range scan |
| `--no-resolve-uncovered` | skip the `dnsx` address-gap fill |
| `--timeout`, `--output-dir`, `--list`, `-v` | per-tool budget, output, inventory, debug |

Exit codes: `0` clean; `1` completed with a failed step (including "no Docker",
which costs the active layers only); `2` aborted on a bad target.

---

## Layout

```
port_service_host/
├── README.md          ← this file
├── DESIGN.md          the research-backed design (read this for the *why*)
├── Dockerfile         the all-in-one stage image (naabu, nmap, httpx, dnsx)
├── commands.txt       raw per-tool Docker commands, for debugging by hand
├── settings.py        paths, limits, PSH_* env overrides
├── seed_builder.py    records.jsonl + declared scope -> the address list
├── normalize.py       IP/port canonicalisation, every tool's output parser
├── pipeline.py        end-to-end runner + CLI + report.json   ← entry point
├── passive/
│   ├── httpjson.py    status-preserving JSON fetch (404 != "source is down")
│   ├── internetdb.py  Shodan InternetDB: keyless per-IP ports/hostnames/tags
│   ├── rdap.py        RDAP allocation record + Team Cymru ASN/prefix
│   └── ptr.py         reverse DNS via `dnsx -ptr`
├── classify/
│   ├── cdn.py         cdn / dedicated / unknown, with the evidence for it
│   └── data/cdn_ranges.txt   dated CDN range snapshot (a supplement, see inside)
└── active/
    ├── tools.py       THE TOOL REGISTRY: image, argument builders, runner
    ├── ladder.py      the per-address scan-ladder decision (pure)
    ├── naabu.py       port scanning + SYN→CONNECT degradation
    ├── nmap.py        service identification, grouped by port signature
    └── webprobe.py    the httpx 80/443 probe for CDN addresses
```

There are deliberately **no per-tool wrapper modules**: every tool here is a
different *command line over the same registry*, and none of them runs "on its
own". `pipeline.py --list` prints the registry and the recognised CDN providers.

---

## Requirements

- **The stage image must exist.** All four tools are co-packaged in
  `port_service_host_image`, built from this directory's `Dockerfile`. The stage
  checks for it before doing any work and reports the exact build command:

  ```bash
  docker build -t port_service_host_image \
    service/recon_pipeline/pipelines/port_service_host/
  ```

  A missing image is *not* fatal to the run: the passive layer needs no Docker, so
  the stage degrades to the passive rung, records `docker_error`, and still writes
  `ips_raw.txt`, `passive_intel.jsonl`, `ownership.jsonl` and
  `cdn_classified.jsonl`.

- **Docker running**, and — for a SYN scan — `NET_RAW`. Standard Docker grants it,
  so `--cap-add=NET_RAW` normally just works; a hardened runtime refuses it and the
  stage falls back to CONNECT (see *SYN, and what happens when it is denied*).
- **`requests`** (already the project's HTTP client) and **`dnspython`** for the
  Team Cymru TXT lookups. Both are optional in the sense that their absence
  degrades one layer rather than the stage.

---

## Where the addresses come from

The decisive inventory fact about this stage is that **the DNS→IP half is already
done**. The sibling active stage's `records.jsonl` carries A/AAAA for every live
host it found, so this stage does not *discover* addresses — it recovers,
deduplicates and gives them provenance:

| Input | What it grants | Notes |
|---|---|---|
| `active/output/records.jsonl` | an address one of our own names resolves to | the strongest claim; also carries CNAME chains, which are pre-scan CDN evidence |
| `active/output/resolved.txt`, `output/live_hosts.txt` | the name list, used to expand an address back into the names that point at it | |
| `--scope` files | **network reach beyond our own DNS data** | per `DESIGN.md` §5.4 the only input that does, and the only thing that marks an address as L3-eligible |

Two edge cases the seed builder handles explicitly rather than silently:

- **Hosts with no record.** `records.jsonl` is written by the sibling's *active*
  pass, so a host that only the *permutation* stage found has no address. The
  stage resolves those with one `dnsx -a` invocation (the output shape is
  identical, so one parser reads both). Disable with `--no-resolve-uncovered`.
  If they still cannot be resolved they are **reported** in
  `seeds.unresolved_hosts`, never quietly dropped.
- **Addresses we must not touch.** Private, loopback, link-local, multicast and
  the documentation ranges are refused with a reason
  (`seeds.refused_reasons`). The check is `is_global` rather than a hand-kept
  range list, so it stays correct as the registries change.

A scan set also cannot explode by accident: `expand_networks` refuses any declared
network above 65,536 addresses *before* enumerating it (a `/8` in a scope file is
one line and 16 million addresses), and `--max-ips` caps the whole set.

---

## Passive first

The intel and ownership layers are keyless and run before anything is scanned, so
on a fresh target they often answer "is there anything here worth scanning".

| Source | Gives | Key needed |
|---|---|---|
| **Shodan InternetDB** | per-IP open ports, hostnames, tags, CPEs, CVEs | none |
| **RDAP** (`rdap.org`) | allocation record: org, handle, country, range | none |
| **Team Cymru** (DNS TXT) | origin ASN, prefix, AS name | none |
| **`dnsx -ptr`** | the names that point *at* an address | none |

### Failure and absence are different answers

This is the honesty property the whole passive layer is built around, and it is
why `passive/httpjson.py` keeps the status code that the sibling stage's helper
deliberately discards:

| InternetDB says | Means | Recorded as |
|---|---|---|
| `200` with a port list | Shodan has data | `indexed` |
| `200` with no ports | no ports seen *recently* | `indexed`, empty ports |
| `404` | Shodan has **never scanned** this address (routine for IPv6) | `not-indexed` |
| timeout / 429 / 5xx | we did not find out | `unavailable` |

`unavailable` is never rendered as "no open ports", and the counts keep all four
states apart.

### Freshness is stated, not implied

InternetDB is refreshed **weekly**, so its answer describes some point in the last
seven days. Every record therefore carries `intel_age_days` as an explicit *upper
bound* derived from that refresh period. Past `PSH_INTEL_MAX_AGE_DAYS` (14) a
record may still **seed** the ladder — an old open port is a good reason to look —
but it is never reported as current state. Live runs report `stale_intel: 0`
because a fresh lookup is at most 7 days old by construction; the mechanism exists
for cached records and for operators who lower the limit.

---

## Classification decides what may be scanned

Port-scanning a CDN edge node is three mistakes at once: the results are
meaningless (the edge answers, not the origin), the traffic is noise on shared
infrastructure that is not the target's, and it is the fastest way to get noticed.
The ASM spec agrees from the other direction — a pure-CDN address is a strongly
*negative* scoring signal.

Every address gets exactly one verdict, always with the evidence that produced it:

- **`cdn`** — shared edge infrastructure. Never port-scanned; at most an HTTP
  probe on 80/443, because that is what actually explains the site behind it.
- **`hosted`** — the target's own name resolves *through* a third-party
  platform's tenant naming (a CNAME chain such as `autodiscover.qbsco.net →
  autodiscover.outlook.com`), so the address serves someone else's application,
  not the target's server. Still scanned at the top-N rung (a tenant endpoint
  can expose the target's own ports), but **escalation to a full-range scan is
  refused** — an open port here means "the platform's edge answered", not "the
  target's server is worth 65,535 probes". The suffix table lives in
  `classify/cdn.py` (`HOSTED_SUFFIXES`); extend it there, with the same
  whole-label matching rule the CDN suffixes use.
- **`dedicated`** — no CDN signal, and one of the target's own names resolves
  here. This is the address class the ladder spends budget on.
- **`unknown`** — nothing to go on.

The `hosted` verdict exists because of a measured failure (qbsco.net,
2026-09-17): an M365-hosted `autodiscover` name put 16 Microsoft addresses on
the scan set, and an L2 port-80 finding escalated into a 13-minute full-range
sweep that re-found nothing — while the CNAME chain naming `outlook.com` had
been in `records.jsonl` before the scan started. The classifier's hardening
against false CDN positives (below) had swung the other way: the evidence was
present, but there was no verdict for it.

Signals, strongest first: published **range** → **CNAME** target into provider
edge naming → provider **PTR** → response **headers** → **ownership** name →
generic **edge tags**.

Two of those are weaker than they look, and both were caught by live runs rather
than by fixtures:

- **A generic tag cannot name a provider.** Shodan tagged `scanme.nmap.org`
  (a Linode VPS) as `cloud`, and an earlier revision gave *every* provider the
  same `("cdn","cloud","waf")` tag list — so one generic tag classified a plain
  VPS as `cdn (Cloudflare)`, which would have excluded a real host from the scan.
  `cloud` is no longer an edge tag at all (a cloud instance is not a CDN), and
  generic tags raise the verdict **without** attributing a provider.
- **A hosting-provider name is not edge evidence.** Linode is now owned by Akamai,
  so Team Cymru reports that VPS's AS as `AKAMAI-LINODE-AP - Akamai Connected
  Cloud` — and a substring match on `"akamai"` classified it as Akamai CDN edge.
  Ownership naming is therefore conclusive only for providers whose *entire*
  network is edge (`EDGE_NETWORKS` in `classify/cdn.py`); for Akamai, Microsoft
  and Google it is recorded as corroboration and needs a naming signal to agree.
  Genuine edge always provides one: their names resolve through `*.edgekey.net`,
  `*.akamaiedge.net`, `*.cloudflare.net` and so on.

The bundled `classify/data/cdn_ranges.txt` is a deliberately small, dated
snapshot (Cloudflare and Fastly only) so that a stale file can cause a *missed*
classification and never a false one. Refresh it from the vendors' published
lists and point `PSH_CDN_RANGES_FILE` at the result.

```bash
# re-check a single address against every signal, live
python -c "
from service.recon_pipeline.pipelines.port_service_host.passive import internetdb, rdap
from service.recon_pipeline.pipelines.port_service_host.classify import cdn
ip = '104.16.0.1'
v = cdn.classify(ip, intel=internetdb.fetch_ip(ip), ownership=rdap.fetch_ip(ip))
print(v.verdict, v.provider, v.confidence); [print(' ', e) for e in v.evidence]"
```

---

## The scan ladder

Full-range scanning of every address is the amateur default and the fastest route
to a blackhole. Five rungs, and escalation between them is one-way and recorded:

| Level | When | What runs | Cost |
|---|---|---|---|
| **L0 skip** | CDN address, probing disabled | nothing | 0 |
| **L1 passive-only** | no passive intel, no scope claim, no in-scope name | nothing; "unknown, unscanned" | 0 |
| **L2 top-N** | the default for a claimed address | `naabu -top-ports 1000` | ≤1000 probes |
| **L2b CDN web probe** | CDN/WAF addresses | `httpx` on 80/443 only | ≤2 connects |
| **L3 full** | scope-declared, in-scope at `--scan-level full`, **or** L2 found an open port | `naabu -top-ports full` | ≤65,535 probes |

One refusal: an address with a `hosted` verdict never escalates, even when its
L2 scan found an open port. Refusals are reported under
`ladder.escalation_refused_hosted` rather than applied silently.

The conditions are checked in that order because the order *is* the policy: a mode
override outranks evidence, a CDN verdict outranks a scope declaration, and
nothing short of a positive claim reaches L3. Escalation is capped
(`PSH_ESCALATE_MAX`, default 25) and reported — "earned" is not the same as
"affordable", and a target where every address has an open port must not silently
become a full-range sweep of the estate.

Cost, at the design's realistic single-target scale (~350 scan-eligible addresses
after CDN collapse): all-L3 is ≈22.9M probes (~6.4 h at 1k pps); this ladder is
≈3.6M (~1 h), and the ~65× gap is spent only on addresses that produced evidence.
Passive-only is zero packets.

Because every address's rung — including L0/L1 — is recorded in `report.json`,
"found nothing" and "never looked" are structurally distinguishable rather than
merely described differently.

---

## Footprint and authorization

| Step | Traffic | Default |
|---|---|---|
| InternetDB / RDAP / Cymru | HTTPS + DNS to **third-party** APIs | **on** |
| reverse DNS | DNS queries to public resolvers | **on** |
| `nmap -sV` | service probes to **the target's own addresses** | **on** |
| CDN port scan | — | **never** (by design) |
| `naabu` port scan | SYN or CONNECT packets to the target | **on**, ladder-gated |
| `httpx` 80/443 probe | HTTP requests to the target | **on**, CDN addresses only |

Only addresses that are in scope — declared, or resolved from one of the target's
own names — ever receive a packet, and `--scan-level passive` refuses all of them.

**SYN, and what happens when it is denied.** naabu's own default is CONNECT, so a
SYN scan is only SYN because we asked for `-s s` *and* `--cap-add=NET_RAW`.
`--scan-type auto` (the default) tries SYN and, if and only if the failure looks
like a denied capability (`cap_net_raw`, `operation not permitted`, a raw-socket
error), retries as CONNECT and records `degraded` in the report. A genuine network
failure is **not** retried: CONNECT would change what a negative result means.

### Settings

Every knob is a `PSH_*` environment variable (the full table is in `settings.py`).
The ones that change behaviour most:

| Variable | Default | Effect |
|---|---|---|
| `PSH_SCAN_LEVEL` | `l2` | `passive` / `l2` / `full` — the ceiling, not a claim |
| `PSH_TOP_PORTS` | `1000` | naabu's top-port preset (`100`/`1000`/`full`) |
| `PSH_MAX_RATE` | `500` | packets/second for the port scan |
| `PSH_SCAN_TYPE` | `auto` | `auto` / `syn` / `connect` |
| `PSH_ESCALATE` / `PSH_ESCALATE_MAX` | `1` / `25` | whether, and how many, L2 findings reach L3 |
| `PSH_CDN_PROBE` | `1` | whether CDN addresses get the 80/443 probe or are skipped |
| `PSH_INTEL_MAX_AGE_DAYS` | `14` | age past which passive intel may seed but not report |
| `PSH_MAX_IPS` | `0` (no cap) | head-count cap on the scan set |
| `PSH_SCOPE_FILE` | unset | declared scope (`:`-separated on Windows, one path per `--scope`) |
| `PSH_IMAGE` | `port_service_host_image` | image tag |

`PSH_SCAN_LEVEL` is a *ceiling*: `full` raises what an address may reach, it does
not create a claim. An unrecognised value falls back to `l2` rather than being read
as "scan everything".

---

## Output contract

Everything lands in `port_service_host/output/` (gitignored — reproduce by
re-running):

| File | Contents |
|---|---|
| `ips_raw.txt` | the scan set: canonical, deduplicated, in scan-set order |
| `passive_intel.jsonl` | per-address ports/hostnames/tags/vulns, with source and `intel_age_days` |
| `ownership.jsonl` | per-address ASN, prefix, AS name, org, registry, country |
| `cdn_classified.jsonl` | verdict + `confidence` + `provider` + the `evidence` list |
| `openports.jsonl` | one line per socket, with `scan_mode` (`syn`/`connect`/`http`) and `source` |
| `services.jsonl` | service, banner, CPEs, and TLS issuer/SAN/validity when present |
| `hosts.txt` | addresses that produced something (v4 then v6, sorted) |
| `report.json` | counts, every ladder decision, scan outcomes, aborts, stealth state |
| `naabu.jsonl`, `httpx.jsonl`, `ptr.jsonl`, `nmap-*.xml` | raw tool output, for when something looks wrong |

Normalization rules: addresses are canonicalised (dotted-quad, RFC 5952) and
sorted v4-before-v6; ports are ints in 1–65535; every JSONL row carries a
`source`. Two provenance details are worth knowing:

- **A port can be claimed by more than one mode.** A SYN result is a hypothesis; a
  completed HTTP connection is proof. `scan_mode` is `syn+http` when both saw it,
  and `counts.confirmed_ports` reports how many sockets are corroborated.
- **naabu's output repeats itself.** It re-verifies what it found and prints each
  port twice — measured on `45.33.32.156`, four open ports produced eight output
  lines. Socket counts therefore come from the *merged* set, and when the raw line
  count differs the report says so (`tool_lines`).

### Measured run: a target whose truth we control `[strongest evidence]`

`2026-09-17`, Docker Desktop / Windows. A local container serving **known** ports —
HTTP on 80 and 8080, a bare TCP listener on 40000 (deliberately outside the
`1000` preset) — scanned with the real tools, so every expectation below is ground
truth rather than an inference. Reproduce with
`python tests/recon/live_groundtruth_scan.py`, which starts the target, runs the
checks and removes it.

| Check | Result |
|---|---|
| L2 (`-top-ports 1000`) | found **80, 8080** — and correctly did *not* reach 40000 |
| L3 (`-top-ports full`) | found **80, 8080, 40000**, a superset of L2 |
| the SYN rung (`--scan-type auto`) | ran as `syn` for real (capability granted) |
| duplicate-line counting | 2 open ports from **4** raw output lines — `tool_lines` reports it |
| port-set grouping on the L2 result | `[]` — every open port was HTTP, so nmap was not invoked |
| port-set grouping on the L3 result | exactly `[(40000,)]` — nmap saw only the non-HTTP port |
| nmap on that port | read the XML and produced one entry (`40000/tcp safetynetp`) |
| httpx on the web ports | `200`, title `psh live target` |
| **checks passed** | **14/14 in 127 s** |

The two rungs are therefore proven *different in practice*, not just in the code:
the port that only the full-range scan can see was found by the full-range scan and
missed by the top-1000 scan, and the HTTP exclusion left nmap with exactly the set
the design says it should have.

### Measured run: the public-target pass `[weaker, still useful]`

Two public addresses, chosen because they are legitimately scan-able rather than
because they are representative: `45.33.32.156` (`scanme.nmap.org`, published by
the nmap project for exactly this) and `104.16.0.1` (a Cloudflare edge, to
exercise the CDN rung).

| Step | Result | Time |
|---|---|---|
| seeds | 2 addresses (1 declared scope, 1 explicit) | — |
| passive intel (InternetDB) | 2/2 indexed, 0 stale | ~2 s |
| ownership (RDAP + Cymru) | 2/2 resolved (`LINODE` / `CLOUDFLARENET`) | ~2 s |
| reverse DNS (`dnsx -ptr`) | 0/2 have a PTR name | 1.4 s |
| classification | 1 `cdn` (Cloudflare), 1 `unknown` | — |
| ladder | `{L2: 1, L2b: 1}` — the CDN address was never port-scanned | — |
| `naabu` SYN scan on the L2 address | 4 open ports (22, 80, 9929, 31337) | 6.2 s |
| `httpx` probe on the CDN address | 1/2 responded, port 80 open | 1.5 s |
| `nmap -sV` on the 3 non-HTTP ports | 3 services, 1 group, 3 address-port pairs | 3.0 s |
| **total** | **5 open ports, 3 services** | **15.4 s** |

The service identities it produced, verbatim from `services.jsonl`:

```
22/tcp    ssh          OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 Ubuntu Linux; protocol 2.0
                       cpe:/a:openbsd:openssh:6.6.1p1, cpe:/o:linux:linux_kernel
9929/tcp  nping-echo   Nping echo
31337/tcp tcpwrapped
```

Port 80 was correctly *excluded* from nmap and left to the HTTP layer, and 9929 and
31337 — which are in the top-1000 preset but easy to miss — were found.

### Measured run: classification breadth

`python tests/recon/live_classify_matrix.py` classifies ten real addresses across
Cloudflare (v4 and v6), Fastly, Google, GitHub, Azure, AWS and a plain Linode VPS,
and asserts the *structure* of the answer rather than any single verdict — because
both classifier bugs found so far were found live, and both would have silently
dropped a real host from the scan.

| Property asserted | Result |
|---|---|
| every address gets exactly one documented verdict, with a confidence and evidence | 10/10 |
| an address inside a shipped range is `cdn` at **high** confidence | 3/3 |
| a plain VPS is **not** `cdn` (Shodan tags it `cloud`, Cymru says *Akamai*) | pass |
| a non-global address yields **no** scan-or-skip signal from the address alone | 4/4 |
| a non-literal is refused as a non-literal | 3/3 |
| classification is deterministic across two runs of the same input | pass |
| a lookup that failed is never rendered as a confident verdict | pass |
| **checks passed** | **23/23** |

The run also shows the fix working in both directions on real data: Google and
Azure addresses carry the ownership evidence in their `evidence` list while
staying `unknown`, because their naming is recorded as corroboration rather than
proof.

Honest caveats:

- **The ground-truth target is one host.** It proves the ladder, the grouping and
  the parsers against known truth, but not scale: very large scan sets,
  wildcard-heavy zones, IPv6-only hosts and CDN-fronted origins on non-standard
  ports are designed for but not demonstrated. A container's open ports are also
  the easy case for naabu — no firewalls, no rate limiting, no loss.
- **The naming-only `cdn` verdict is conservative, and sometimes over-conservative.**
  A Cloudflare-owned address is `cdn` on ownership naming alone (Cloudflare's whole
  network is edge). Measured: `1.1.1.1` classifies as `cdn (Cloudflare)` — correct
  about the network, but it is a DNS resolver, not a CDN edge, and it would be
  excluded from port scanning. The error costs coverage rather than safety, and it
  is the price of never scanning shared edge infrastructure by mistake.
- **The SYN→CONNECT degradation is unit-tested, not live-exercised.** L3 and the
  SYN path now are (above). The degradation needs a container deliberately denied
  `NET_RAW`, which a normal Docker run does not produce.
- **Detection is not block-proven.** The CDN rung carries the shared stealth
  identity and feeds WAF verdicts into quarantine, but no live run in this session
  was actually blocked, so the escalation to passive-only has not been seen in the
  wild.
- **The `-cdn` flag is corroboration only.** naabu can report its own CDN
  attribution; it is captured into the report and never used to override a verdict
  computed from stronger evidence.

---

## Stealth & resilience (spec §5.1)

The stage runs under the shared stealth layer
([`service/recon_pipeline/platform/stealth/`](../../../stealth/README.md)):

* **CDN probes carry one coherent identity** — `-random-agent=false` plus a stable
  header set and `-tlsi` ClientHello. Measured elsewhere in this repo: the CLI's
  randomiser emits user agents such as `Firefox/3.6.13`, i.e. fiction no browser
  has ever sent.
* **WAF verdicts feed quarantine.** A challenge or block on a probe is recorded
  against the host, so later steps skip it, and sustained blocks degrade the run.
* **`PASSIVE_ONLY=1`, or a quarantine carried over from a previous run, drops every
  address to L1** — every artifact is still produced and the report says why. This
  stage does *not* abort in passive-only mode, because the passive layer is
  genuinely useful on its own.
* **Every run records its stealth state** under `"stealth"` in `report.json`
  (transport and its real capabilities, identities, pacing, verdicts, quarantine).

Port-scan rate is a `PSH_*` knob rather than a stealth one, because a port scan has
no HTTP analogue for "requests per second"; `PSH_MAX_RATE` (500 pps) is the control
that stretches a unique-port burst, and the ladder — not the rate — is what keeps
the stage from looking like a scanner sweep.

---

## Testing

Hermetic — no Docker, no DNS, no HTTP, no dependence on `output/`:

```bash
python -m pytest tests/recon/test_psh_normalize.py \
                 tests/recon/test_psh_seed.py \
                 tests/recon/test_psh_passive.py \
                 tests/recon/test_psh_passive_edges.py \
                 tests/recon/test_psh_httpjson.py \
                 tests/recon/test_psh_ptr_runner.py \
                 tests/recon/test_psh_classify.py \
                 tests/recon/test_psh_ladder.py \
                 tests/recon/test_psh_tools.py \
                 tests/recon/test_psh_active.py \
                 tests/recon/test_psh_active_edges.py \
                 tests/recon/test_psh_cli.py \
                 tests/recon/test_psh_pipeline.py -q
```

Every tool wrapper and every network-backed lookup is an injection point, so the
whole stage is exercised with fakes: the SYN→CONNECT degradation and the rule that
it fires only for a capability failure, port-set grouping, the ladder's conditions
*and their ordering*, the CDN signals and their confidence, and the full stage
contract through `pipeline.run_port_service_host_stage`.

Two tests exist because a live run found a bug that fixtures had missed, and they
are named for it: `test_a_cloud_tag_alone_is_not_a_cdn` and
`test_a_hosting_provider_name_is_not_by_itself_edge_evidence`. They pin the two
false positives (a Linode VPS reported as `cdn (Cloudflare)`, then as Akamai) that
would each have silently excluded a real host from the scan.

### Live checks (opt-in, needs Docker)

Not part of the suite — they start containers and contact third-party APIs:

| Script | What it proves |
|---|---|
| `tests/recon/live_groundtruth_scan.py` | scans a **local container with known ports** with the real tools: the L2/L3 rungs differ as designed, the HTTP exclusion leaves nmap the right set, the parsers read real output. 14/14, ~2 min. |
| `tests/recon/live_classify_matrix.py` | classifies ten real provider addresses and asserts the structure of every verdict. Passive only — no packets to the addresses. 23/23, ~30 s. |

Both exit non-zero on any failed check, so they are usable as a pre-release gate.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `image ... not built` | Build it — `docker build -t port_service_host_image <stage dir>`. The message contains the exact line. |
| `docker_error` in the report, `run_mode: passive` | Docker unreachable. The passive layer still ran; the active layers are skipped and reported. |
| Every address is `unscanned` / all L1 | Nothing claimed them: no in-scope name, no `--scope`, no passive intel. Pass `--scope`, or run the subdomain stage first. |
| `no scan-eligible address` | `records.jsonl` was empty and no scope was declared. Run the subdomain stage's active pass, or pass `--scope` / `--address`. |
| An address you expected to be scanned is `L0/L1` | Check its verdict in `cdn_classified.jsonl` — if it is `cdn`, that is the design working, not a bug. |
| `unresolved_hosts` is large | `records.jsonl` is stale, or hosts came from the permutation stage. Re-run the subdomain stage, or leave `PSH_RESOLVE_UNCOVERED` on. |
| A scan reports `degraded` | SYN was refused for want of `NET_RAW`; results are from CONNECT. Capability-proven, just slower. |
| Ports look doubled | They are, in the raw tool output — naabu re-verifies. Counts come from the merged set; `tool_lines` shows the raw figure. |
| Fewer ports than naabu shows by hand | Correct: CDN addresses are not scanned, HTTP ports are excluded from nmap, and the ladder caps what is probed. |
| Container left running after Ctrl-C | `docker rm -f $(docker ps -q --filter ancestor=port_service_host_image)`; the pipeline removes its own containers on timeout, but an interrupted parent cannot. |

## Related

- [`DESIGN.md`](DESIGN.md) — the R&D: sources, tool comparisons, efficiency maths, phased plan.
- [`commands.txt`](commands.txt) — raw per-tool commands, with the scope warning.
- `../subdomain_domain_wildcards/README.md` — the upstream stage that supplies the addresses.
- [`../../../stealth/README.md`](../../../stealth/README.md) — the shared shaping layer.
- [`../../../docs/recon_docs/port_service_host.md`](../../../docs/recon_docs/port_service_host.md) — the R&D doc that is this stage's authority (marked *implemented, with deltas*). It maps to **no numbered plan stage**: plan-v2's S22–S24 are cloud buckets, mobile teardown and JS crawl, not port/service enumeration.
