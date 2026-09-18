# Ports, Services & Hosts — Pipeline Design (R&D)

> **Status: IMPLEMENTED, with the deltas recorded here.** This doc is the
> research-backed blueprint and the code now follows it; `README.md` in this
> directory describes what *is*, and the deltas between plan and build are listed
> at the end of this header so the two cannot drift silently.
>
> Every tool claim below was verified against vendor documentation in September
> 2026, and every "we already have" claim against the codebase. Sections marked
> **[measured]** cite repo evidence; **[research]** cites the external sources in
> §13. Flags that this doc described from documentation were additionally checked
> against the real binaries during implementation (naabu's JSON shape, its
> duplicate output, `-top-ports full`, and that its default scan type is CONNECT;
> `dnsx -ptr` emitting names only in the JSON stream).
>
> **Deltas from the plan as written:**
>
> * **P1–P3 are built**; P4 (keyed Censys/Shodan sources and the cert pivot) and
>   P5 (graph writes) are not, exactly as phased. `censys.py`/`shodan.py` do not
>   exist; keyless InternetDB carries the passive layer instead (§5.1's default).
> * **Ptr uses `dnsx -ptr` as designed**, but its output shape is JSON-only — the
>   plain stream echoes the *input list* back, so `-json` is required rather than
>   cosmetic (§5.1).
> * **nmap grouping is by identical port signature**, not one invocation per
>   address and not `-nmap-cli`: one invocation per *distinct port set* avoids both
>   the container-per-address cost and the over-scan that a union port list causes
>   (§6.2's objection to `-nmap-cli`, solved without its cost).
> * **Ownership naming is corroboration, not proof.** §3's D2 and the classifier
>   were written assuming a provider name implies CDN edge. A live run disproved
>   that: Linode is owned by Akamai, so Cymru reports `AKAMAI-LINODE-AP - Akamai
>   Connected Cloud` for a plain cloud-hosting VPS, and a name match classified it
>   as Akamai edge. Ownership naming is now conclusive only for providers whose
>   whole network is edge (`EDGE_NETWORKS` in `classify/cdn.py`). The same run
>   showed Shodan's generic `cloud` tag is not an edge tag either. See
>   *Classification decides what may be scanned* in `README.md`.
> * **`records.jsonl` alone is not a complete address source.** It is written by
>   the sibling's *active* pass, so permutation-only hosts have no record; §2's
>   input table omits this. The seed builder fills the gap with one `dnsx -a`
>   invocation (same output shape, same parser) and reports anything it still
>   cannot resolve.
> * **`port_service_host/` keeps its tools in one image** built from its own
>   Dockerfile, matching the sibling active stage rather than the passive stage's
>   image-per-tool model (§4 assumed the latter).
> * **§6.4's retry and CONNECT-verification advice is implemented** as SYN→CONNECT
>   degradation on a *capability-shaped* failure only, since retrying a genuine
>   network failure would change what a negative result means §6.4 takes as read.
> * **Scan-type spellings are mapped explicitly.** §6.1's ladder names the rungs in
>   the settings vocabulary (`syn`/`connect`/`auto`), while `active/tools.py`
>   exports naabu's own flag values (`s`/`c`). Both are accepted now, because the
>   fall-through is the *auto* path: an unmapped `"s"` quietly turned an explicit
>   SYN request into "SYN, then degrade to CONNECT if refused" — a weaker scan than
>   the caller asked for. `naabu.scan_intent` is the one place that mapping lives.
> * **Recursion's live behaviour was re-checked against the ladder's assumptions.**
>   That work is in the *other* stage, but it matters here because this stage
>   consumes its output: `recursion_parents` no longer offers the apex or any name
>   outside it (see `../subdomain_domain_wildcards/active/README.md`), which removed
>   a set of duplicate level-1 queries from every recursive run.

---

## 1. Why this stage exists, and what "done" means

The subdomain/domain stage answers *what names exist*. This stage answers the
question that actually finds bug-bounty surface: **what is listening, on what
address, speaking what protocol?** A `dev.` subdomain is a name; `dev.tesla.com →
23.1.2.3 :8443 → "Jetty 9.4 on an admin API"` is an attack surface.

The stage's output contract (what downstream consumers may rely on):

| Artifact | Content | Graph mapping |
|---|---|---|
| `hosts.txt` | unique live IPs (v4+v6) with first-seen provenance | `:IP` nodes |
| `openports.jsonl` | `{"ip":…, "port":…, "host":…}` per open socket | `RESOLVES_TO` enrichment, scan provenance |
| `services.jsonl` | service/banner/TLS identity per open port | `HOSTS`, `USES_TECHNOLOGY` |
| `cdn_classified.jsonl` | per-IP verdict: `cdn` / `dedicated` / `unknown` + evidence | the CDN/shared-hosting scoring signals (spec §7: −80 pure-CDN, −60 shared-hosting, +30 shares-non-CDN-IP) |
| `passive_intel.jsonl` | per-IP passive ports/hostnames/vulns (source-labelled) | same, provenance-marked |
| `report.json` | counts, scan-ladder decisions, budget consumption, aborts | — |

`done` = given the subdomain stage's outputs plus scope seeds, the stage
produces all six artifacts hermetically testably, honours the stealth budget
(§8), degrades to passive-only when scanning is unwise, and never emits a
port/service claim without a named source.

---

## 2. Inputs — we already own most of them **[measured]**

| Seed | Producer | Cost to obtain | Notes |
|---|---|---|---|
| `A`/`AAAA` per live host | active stage's `records.jsonl` (dnsx) | **free — already on disk** | 493 live hosts on tesla.com each carry A/AAAA in `active/output/records.jsonl` |
| Scope CIDRs / IPs | scraper: HackerOne `scope_type ∈ {CIDR, IP}` (`docs/scraper_docs/schema.md`) | free — in Postgres | the only seeds that grant *network* reach beyond our resolved hosts |
| ASN → CIDR | RDAP/Team Cymru (§5) | 1 query per ASN | speculative: in-scope only after scope policy (§5.4) |
| PTR names | `dnsx -ptr` | 1 query per IP | turns IPs into candidate hostnames (reverse gate) |
| Historical port/banner data | Shodan/Censys passive (§5) | API quota | freshest-free is **Shodan InternetDB** (no key) |
| apex / TARGET | `config.py` | — | same single-target convention as the other stage |

The decisive inventory fact: **the active stage already resolved every live
host to IPs.** The DNS→IP half of this pipeline is bookkeeping, not scanning.
The genuinely new work is (a) passive intel on those IPs, (b) port scanning
them + scope CIDRs, (c) service identification, (d) CDN classification.

---

## 3. Design principles

**D1 — Passive first, always.** Every IP gets passive intel before any packet
is sent at it. InternetDB is keyless; on fresh targets the passive pass alone
often answers "is there anything here worth scanning".

**D2 — Classify before you scan.** CDN/WAF IPs get **at most** 80/443 probed
via HTTP (never a port scan): scanning Cloudflare ranges is noise that also
destroys our ability to interpret results. Naabu's `-exclude-cdn` implements
exactly this and is on by default in our design [research: PD docs].

**D3 — Scan only what deserves it (the scan ladder).** Full-range scanning of
every IP is the amateur default and the fastest route to a blackhole. §6
defines L0–L3; the ladder decides per-IP, from scope, passive findings, and
scoring state.

**D4 — One connection model, chosen per run.** SYN when root/raw is available,
CONNECT otherwise — chosen at runtime, reported honestly. Tools degrade, runs
don't fail.

**D5 — Depth is reserved for corroboration.** Version detection (`-sV`) runs
on open ports only, and mostly at low intensity. We are not vuln-scanning; we
are *naming* services.

**D6 — Every result carries provenance.** `{ip, port, source, first_seen,
tool, scan_mode}` or it doesn't exist. Port state from a 1-in-65535 lossy
protocol without repetition is a hypothesis, not a fact (§6.4).

**D7 — Scope is a hard gate for network reach.** DNS names can be re-verified
cheaply; a stray packet at an out-of-scope IP cannot be unsent. CIDR/ASN
expansion only enters the scan set through the scope-policy module (§5.4).

**D8 — Budgets everywhere, same as the subdomain stage.** Ports-per-second,
hosts-in-flight, and total packets are budgeted through the stealth layer
(`service/recon_pipeline/platform/stealth/`), not left to tool defaults.

---

## 4. Architecture

Mirrors the mature subdomain stage: settings → sources → normalizer →
pipeline, with the stealth `StealthSession` chokepoint reused, not re-invented.

```
                 ┌────────────────────────────────────────────────────┐
 inputs ────────►│ seed_builder                                       │
 (records.jsonl, │  resolved IPs · scope CIDR/IP · (opt) ASN expansion│
  Postgres scope)│  → ips_raw.txt (deduped, canonicalised, scoped)    │
                 └────────────────────────────────────────────────────┘
                                     │
                 ┌────────────────────────────────────────────────────┐
                 │ PASSIVE                                            │
                 │  internetdb.py   keyless per-IP ports/hostnames/CVE│
                 │  censys.py       search pivot (optional key)       │
                 │  shodan.py       /shodan/host/{ip} (optional key)  │
                 │  rdap.py         IP→org/ASN (RDAP + Team Cymru)    │
                 │  ptr.py          dnsx -ptr per IP                  │
                 │  → passive_intel.jsonl, cdn hints, ASN map         │
                 └────────────────────────────────────────────────────┘
                                     │
                 ┌────────────────────────────────────────────────────┐
                 │ CLASSIFY  (cdn_classify.py)                        │
                 │  CDN/WAF ranges from intel + HTTP evidence         │
                 │  → cdn / dedicated / unknown per IP                │
                 └────────────────────────────────────────────────────┘
                                     │
                 ┌────────────────────────────────────────────────────┐
                 │ ACTIVE  (scan ladder §6)                           │
                 │  L0 skip · L1 passive-only · L2 top-N · L3 full    │
                 │  naabu (SYN|CONNECT) → per-IP port sets            │
                 │  L2b  httpx probe 80/443 on CDN IPs                │
                 │  nmap -sV (low intensity) on open non-HTTP ports   │
                 │  → openports.jsonl, services.jsonl                 │
                 └────────────────────────────────────────────────────┘
                                     │
                 ┌────────────────────────────────────────────────────┐
                 │ NORMALIZE + REPORT                                 │
                 │  dedup, provenance merge, hosts.txt, report.json   │
                 └────────────────────────────────────────────────────┘
```

```
port_service_host/
  README.md            # the "what IS", written after implementation
  DESIGN.md            # this file
  settings.py          # paths, env knobs (PSH_*), timeouts — settings.py convention
  seed_builder.py      # records.jsonl + scope → ips_raw.txt
  passive/             # internetdb.py, censys.py, shodan.py, rdap.py, ptr.py
  classify/cdn.py      # CDN/WAF verdicts
  active/              # naabu.py, nmap.py, ladder.py, httpx_probe.py
  normalize.py         # merge + provenance (steal from sibling stage's normalize.py)
  pipeline.py          # run_port_service_host_stage()
  main.py              # CLI
```

---

## 5. Passive layer

### 5.1 Sources **[research]**

| Source | What it gives | Access | Notes |
|---|---|---|---|
| **Shodan InternetDB** | open ports, hostnames, CVEs, tags, CPEs per IP | **no key**, `GET https://internetdb.shodan.io/{ip}` | refreshed **weekly** → freshness flag mandatory; built for per-IP lookups, so fetch politely (sequential or lightly concurrent, retry-aware); the default intel source |
| **Shodan REST** | full banners, historical | key (`SHODAN_API_KEY`) | `/shodan/host/{ip}`; paid tiers meter scans/queries |
| **Censys Search 2.0** | per-host services (`services.service_name`, `services.port`) + cert pivots | API ID/secret, free tier | free tier: **500 results/query, 1 concurrent request** — design for patience |
| **Censys cert pivot** | `parsed.names: <domain>` → hosts holding certs naming our domain | same | new-host discovery, feeds back to the subdomain stage |
| **RDAP / Team Cymru** | IP → org, ASN, prefixes | keyless (`whois -h whois.cymru.com " -v <ip>"`, RDAP per RIR) | ownership edges `BELONGS_TO_ASN` |
| **PTR** | IP → hostname candidates | `dnsx -ptr -l ips.txt -r resolvers` | cheap, in-scope filter, feeds host list |
| **Amass / CT / our own stage** | DNS names already known per IP | free (local) | `dnsx -a -resp` gives name↔IP; dedup against it first |

### 5.2 InternetDB honesty requirements

1. **Freshness flag**: every record gets `intel_age_days` estimated from the
   source's weekly cycle; passive port data older than `PSH_INTEL_MAX_AGE_DAYS`
   (default 14) may *seed* the ladder but may not be reported as current state.
2. **Absence ≠ closed**: InternetDB returning no ports means "Shodan saw no
   open ports recently", not "the host has none" — merge passively-seeded
   nothingness with active confirmation, never collapse them.
3. **404** = Shodan has never scanned that IP (common for IPv6).

### 5.3 Censys query patterns worth building

- Host view: `services.port: *` under `ip: <addr>` → exact service list.
- Domain pivot: `parsed.names: example.com` (and `*.example.com`) → cert-hosted
  discovery into the subdomain stage's input.
- ASN facet: hosts we hold + `autonomous_system.asn: <n>` → coverage check of
  our scan set against the org's known footprint.

### 5.4 Scope policy for network-reachable seeds

CIDRs from Postgres scope are scanned **only** if the scope type is explicitly
CIDR/IP. ASN-derived prefixes are **advisory only** in v1: they surface as
"the org also owns X — not scanned (out of declared scope)" in the report.
Reverse-WHOIS org-name matching (spec Stage 17) is a post-v1 expansion behind
the same gate.

---

## 6. Active layer

### 6.1 The scan ladder

| Level | When | What runs | Cost model |
|---|---|---|---|
| **L0 skip** | IP is CDN/WAF-classified **and** not web-interesting | nothing (80/443 deferred to L2b) | 0 packets |
| **L1 passive-only** | no passive intel, no scope declaration, unknown ASN | nothing active; record "unknown, unscanned" | 0 packets |
| **L2 top-N** | default for dedicated/unknown IPs with any signal | naabu `-top-ports 1000` (SYN or CONNECT) | ≤1000 probes/IP |
| **L2b CDN web probe** | CDN-classified IPs | httpx on `80,443` only (identity/stealth §8) | ≤2 connects/IP |
| **L3 full** | only: scope-declared IPs **or** L2 found ports >0 **or** scoring state ≥ Active | naabu `-top-ports full` (1–65535) | ≤65535 probes/IP, capped per run |

Escalation is one-way (L2 found ports → L3 for that IP) and recorded per IP in
`report.json`, and it is **capped** (`PSH_ESCALATE_MAX`, default 25) because
"earned" is not the same as "affordable" — a target where every IP has an open
port must not silently become a full-range sweep of the estate. The built stage
also reaches L3 for an operator who sets `--scan-level full`; the scoring state
above is the graph-era condition and is the one piece still waiting on S2.

There is **no** L3-by-default: at tesla.com scale (493 hosts
[measured], ~350 scan-eligible after CDN collapse) L2 costs ≈ 350k probes
(350 × 1,000) while all-L3 would cost ≈ 22.9M (350 × 65,535) — a ~65× gap the
ladder spends only on IPs that earn it.

### 6.2 Tool decisions **[research]**

| Decision | Choice | Why (verified) |
|---|---|---|
| Port scanner | **naabu** (`projectdiscovery/naabu` image) | Go speed + PD JSON output + `-exclude-cdn` + `-nmap-cli` handoff + ASN/CIDR input; native to our existing docker_tool plumbing |
| Masscan | **not** in v1 | its defining strength (internet-scale, millions of IPs) is exactly our absent case; different safety model, no JSON streaming, out-of-tree claims need their own verification |
| Scan type | SYN if root/raw, else CONNECT; `-scan-type` explicit | naabu docs: "Running SYN scan with root privileges" / "CONNECT scan with non root"; Docker needs `--cap-add=NET_RAW` (+ `NET_ADMIN` for some discovery modes) — plumbing must try SYN, fall back cleanly |
| Rate control | `-rate` from budget, not tool default | PD docs: increasing rate "may lead to increased false-positive rates" — mirrors our DNS budget finding |
| IPv6 | naabu `-iv 4,6` + `-sa` (scan-all-ips) only where records show AAAA | records.jsonl already distinguishes families |
| Host discovery | **skip** for resolved hosts (existence proven by DNS+stealth-shaped HTTP); `-Pn` equivalent | ARP/ICMP discovery adds noise for near-zero information in our threat model |
| Service naming | **httpx** for HTTP-ish ports (it already speaks our identity profile); **nmap `-sV --version-light`** for the rest, open ports only | version detection is the slow phase; confine it to ≤ dozens of sockets, not thousands |
| nmap handoff | naabu `-nmap-cli 'nmap -sV …'` for per-IP grouping, **or** own `nmap.py` fed by openports.jsonl | own module preferred: naabu's `-nmap-cli` builds one nmap command per IP, which re-scans closed ports and loses our per-port budget accounting |

### 6.3 Per-IP scanning, not per-host

naabu accepts `host:port`-style dedup itself, but our normalizer must collapse
**name → IP** before scanning (scan the IP once, not once per hostname) and
expand **IP → names** afterwards via PTR + reverse mapping from records.jsonl.
Measured impact on tesla.com: 1,380 names → 493 live hosts → far fewer unique
IPs after CDN collapse; scanning per-name would multiply probe volume by ~3×.

### 6.4 Accuracy knobs

- SYN scans at high rates drop SYN-ACKs under loss → raise naabu `-retries`
  above its default on L3; accept the cost.
- CONNECT mode double-checks: a TCP connect that succeeds is *proof*, making it
  the preferred verification for L3 findings when raw sockets are unavailable.
- Every open-port claim records `scan_mode: syn|connect|passive` — the report
  distinguishes "confirmed twice" from "seen once".

---

## 7. Efficiency math (why this design is "most efficient")

**[measured]** tesla.com single-target scale: 1,380 passive names, 493 live
hosts after active+permutation. Assume ~30% of live hosts are CDN-collapsed →
≈ 350 unique scan-eligible IPs.

| Strategy | Probes (approx) | Wall time @ 1k pps | Misses |
|---|---|---|---|
| Naive: nmap -sV full range per host | 350 × 65535 + version probes | days | few |
| Naive: naabu full per host | 350 × 65535 ≈ 23M | ~6.4 h @ 1k pps | lossy without retries |
| **Ladder (this design)** | ~350 × 1000 (L2) + ~50 × 65535 (L3, escalated only) ≈ 3.6M | ~1 h @ 1k pps | CDN-collapsed ports (by policy) |
| Passive-only (InternetDB+Censys) | 0 packets | minutes (quota-bound) | everything not yet indexed (weekly lag) |

The ladder spends its probe budget where signal lives: passive intel seeds
expectation, L2 confirms cheaply, L3 escalates only where L2 found open ports.
Combine with 5.2's freshness rule and 6.4's verification rule and the stage
maximises *confirmed surface per packet* — the only efficiency that matters.

---

## 8. Detection & safety **[research + repo]**

Detection of port scans is **volume-shaped, not fingerprint-shaped**: Elastic's
production rule flags a source hitting *many unique destination ports with ≤2
packets per port* inside a ~9-minute window (`discovery_potential_syn_port_scan_detected`,
threshold type, risk 21). That maps directly onto our controls:

| Control | Setting | Detects-avoidance rationale |
|---|---|---|
| Ports/sec budget | `PSH_MAX_RATE` via naabu `-rate`, derived from stealth pacing caps | stretches unique-port bursts below threshold windows |
| CDN exclusion first | `-exclude-cdn` always on (D2) | cuts the biggest shared-infrastructure blind eye; Cloudflare/Akamai/Incapsula/Sucuri supported by naabu |
| Passive-first | §5 | fewer IPs ever need scanning |
| Ladder | §6.1 | no full-range storms |
| HTTP probes through StealthSession | identity + pacing + detection + quarantine reused verbatim | L2b probes look like the shaped traffic the HTTP layer already emits; WAF/challenge verdicts quarantine IPs exactly like hosts |
| CONNECT fallback | D4 | never fail a run because raw sockets were denied — report the mode and continue |

Bug-bounty reality check **[research: YesWeHack guidance]**: programs must
explicitly permit port scanning; where TOS is silent, the stage defaults to
L2 (top-1000) and passive-only for everything else, with `PSH_SCAN_LEVEL`
env override and the abort-refuses-half-done-runs pattern from the sibling
stage.

---

## 9. Output contract

```
output/
  ips_raw.txt            # seed_builder: one IP per line, canonical, scoped
  passive_intel.jsonl    # {"ip","source","ports","hostnames","tags","vulns","intel_age_days","fetched_at"}
  cdn_classified.jsonl   # {"ip","verdict":"cdn|dedicated|unknown","evidence":[...]}
  openports.jsonl        # {"ip","port","host","scan_mode","source":"naabu|intel|censys","first_seen"}
  services.jsonl         # {"ip","port","service","banner","tls":{"issuer","san":[...],"not_after"},"tool"}
  hosts.txt              # unique IPs (v4 then v6, sorted)
  report.json            # ladder decisions per level-class, budgets consumed, aborts, counts
```

Normalization rules (inherit from sibling `normalize.py` conventions): IPs
canonicalised (v4 dotted-quad, v6 RFC 5952), ports int 1–65535, hostnames
lowercase/trailing-dot-stripped, every JSONL line carries `source`, and
`report.json` distinguishes "found nothing" from "never attempted" (the
L0/L1 ladder decisions make this *structural*, not just textual).

Graph writes (post-S4; out of scope for v1 code but the schema is fixed):
`(:IP)`, `(:IP)-[:RESOLVES_TO]←(:Domain)` enrichment, `(:IP)-[:BELONGS_TO_ASN]→(:ASN)`,
`(:Asset)-[:HOSTS]→(:IP)`, service identity as `USES_TECHNOLOGY` edges with
provenance properties per Appendix A.

---

## 10. Integration with the existing system

1. **Orchestrator position**: runs after `subdomain_domain_wildcards.main`
   produces the union + records.jsonl; consumes `PASSIVE_SUBDOMAINS_FILE`-style
   paths from the sibling stage's `settings.py` (import through its settings
   module, never hardcode — the cross-layer rule from `docs/codebase/CONVENTIONS.md`).
2. **StealthSession reuse**: HTTP probes (L2b, Censys/Shodan/RDAP calls) go
   through `service/recon_pipeline/platform/stealth/session.py`; port scans get their
   own budget knobs (`PSH_*`) but share the pacing clock and quarantine file,
   so an IP that WAF'd our HTTP probe is *also* deprioritised for scanning.
3. **DNS budget**: PTR lookups join the existing `dns_budget` accounting.
4. **Passive-only mode**: when `STEALTH_*` quarantine or `PSH_SCAN_LEVEL=passive`
   is set, the active layer refuses to run and the report says so — the
   graceful-degradation requirement from spec §5.1/§9.
5. **Testing**: same hermetic bar as the sibling stage — fake clock, stub
   docker_tool, canned JSONL fixtures; ~40–60 tests projected across
   seed_builder/normalize/ladder/classify/pipeline.

---

## 11. Edge cases worth their own tests

- **IPv6-only hosts** (AAAA, no A): naabu `-iv 6` path; InternetDB is
  IPv4-primary → expect sparse intel, don't fabricate.
- **CDN on non-standard ports**: `-exclude-cdn` limits CDN IPs to 80/443; a
  Cloudflare-fronted origin exposing 8443 legitimately will be invisible at
  L2 — acceptable, documented, revisitable via explicit `PSH_SCAN_LEVEL=full`.
- **NAT/loopback/documentation ranges** (RFC 1918/5737/3849): normalizer
  refuses to scan or record; spec scoring already kills documentation IPs (−100).
- **Rebinding hosts** (A record changing mid-run): per-run IP pinning — the
  scan targets the IP observed in *this* run's records.jsonl, tagged with the
  hostname's observed IP set for later reconciliation.
- **Wildcard certificates**: SAN `*.example.com` is not an in-scope hostname
  witness by itself (the sibling stage's wildcard suppression already encodes
  the same lesson).
- **Rate-limited passive APIs**: Censys 1-concurrency + 500-result pages →
  paged, patient, retry-after-aware fetching through the pacing layer.

---

## 12. Phased plan

| Phase | Deliverable | Depends on |
|---|---|---|
| P1 | seed_builder + passive/InternetDB + rdap + ptr + normalize + report (passive-only stage complete, no packets) | nothing — immediately buildable |
| P2 | cdn_classify + naabu L2/L2b + ladder + `PSH_*` budgets | P1, docker image pull, `--cap-add=NET_RAW` decision |
| P3 | L3 + retries + nmap `-sV --version-light` module + services.jsonl | P2 |
| P4 | Censys/Shodan keyed sources + cert-pivot feedback into the subdomain stage | P1 + API keys |
| P5 | Graph writes (`:IP/:ASN/:CIDR` + edges) once S4 ingestion exists | S4 |

---

## 13. Research sources (verified Sept 2026)

- Naabu usage/flags (SYN vs CONNECT, `-exclude-cdn`, `-nmap-cli`, `-rate`,
  host discovery, IPv6 `-iv/-sa`, ASN input): docs.projectdiscovery.io/opensource/naabu/running
- Naabu image: hub.docker.com/r/projectdiscovery/naabu
- Shodan InternetDB (keyless per-IP ports/hostnames/CVEs, weekly refresh):
  internetdb.shodan.io; osintph 2026 free-tier comparison
- Censys free tier (500 results/query, 1 concurrent) + Search 2.0:
  docs.censys.com data-access-tiers, /reference/get-started
- Censys cert pivot patterns (`parsed.names`): censys-python docs,
  appsecco/the-art-of-subdomain-enumeration
- SYN-scan detection shape (unique-ports threshold, ≤2 packets/port, ~9 min):
  detection.fyi / Elastic rule `discovery_potential_syn_port_scan_detected`
- Program TOS expectations for port scanning: yeswehack.com recon-guides
  (port scanning attack vectors)
- Prior art on scan efficiency (two-phase split, tool comparisons):
  DivideAndScan (snovvcrash), captmeelo port-scanning trade-offs,
  arXiv 2303.11282 (nmap/masscan/ZMap efficacy)

Repo evidence **[measured]**: `active/output/records.jsonl` (493 hosts, A/AAAA),
tesla.com passive run report.json (1,380 names), `docs/scraper_docs/schema.md`
(scope CIDR/IP), `service/recon_pipeline/platform/stealth/` (session/pacing/quarantine),
sibling stage settings/normalize conventions.
