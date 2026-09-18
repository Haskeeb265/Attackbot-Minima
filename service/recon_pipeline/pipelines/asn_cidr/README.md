# asn_cidr — network-ownership discovery (ASNs & CIDRs)

**What it answers:** which networks does the target hold or announce — and
therefore which address space exists that DNS never pointed at?  Asset types
#17 (ASN) and the discovery half of #4 (CIDR) in `docs/recon_docs/recon.md` §3.

The sibling pipelines are bounded by what DNS resolves today; this pipeline is
not.  It is **keyless, Docker-free and never scans** — it reads third-party
routing/allocation registries and writes artifacts, one of which
(`scope/discovered.txt`) is byte-compatible with the ports stage's declared
scope input while being marked `discovered`, so the ports stage's own scope
gate decides what may ever be touched (design §5.4: announced ≠ owned ≠
in-scope).

## Pipeline

```
seeds     sibling addresses (ports stage) + --asn / --address overrides
   ↓
lookup    RIPEstat  → prefixes each origin AS announces      (routing claim)
          RDAP      → the allocation range behind an address (registry claim)
   ↓
merge     one row per network; origins unioned; corroborated rows marked
   ↓
annotate  which networks contain addresses the sibling stages already resolved
   ↓
emit      output/networks.jsonl · output/asns.jsonl
          output/scope/discovered.txt        (bare CIDRs — machine format)
          output/scope/discovered.annotated.txt (CIDR # class — holder)
          output/report.json
```

## Sources

| Source | Claim | Keyless | Notes |
|---|---|---|---|
| RIPEstat Data API | `announced` | yes | `sourceapp` identification sent; caps recorded when they bite |
| RDAP (`rdap.org`) | `allocated` | yes | 404 = "nothing allocated there" (a fact), ≠ "RIR unreachable" (a failure) |
| Sibling `ownership.jsonl` | both | — | consumed, not re-queried: the ports stage already resolved per-address ownership |

R&D evidence for these choices (including the APIs that failed DNS resolution
from this network during research) is in [`DESIGN.md`](DESIGN.md).

## Outputs

| File | Contents |
|---|---|
| `networks.jsonl` | one row per network: canonical CIDR, origin classes, ASNs, org, country, sources, known-host count |
| `asns.jsonl` | per-AS rollup (name, network count, origin kinds) |
| `scope/discovered.txt` | bare CIDR per line — the ports stage's scope-file shape, **marked discovered, never scan-authorising** |
| `scope/discovered.annotated.txt` | same networks with inline `# class — holder` comments |
| `report.json` | counts (raw claims, merges, refusals by reason, source failures), per-source status, seeds |

## Flags

| Flag | Purpose |
|---|---|
| `-t, --target` | apex domain (default: `TARGET` from `.env`) |
| `--asn` | direct AS seed, repeatable (`--asn 400771`) |
| `--address` | direct address seed, repeatable (default: sibling artifacts) |
| `--no-sibling-input` | ignore sibling-stage artifacts; seeds only from flags |
| `--output-dir` | output directory |
| `--timeout` | per-request seconds |
| `-v` | debug logging |

Exit codes: `0` clean; `1` completed with source failures; `2` refused (bad target).

Environment: `ASN_RIPESTAT_ENABLED`, `ASN_RDAP_ENABLED`, `ASN_MAX_PREFIXES_PER_ASN`,
`ASN_MIN_PREFIX_LEN` (default 24 — drops VIP-scale announcements),
`ASN_MAX_PREFIX_LEN` (default 16 — drops /8-scale aggregates; measured live),
`ASN_HTTP_TIMEOUT`, `ASN_HTTP_RETRIES`.

## Measured (2026-09-18, live, `qbsco.net`)

- **71.7 s**, 0 source failures: 77 985 raw claims → **3 422 networks**
  (3 417 announced, 6 allocated, **1 corroborated**), 2 486 refused networks
  (all aggregates above the /16 wall), 2486 refusals counted not hidden.
- **Confirmed territory** (networks containing sibling-resolved addresses):
  `103.53.44.0/22` — announced **and** allocated to the target's hoster — plus
  the Cloudflare and Microsoft allocations behind the CDN/M365 addresses.
- The /16 ceiling exists because the first run presented `40.0.0.0/8` (a
  Microsoft routing aggregate containing one target address) as a discovered
  network.  Measured, filtered, documented — see `DESIGN.md` §3.

## Not built

- **Per-prefix RDAP sweeps** (P3) — allocation facts for every announced
  prefix, not just the seed; wants a rate budget before it is polite.
- **Graph writes** (`ASN`/`CIDR` nodes, `BELONGS_TO_ASN`/`ANNOUNCED_BY` edges)
  — file-only like every sibling today.
- **Peer-ASN expansion** (RIPEstat `asn-neighbours`) — unbounded for Tier-1
  seeds; needs scoring.

## Related

- [`DESIGN.md`](DESIGN.md) — source choices, live-run lessons, phases.
- `../port_service_host/README.md` — the consumer of the discovered scope
  files, and owner of the declared-vs-advisory gate.
- `../port_service_host/passive/rdap.py` — the per-address ownership lookups
  this pipeline reuses instead of duplicating.
- `../url_endpoint/README.md`, `../subdomain_domain_wildcards/README.md` — the
  other asset pipelines.
