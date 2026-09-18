# ASN / CIDR — Pipeline Design & Research

**Status:** lookup + emit **implemented**; per-prefix RDAP sweeps and graph
writes designed, not built (see *Phases*).

**Problem.** The names pipeline answers "what hosts exist" and the ports
pipeline answers "what is listening".  Both are bounded by the same input: the
DNS records that happen to resolve *today*.  A host decommissioned last month
leaves no DNS trace; a staging network announced but never named is invisible to
both.  This pipeline asks the question neither can: **which networks does the
organisation hold or announce, and what is inside them that DNS never pointed
at?**

This is asset type **#17 (ASN)** in `recon.md` §3 plus the discovery half of
**#4 (CIDR)**, and it closes a loop the ports pipeline left open: §5.4 of the
design says ASN-derived prefixes never enter the scan set — but no code ever
*produced* them, so the rule had nothing to gate.

---

## 1. Source selection (all keyless, all verified live, 2026-09-18)

| Source | Claim kind | What it answers | Measured behaviour |
|---|---|---|---|
| **RIPEstat Data API** (`stat.ripe.net`) | `announced` (routing) | Which prefixes an AS announces (`announced-prefixes`); which AS(es) announce the prefix an address lives in (`prefix-overview`) | Keyless, no auth; documented 8-concurrent-request limit per IP; `sourceapp` identification parameter sent; `announced-prefixes` on a big AS (AS13335) returned **5 411 prefixes / ~635 KB** in ~20 s. `bgpview.io` and `hackertarget` were unreachable from this network (DNS resolution failures on two separate runs) — RIPEstat was the reliable keyless routing source. |
| **RDAP** (`rdap.org` → IANA bootstrap) | `allocated` (registry) | Which organisation is responsible for which range, with start/end addresses, registry and country | Keyless, bootstraps to the authoritative RIR; measured: `40.104.56.232` → `MSFT` / `NET-40-74-0-0-1` / `40.74.0.0–40.125.127.255`. A 404 is a usable fact (nothing allocated there), distinct from "RIR did not answer". |
| **Team Cymru** (DNS TXT, via the sibling's `rdap.py`) | `announced` | Origin ASN per address (`origin.asn.cymru.com`) — *reused, not re-implemented* | Port 43 whois was unreachable from this host; the DNS-TXT path (which the ports stage already uses) is the reachable one. This pipeline consumes the sibling's `ownership.jsonl` rather than duplicating the lookups. |

Sources **not** chosen, and why:

- **`bgpview.io` / `hackertarget`** — keyless and useful, but both failed DNS
  resolution from this network during R&D.  Not a condemnation of the APIs;
  a note that a single-source design would have shipped dead.
- **`whois.cymru.com` port 43** (the classic netcat recipe) — blocked here, and
  the DNS-TXT equivalent already exists in the codebase.
- **Full-RIR bulk downloads** ( delegated-extended lists ) — the right choice
  for a weekly org-wide diff, wrong for a per-target interactive run (~100 MB
  per fetch).

### Why two claim kinds never blur

The design's §5.4 makes the distinction load-bearing: an **allocation** is the
registry's record of responsibility (as close to ownership as the public
internet offers), an **announcement** is a routing claim that changes with BGP,
not with contracts.  So every network row carries `origin: announcement`,
`allocation`, or `announcement+allocation` when both sources independently
corroborate — and the corroborated row is the strongest fact this pipeline can
produce.  The ports stage's scope gate (declared vs advisory) reads that field;
nothing here scan-authorises.

## 2. Design principles

1. **Never scans.**  The pipeline sends packets to exactly two third-party
   APIs (RIPEstat, RDAP) and none to the target or to anything it discovers.
   Discovery without touch is what makes it safe to run at any stage.
2. **Claims, not truth.**  Every row carries *how we know* (origin classes,
   source set), so a downstream consumer applies the scope gate without
   re-deriving the epistemology.
3. **One row per network.**  The same prefix arriving from two origins folds
   into one row with unioned facts (`merge_claims`), the same identity rule the
   URL pipeline applies to URL spellings.
4. **Caps that say so.**  A Tier-1 seed (AS13335) announces 5 411 prefixes;
   the per-ASN cap keeps the artifact set bounded and records `truncated: true`
   when it bites.  Refused networks (private space, over-narrow VIPs,
   over-wide aggregates) are counted with reasons in `report.json`.
5. **Emits the sibling's format.**  `scope/discovered.txt` is one CIDR per
   line — byte-compatible with the ports stage's scope files — under a
   directory name that says *discovered*, plus an annotated variant
   (`40.74.0.0/16 # allocated — ACME Corporation`) for humans and PR reviews.
6. **Deterministic.**  Sorted at every step; two runs over the same facts are
   byte-identical.

## 3. The live run changed the design (2026-09-18, `qbsco.net`)

- **Aggregate announcements are noise, not footprint.**  The first run recorded
  `40.0.0.0/8` (announced by AS8075) as a discovered network because it contains
  one sibling address — presenting 16 million addresses the organisation does
  not operate.  A **/16 ceiling** (`ASN_MAX_PREFIX_LEN`) now refuses v4
  aggregates and counts them (`refused_wide: 2486` in the measured run).
- **RIPEstat's `block` field bypassed the filter.**  The `prefix-overview`
  block was merged as a claim without passing the ceiling; it now goes through
  the same routability + width gates as everything else.
- **Sibling annotation is the value.**  After filtering, the networks that
  contain addresses the sibling stages actually resolved are the *confirmed*
  set (measured: `103.53.44.0/22` — announced **and** allocated to the target's
  hoster, containing the resolved address — plus the Cloudflare/Microsoft
  allocations behind the CDN/M365 addresses).  The rest is territory DNS has
  never pointed at, which is exactly what an operator wants listed.

## 4. Phases

| Phase | Scope | Status |
|---|---|---|
| **P1** | Seed expansion (address → origin ASNs → announced prefixes; address → RDAP allocation) + merge + sibling annotation | **built** |
| **P2** | Emission: `networks.jsonl`, `asns.jsonl`, `scope/discovered{,.annotated}.txt`, `report.json` | **built** |
| **P3** | Per-prefix RDAP sweep (allocation facts for every announced prefix, not just the seed) | not built — a /22-scale target costs hundreds of RIR queries; wants caching + rate-budget design first |
| **P4** | Graph writes (`ASN`, `CIDR` nodes, `BELONGS_TO_ASN` / `ANNOUNCED_BY` edges) | not built — the whole recon suite is file-only today |
| **P5** | RIPEstat `asn-neighbours` expansion (peer ASNs as second-order seeds) | not built — unbounded for Tier-1 seeds; needs a scoring pass to be worth it |

## 5. References

- RIPEstat Data API: `https://stat.ripe.net/docs/data-api/ripestat-data-api`
  (usage rules, `sourceapp`, 8-concurrent limit; verified live)
- RDAP bootstrap: `https://rdap.org` (IANA redirector; verified live against
  ARIN responses)
- Team Cymru IP-to-ASN: DNS zones `origin.asn.cymru.com` / `AS<n>.asn.cymru.com`
  (already implemented in `../port_service_host/passive/rdap.py`, which this
  pipeline consumes)
- `docs/recon_docs/recon.md` §3 #17 and §5.4 (announced ≠ owned ≠ in-scope);
  `docs/recon_docs/recon_v2.md` S18 (the numbered stage this pipeline
  pre-empts, minus the v2 graph plumbing)
