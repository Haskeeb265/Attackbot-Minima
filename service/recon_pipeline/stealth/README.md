# Stealth & resilience layer (spec §5.1)

Every active step in this pipeline — resolver validation, candidate resolution,
wordlist brute force, permutations, zone-transfer attempts, the opt-in HTTP probe
— is traffic against someone else's infrastructure. This package is the one place
that decides **how that traffic is shaped**, and it is a package rather than a
flag because "don't look like a scanner" is not something a single option buys
you.

It exists in this shape because of what the detectors actually measure. That is
the first section, and everything else follows from it.

---

## 1. What the other side is measuring

The spec's §5.1 asks for five things; the research says which of them pay off,
and in what order.

| Signal the defender computes | What it actually catches | What we can do about it |
|---|---|---|
| **JA3 / JA4** (TLS ClientHello) | A client whose handshake isn't a browser's, at all | Impersonate a real, *common* browser ClientHello |
| **HTTP/2 fingerprint** (SETTINGS, window, priority frames) + header **order** | A client that speaks h2 like a library, or sends headers in an order no browser uses | Real h2 + browser header order, or don't claim to be a browser at all |
| **JA4 Signals — inter-request aggregates** over the last hour of global traffic (`browser_ratio_1h`, `cache_ratio_1h`, `h2h3_ratio_1h`, …) | A *rare* fingerprint, or one that changes mid-session, even when each individual request looks fine | Be common and boring; one stable identity per host |
| **Volume + NXDOMAIN share** per client per base domain per hour | Subdomain brute force, by counting, with no fingerprinting at all | Cap the names any one resolver sees; spread, batch, shuffle |
| **Timing regularity** | A scheduler: perfectly even intervals, tight bursts | Jittered delays, per-host token buckets, backoff |

Two consequences shaped the design more than anything else:

1. **Per-connection spoofing is the easy half.** Cloudflare's own write-up on
   JA4 Signals describes scoring *aggregates of the last hour of traffic*: how
   browser-like a fingerprint is globally and how consistently it behaves. A
   client that rotates identities, or that behaves like a machine, stays an
   outlier no matter how good its ClientHello is. Hence: **stable identities,
   paced requests, and a stated preference for looking ordinary.**
2. **DNS enumeration is caught by arithmetic.** Volume-based analytics flag a
   client resolving more than about 75 unique names of one base domain within an
   hour, compounded by the high NXDOMAIN share a wordlist inevitably has.
   Nothing about that is fixable with a fingerprint; it is fixed by putting fewer
   names per resolver, which is a *planning* problem.

---

## 2. What we measured, not assumed

All captures below are against `tls.peet.ws` / `tls.browserleaks.com`, with this
project's own image (`subdomain_domain_wildcards_image`) and this project's own
argument builders.

**`httpx -tlsi chrome` really does produce Chrome.** Baseline vs impersonated:

| Command | JA4 | Cipher hash |
|---|---|---|
| `httpx` (no flags) | `t13d2511_b78ed14e2fd0_ab7e3b40a677` | Go's own |
| `httpx -tlsi chrome` | `t13d1516h2_8daaf6152771_e5627efa2ab1` | **`8daaf6152771`** — the hash Cloudflare publishes for current Chrome |

So TLS impersonation is not a promise here, it is a measurement. Our
`httpx_args()` passes `-tlsi <profile>` derived from the host's identity, and a
live run through the container confirms the JA4 above.

**The default user agent is a mismatch factory.** `-random-agent` is **on by
default**, and with it the CLI sent — through our own stage — user agents like:

* `Mozilla/5.0 (X11; Linux i686; rv:1.9.7.20) Gecko/ Firefox/3.6.13` (a 2010 UA), and
* `Mozilla/5.0 (Kubuntu; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36`
  — a spelling no browser has ever sent, paired with whichever ClientHello the
  impersonator picked.

The single cheapest fix in this whole layer is `-random-agent=false` plus one
coherent identity, and it is applied unconditionally.

**The CLI cannot send browser header order.** Same tool, same request:

| Path | Headers as received by the server |
|---|---|
| `httpx -tlsi chrome` | `Host, User-Agent, Accept, Accept-Charset, Accept-Encoding, Accept-Language, Priority, Sec-Ch-Ua, …` |
| our `RequestsTransport` | `Host, Connection: keep-alive, Sec-Ch-Ua, Sec-Ch-Ua-Mobile, Sec-Ch-Ua-Platform, Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-User, Sec-Fetch-Dest, …` |

Go alphabetises headers and adds `Accept-Charset: utf-8`, and every CLI request
carries `Connection: close`. Its raw mode (`-unsafe`) preserves order but drops
the impersonation — the JA4 reverts to Go's default. So the CLI can have the real
handshake *or* the real header shape, not both; that is why there is a Python
transport (`transport.py`) and why `curl_cffi` is supported as an optional
backend that gives both.

**Header *name casing* is part of the shape.** Browsers send `User-Agent` and
`Sec-Ch-Ua` over HTTP/1.1; a client that lowercases everything is a mismatch
before any value is read. Identities store headers lowercase (for simple lookups)
and case them for the wire in `identity.wire_case`.

---

## 3. The five pieces

| Module | Job |
|---|---|
| `identity.py` | Coherent browser identities (UA ↔ Client Hints ↔ header set ↔ ClientHello), one **stable** identity per host. `verify()` fails a profile whose parts contradict each other, so a bad edit breaks tests instead of a target. |
| `pacing.py` | Per-host token buckets (2/s sustained, small burst), centred jitter, exponential backoff, `Retry-After` cooldowns, and a hard per-host request ceiling — on an injectable clock. |
| `detect.py` | WAF fingerprints (Cloudflare, Akamai, Imperva, DataDome, PerimeterX, Fastly, CloudFront, F5, FortiWeb, …), challenge-page markers, `Retry-After` parsing, and a `Verdict` the rest of the system acts on. |
| `quarantine.py` | Persistent per-host and per-WAF quarantine with TTL, escalating to a passive-only run when one WAF challenges several hosts. |
| `dns_budget.py` | Per-resolver unique-name budget, keyed shuffle of candidate order, resolver rotation, batch planning, and the `--rate-limit` value the tools are given. |
| `transport.py` | Request transports with an honest capability report: `curl_cffi` (real ClientHello + h2 + order) > `requests` (real order, Python TLS) — and it says which one ran. |
| `session.py` | The chokepoint: gate → pace → send → classify → record. A stage that touches the network without one is a bug. |

### Deliberate design choices

* **Stable, not rotating, identities.** `IdentityPool.for_host` is deterministic
  in `(host, salt)`, so a re-run presents the same identity to the same host.
  Rotating a browser per request is a *rarer* pattern than any single tool
  fingerprint; the winning move is to be unremarkable.
* **A block must be evidenced before it silences a host.** A challenge marker
  (`__cf_chl`, `_Incapsula_Resource`, "Just a moment") is enough; the word
  "captcha" on a login page is not, and neither is a bare 403 — that is a
  finding, not a block. An over-eager detector throws away real attack surface.
* **A served challenge stops work immediately** (one incident is enough), while a
  plain WAF denial has to repeat. Challenges mean "stop"; denials often mean "not
  this path".
* **Volume is capped by planning, not by slowing down.** `N` names over `R`
  resolvers is `N/R` names per resolver *regardless of query rate*. The budget is
  therefore enforced by batching and rotation, and the plan says out loud when
  the pool is too small — it never silently drops coverage.
* **Wordlist order is the one thing we do not shuffle.** The operator's priority
  order drives recursion's first-N shortlist; a generic list's order reveals
  nothing target-specific. Candidate and parent lists *are* shuffled, keyed on
  the target, so the order is reproducible for us and not precomputable for
  anyone else.
* **Quarantine state is shared state, on disk.** It lives in the stage's
  `output/quarantine.json` (not in the per-run artifact directory) precisely so a
  cooldown triggered in one stage or run is respected by the next. Redis would be
  the multi-worker answer; it is not in this stack, and the interface would not
  change if it arrived.

---

## 4. Knobs

Every value is an environment variable with a documented default; nothing needs
editing to tune.

| Variable | Default | Meaning |
|---|---|---|
| `STEALTH_PASSIVE_ONLY` | `0` | Refuse all active technique, in every stage |
| `STEALTH_IDENTITY` | *(per host)* | Pin one identity profile for the whole run |
| `STEALTH_IDENTITY_SALT` | target | Seed for per-host identity choice |
| `STEALTH_HOST_QPS` / `STEALTH_HOST_BURST` | `2` / `4` | Per-host HTTP rate and burst |
| `STEALTH_JITTER` | `0.35` | Timing jitter as a fraction of each delay |
| `STEALTH_BACKOFF_BASE` / `_MAX` | `1.0` / `60` | Exponential backoff bounds |
| `STEALTH_MAX_RETRIES` | `2` | Retries per request |
| `STEALTH_DNS_NAMES_PER_RESOLVER_HOUR` | `60` | The volume budget (below the ~75 detection threshold) |
| `STEALTH_DNS_BATCH_SIZE` | `500` | Names per resolver window |
| `STEALTH_DNS_BATCH_SPACING` | `20` | Jittered seconds between batches |
| `STEALTH_DNS_QPS` | `100` | Total query rate across the pool (`0` = unlimited) |
| `STEALTH_DNS_SHUFFLE` / `STEALTH_DNS_SEED` | `1` / target | Candidate-order shuffling |
| `STEALTH_QUARANTINE_TTL` / `_FAILURES` | `3600` / `3` | Cooldown and repeat threshold |
| `STEALTH_QUARANTINE_FILE` | stage `output/quarantine.json` | Where quarantine persists |
| `ACTIVE_STEALTH` | `1` | Stage-level switch for the whole layer |
| `ACTIVE_HTTP_IMPERSONATE` | `1` | `httpx -tlsi` on the HTTP probe |

---

## 5. Measured cost (live, `tesla.com`)

A real run of the active stage with the layer enabled, 2,083 candidates and 755
brute-force labels:

| | Stealth on | Stealth off (previous behaviour) |
|---|---|---|
| Wall clock | **193 s** | ~64 s |
| Live hosts found | **493** | 493 |
| Deliberate waiting | 48 s (2 pauses across 3 batches) | 0 |
| Resolver tools run | 4 (3 budgeted batches + 1 brute force) | 1 |
| AXFR attempts | 6, spaced ~5 s, all refused | 6, back-to-back |
| Names per resolver | up to **111** | ~81 |

The honest reading of that table: **the stealth layer costs about 3× wall clock
and found exactly the same hosts.** It also reported that the current resolver
pool is still *too small* to keep the run inside the volume budget (1,378 names
over 17–24 resolvers ≈ 111 per resolver, against a 60 budget, needing 23+ or two
hourly windows). That note is the feature: it tells an operator what it would
take, instead of quietly exceeding the threshold or quietly dropping names.

---

## 6. What this layer does **not** do

* **No proxies, and no identity spoofing.** Requests come from this host's IP.
  Pools, rotation and health scoring are the spec's next step (§5.1) and would
  slot in behind `transport.py` without touching callers.
* **No CAPTCHA solving.** A challenge is treated as a stop signal — solving them
  is a different activity with a different authorization posture.
* **`curl_cffi` is optional and, in this environment, not installed.** The
  capability is implemented, reported, and exercised by tests; without it the
  session falls back to `requests` and the report says `tls_impersonation:
  false` with the reason. The live captures above show both halves of that
  trade-off (real order, Python JA4).
* **The bulk HTTP probe uses one identity for the batch**, because the CLI takes
  one header set per invocation. Per-host identities are honoured by the Python
  transport, which is the paced follow-up path; the stage's report records which
  identity the batch used.
* **No live block was ever provoked.** Detection is verified against fixtures
  that reproduce Cloudflare/Akamai/Imperva/DataDome challenge responses, plus
  live requests to a benign host to prove ordinary pages are *not* flagged. No
  target was made to challenge us in order to test the code.
* **Rate-limit "decay" in `IMPLEMENTATION_PLAN.md` is a different thing** — that
  is an adaptive *token rate* for a throttled source. Score decay is gone from
  the scoring model entirely (see §7 below).

---

## 7. Relationship to the scoring model

The ASM spec's original scoring model multiplied each signal by an exponential
time-decay term. That model is **removed** throughout the docs: a score is a
function of observed evidence, never of the clock. Staleness is expressed as
*evidence* — a parking page, NXDOMAIN for more than 14 days, an expired
certificate, a dangling CNAME — each of which is an explicit penalty or a
withdrawn signal, re-verified by the S11 refresher. Reasons: scores stay
reproducible from the graph alone, a cached score always agrees with a
recomputed one, and nothing is demoted merely for being old.

## 8. Tests

`tests/recon/test_stealth_*.py` (129 tests) and `tests/recon/test_stealth_wiring.py`
cover the layer hermetically — no Docker, no DNS, no network:

* identity coherence (version/platform/hint contradictions are caught),
  per-host stability, and the header casing/order invariants;
* token buckets, jitter bounds, backoff escalation, `Retry-After`, per-host
  ceilings, all on a fake clock;
* challenge/blocks across the WAF signature table, plus the **false-positive
  guards** that keep healthy hosts out of quarantine;
* quarantine thresholds, TTL expiry, persistence across runs, corrupt-file
  tolerance and WAF escalation to passive-only;
* the DNS volume arithmetic (`required_resolvers`, `hours_needed`, strict mode,
  shuffle determinism, rotation);
* transport capability reporting and the exact prepared header order;
* the wiring: `httpx_args` flags, response-header normalisation, quarantined
  hosts never being probed, AXFR spacing, and the passive-only gates in both
  stages and the orchestrator.
