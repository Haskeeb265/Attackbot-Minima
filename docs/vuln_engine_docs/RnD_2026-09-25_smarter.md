# Making the engine smarter — RnD addendum (2026-09-25)

**Status: research. Nothing here is implemented; nothing below modifies the
engine.** A third pass, narrower than [`RnD_2026-09.md`](./RnD_2026-09.md):
it starts from what the engine *measured on a live target this week* and from
what was **built this week** (junction 4 — hypothesize — and the campaign
widening seam), then asks one question: what makes the next live run produce a
lead the current run could not?

## 0. The measured baseline (this is where the smartness must come from)

The e2e run against `try.discourse.org` (discourse program, scraped scope):

| Stage | Number | What it says about intelligence |
|---|---|---|
| Scraper → scope | 1 URL (`try.discourse.org`) | scope was never the bottleneck |
| Recon | 2,172 URLs → 2,090 endpoints, **35 params**, 11 JS bundles, 74 verified-alive URLs | the raw material for smartness already exists |
| Hand-declared surfaces | **3** | the operator, not the engine, was the narrowest stage |
| Junction 4 widening | **+12 validated surfaces** (1,096 known URLs, 0 invented) | the model widened attention 4× beyond the operator's picks |
| Manifest arms | 6 hypotheses / 30 probes, **0 findings, 0 leads** | honest zero over a hardened target |
| Campaign rounds | 2 of 4 spent on junction-proposed surfaces | the scheduler *used* the widening (round 0: `oob_fetch` on `preview-style`) |

Reading: the pipeline's two blind spots are (a) **one probe pass per arm** —
the manifest loop observes, concludes `none`, and stops; there is no
*investigation*; and (b) **five vuln classes**. Everything below serves one of
those two, in priority order.

## 1. The literature this pass adds (beyond the September refresh)

- **Red-MIRROR** (arXiv 2603.27127, Mar 2026): multi-agent pentesting with a
  tightly coupled **memory–reflection backbone** — after each interaction the
  agent reflects on *what the response taught it* and updates a structured
  memory that shapes the next action. The transfer is not "add an agent"; it
  is the loop shape: observe → reflect → re-plan within one engagement.
- **OpenAnt** (arXiv 2606.19149, Jun 2026, open source): a **funnel**, not a
  scan — reachability filter (−97%) → exposure classification (−87%) →
  detection → **adversarial verification under a constrained attacker model**
  (browser-only, no creds) → dynamic confirmation in ephemeral sandboxes.
  Each stage discards; cost is spent only on what survives. Their
  constrained-attacker simulation is the missing *pre-probe* judge for our
  hypotheses.
- **Dual-session IDOR agent** (arXiv 2605.23243): maintains **two
  authenticated sessions**, enumerates parameterized endpoints from the API
  surface, and executes **differential access checks** — the canonical
  authorization-test loop, now published as an agent pattern.
- Reconfirmed from the September refresh: AWE's per-class specialized
  pipelines (87% XSS on XBOW at $7.73/run), the TDA difficulty dimensions
  (cut Type-B failures 58→27%), ARTEMIS's 82% valid-submission precision bar.

## 2. The moves, ranked by (expected yield ÷ effort), mapped to our seams

### M1. Probe-2: make the loop iterative, not one-pass — *the highest-leverage change*
Today: `hypotheses(surface)` → `probes()` → `interpret()` → verdict, once.
The literature's convergent shape (Red-MIRROR, AWE's filter inference, EGATS)
is a **bounded investigation loop per surface**: propose → observe → *reflect
on the response* → adapt the next probe → stop on evidence or budget.

Concrete seam: a **junction 5 (reflect)** between observation and verdict,
mirroring junction 4's discipline — pure module in `llm/`, thin runtime,
logged as `llm.junction`, degraded = exactly today's behavior. Input: typed
observation fields only (contexts seen, marker mutations, status/timing
deltas) — **never raw response bodies** (the quarantined-LLM rule already
enforced by `write.finding_input`'s whitelist generalizes here). Output: a
validated *next-probe choice from the technique's own grammar* (the
`ProbeGrammar` rows already exist for xss_reflected) — the model picks among
the technique's declared frontier, it never invents payloads. Budget: ≤2
extra propose-probes per surface, declared in noise terms like everything
else. Measured first on DVWA `sqli_blind` (the fixture `/delay` already
answers payload *families*, per its own docstring — the loop is testable
offline).

### M2. Session shim 2.0 → the authorization class (IDOR) — *the yield class we do not cover at all*
Five of our five techniques are unauthenticated-shaped. The dual-session
pattern maps onto the engine cleanly: a **second cookie jar** (operator
declares both — same boundary as today's `--cookie`), a technique whose
hypotheses are "endpoint X, object id N, session A sees it, session B must
not", and a verifier whose confirmation is a **differential re-measure**
(both sessions, fresh) — the exact independence shape `timing_differential`
already has. IDOR/authorization is perennially the #1 paid web class; this
one technique adds more bounty-area than any model improvement. The `delayed_response` capability pattern shows how a *claim* gates a technique; a
`cross_account_readable` capability claim is the same move.

### M3. The hypothesize junction, fed better blood — *cheap, compounding*
Three concrete upgrades, all inside the existing validated-proposal
contract:
1. **JS-bundle awareness**: feed `url_endpoint`'s `javascript.txt` +
   extracted JS endpoints (today: only `parameters.jsonl` +
   `url_validation.jsonl`). The model reads client-side route/param
   structure no archive captures. (Still: proposals must name URLs recon
   observed — extend the observed set, not the model's freedom.)
2. **Recon-graph reachability**: the Neo4j graph knows which hosts are
   alive, which are CDN-fronted, which share certificates. Rank proposals
   by reachability instead of observation count.
3. **Post-run reflection → next-run memory** (AWE's long-term memory, the
   safe form): after a campaign, ask the model to summarize which surface
   *shapes* answered unusually (contexts seen, timings) into a JSON memory
   file. Feed it into the next run's hypothesize input. Cross-target,
   no fine-tuning, fully loggable — and replayable because the memory file
   is an input, not a side channel.

### M4. OpenAnt's funnel as the pre-probe judge — *precision, which ARTEMIS proved is the credibility metric*
Before any live probe on a widened surface, a **constrained-attacker
simulation**: the model receives the typed surface description and must
construct the exploitation path *under our attacker model* (black-box HTTP,
declared cookies, no OOB unless the collaborator is wired) or the hypothesis
is parked as `unfunded`. This is a **rank-class prior, not a gate** —
surfaced as an arm prior ceiling-capped at 0.4 exactly like `rank`, because
a wrong simulation must never suppress a measured probe. Cost: one small
call per new surface; benefit: the host budget stops being spent on
structurally hopeless surfaces (the `loadedAllPosts=false` class).

### M5. Difficulty assessment (TDA) over arms — *the scheduler gets situational awareness*
PentestGPT v2's four dimensions are all derivable from our own ledger:
horizon ≈ probes-since-lead per arm; evidence confidence ≈ the S2-style
scoring we already run on recon nodes; context load ≈ observations per
surface; historical success ≈ receipts. Feed them into `ucb.pick` as the
bandit's context (the doc's §10 "contextual bandit" flag, now with published
ablation numbers: Type-B failures 58→27%).

### M6. Fifth technique-class additions, in bounty-value order
IDOR (M2) → **open-redirect** (pure reflection-class, the junction's
`origin` pick practically asked for it) → **CORS misconfig** (header
reflection, zero noise) → SSRF-with-collaborator variants beyond `/fetch`
(the `oob_fetch` technique generalizes; the capability claim is the only new
thing). Each is a folder under `techniques/` — the architecture's whole
point is that this list costs nothing else.

### M7. Explicitly deferred (the September refresh's own warnings stand)
Summarization-for-context machinery (eroding as models improve); fully
autonomous chain exploitation (beyond current systems per PentestGPT v2's
own limits); EPSS/prioritization metrics (upstream of an engine that has not
yet produced its first live lead); MCP tooling (we have one door, by design).

## 3. The experiment that decides (repeatable, cheap)

The claim "M1 makes the engine smarter" is testable in a day on existing
infrastructure: **DVWA-low + Juice Shop + fixture** with ground truth already
pinned in `benchmarks/vwas/*/case.json` (the VWA proposal's v2 schema exists;
tier-1 ground truth is transcribed). Run three configurations —
manifest-only, +widening (today), +widening+reflect-loop — same budgets.
Metrics: leads before confirmation, probes-to-conclusion, FP count, tokens.
If the reflect loop does not move leads-before-confirmation on DVWA's blind
SQLi (where the differential is unambiguous), the whole M1 direction gets
killed early — which is the point of measuring before building.

## 4. One-paragraph answer to "how do we make it smarter"

The engine is honest but static: it looks where it is told, once, and
concludes. The field's proven answer is not a bigger model — it is (1) a
**loop** (reflect on what the response taught you, adapt within budget),
(2) **coverage of the classes that pay** (authorization first), and (3) a
**funnel** (spend probes only on hypotheses a constrained-attacker
simulation can actually fund), all wrapped in the discipline we already
have: proposals validated against observed reality, every model word logged
and replayable, confirmation owned by the verifier. We built the seed
this week; M1 and M2 are the next two orders of magnitude.
