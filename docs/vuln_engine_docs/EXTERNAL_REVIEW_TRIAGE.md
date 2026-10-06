# External review triage — "what's hindering the engine?"

Three reviews of `VULN_ENGINE_MASTER_REFERENCE.md` were collected (DeepSeek, Claude,
ChatGPT). Every claim below was checked against the code on this branch before it
was accepted; where a reviewer was wrong or overstated, that is said. What follows
is the merged, verified diagnosis and the order the fixes went in.

## Verdict table

| # | Claim | Source | Verdict | Evidence |
|---|---|---|---|---|
| 1 | Capability gating requires *declared* claims; the engine cannot establish them | all three | **Correct — the #1 bottleneck** | every `surfaces()` gate reads `surface.capability == CAP_*`; the graph bridge supplies only `public_param`; two of eight techniques fire from recon alone (`seed/from_graph.py`, measured in the docs) |
| 2 | SQLi/command-injection proof shows *a delay*, not *SQL interpretation* | ChatGPT | **Correct and the sharpest catch of the three** | `TimingVerifier` proves `median(injected) - median(baseline) >= margin` and nothing more; the same grammar and oracle serve both classes, so the finding's *class attribution* rests entirely on which folder proposed it |
| 3 | IDOR/authorization proof is status-code-only | ChatGPT + DeepSeek | **Correct** | `AuthorizationVerifier` buckets only statuses; a 200 carrying an empty/neutral body is indistinguishable from a 200 carrying the object — both "allowed" |
| 4 | The technique corpus is small | all three | **Correct but not the bottleneck** | 8 folders; yet a correct technique added today still cannot fire on a graph-derived surface (claim #1). Adding techniques before fixing #1 widens an inert corpus |
| 5 | Surfaces are too impoverished (no body/path/header, no method) | ChatGPT, DeepSeek | **Partly correct** | `where="body"` is fully supported by the timing/oob grammars (`json_body_request`, `BODY_VARIANTS`); the real gap is that the *graph bridge* never emits body/path surfaces — a supply limit, not a contract limit |
| 6 | The LLM is too quarantined; starved of response bodies | DeepSeek, ChatGPT | **Correct but low priority** | quarantine is a deliberate, documented invariant (prompt-injection safety). Loosening it is a product decision, not an obvious fix; nothing here does it |
| 7 | UCB/cost scheduling starves expensive techniques | DeepSeek | **Overstated** | the browser ×3 multiplier exists, but an untried arm returns `inf` and always wins once; cost only orders *untried* arms and divides reward of tried ones. Not where recall dies |
| 8 | Receipt settlement suppresses retesting | ChatGPT | **Overstated** | `--force` exists precisely for retesting; `failed` outcomes never settle. The arm-level key is coarse, but it is not the recall ceiling |
| 9 | No stateful workflows / auth automation | ChatGPT | **Correct** — large, deferred | real, but a workstream of its own; not started here |
| 10 | Gate strictness, HTTP/1-only, DNS OOB, etc. | DeepSeek | **Correct** — known, documented limits | recorded in the master reference's own "measured limitations" |

## What was actually done

The three highest-leverage, code-verifiable items were implemented on this branch:

1. **Capability Closure** (review claims #1/#4/#5's root) — the preconditions a
   technique gates on become *measured facts* the engine can establish itself,
   not strings only the operator can declare. See `RND_dynamic_preconditions.md`
   for the design; `service/vuln_engine/elicit/` for the implementation.
2. **Timing proof gets a causal discriminator** (claim #2) — a fresh timing
   separation alone is no longer sufficient for a `differential` finding; the
   verifier must also observe the SQL dose-response signature (delay scales with
   the sleep argument, delay appears and disappears with payload presence) before
   it will prove the claim, and the evidence carries the discrimination data.
3. **Authorization proof reads content** (claim #3) — session B's 200 is compared
   against session A's representation by length and body hash; a 200 that carries
   a different (including empty) representation from A's is a refusal, not a
   finding, with the fresh evidence attached.

Deliberately *not* done (agreed deferrals, each a workstream of its own):
stateful workflow modeling (#9), LLM quarantine loosening (#6), technique-corpus
expansion (#4 — inert until #1 ships anyway), transport widening (#10).

## Two things the reviews missed

- **The evidence-lattice collision is real but bounded**: `sqli_blind_time` and
  `command_injection` share the `timing.differential` verifier, so at most one of
  them can ever be proven on one surface (the first proven verdict settles the
  arm). With the discriminator the attribution improves from "some timed
  processing" to "the delay tracks the SQL dose", which is the honest line a
  black-box instrument can draw.
- **Capability Closure subsumes several "missing" complaints**: the capability
  agent's refusal to run `sqli` because recon never claimed `delayed_response`,
  the two-techniques-can-fire-from-graph complaint, and the "capabilities should
  be discovered, not declared" inversion are all the same defect, and this
  mechanism fixes them at the root rather than patching each symptom.
