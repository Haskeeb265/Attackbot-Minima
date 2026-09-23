# Vuln engine design thesis — module contracts, owned primitives, campaign properties

Response to three constraints set on 2026-09-20, after the
[`RnD_2026-09.md`](./RnD_2026-09.md) refresh:

1. **The engine is a puzzle** — loosely coupled, independently replaceable
   modules (the DeepSeek-harness property: the reasoning core is a
   component; the harness owns everything else).
2. **No readymade-tool wrapping as the core** — first-class primitives,
   engineered for an edge, not for the bare-minimum "pentesting" bar.
3. **The scope exceeds bug bounty** — the engine should be built so that
   long-horizon, patient, adaptive operation is a native property, not a
   bolt-on.

Ground rule for this document: it sets **design direction and invariants**,
not implementation decisions. "APT-grade" is treated here as an engineering
bar — patience, statefulness, adaptivity, low signature, owned primitives —
applied to *authorized* engagements. C2 infrastructure, malware, and
defender-targeted evasion are out of scope and none of what follows needs
them; the legitimate translation of the APT lens is *"what does tooling
look like when the operator can afford to wait weeks and cannot afford to
look like a scanner?"* — the same question serious authorized red-team
tooling answers.

---

## 1. The kernel: contracts before modules

The recon platform's real innovation is the pipeline contract — add a
folder, get a pipeline, discovered at runtime. The vuln engine inherits
that pattern but raises the bar: **modules must be pure at their
boundaries**, so that any module can be removed, replaced, or tested in
isolation without the rest of the engine knowing or caring.

### 1.1 The six contracts

| Contract | Owns | Never does |
|---|---|---|
| **Effect** | All network/system interaction: every request, connection, browser action, OOB interaction | Contain technique logic; know what an XSS is |
| **Observation** | Typed, structural readings of the world | Exist as raw text blobs |
| **Technique** | Hypothesis → probe-spec → interpretation for ONE vulnerability class | Perform I/O; hold clock; call the LLM |
| **Verification** | Independent confirmation of a candidate, using a *different evidence class* than the hypothesis source | Reuse the proposer's reasoning chain |
| **Scheduler** | Ordering, budgets, and pruning over an attack tree | Know technique internals; touch the network |
| **World model** | Append-only event log + derived views (graph, receipts, scores) | Hold mutable state anywhere else |

Two rules make the puzzle property real rather than nominal:

1. **All I/O passes through Effect, and Effect passes the policy gate.**
   There is exactly one chokepoint (the existing `dispatch.py` semantics:
   ALLOW/DEFER/DENY with reasons, deny-by-default, budgeted). A module
   that cannot reach the network directly cannot bypass scope — the gate
   is structural, not conventional. This is also what makes the engine
   *replayable*: an engagement is a log of effects and observations, and
   the log is sufficient to reproduce every downstream decision offline.
2. **Techniques are pure functions.** Same discipline as the platform's
   `scoring.py` (pure, no I/O, no clock, audit trail). A technique takes
   typed observations and returns probe specs and evidence. Determinism
   at module level is what makes offline testing (replay harnesses,
   NASim-style dry runs, regression against disclosed-report replays)
   possible without touching a single real target.

### 1.2 The LLM's position: pinned, typed, advisory

The harness owns everything the DeepSeek-harness framing externalizes:
state, protocols, tools, memory. The LLM appears only at **named,
typed junctions** with logged inputs and outputs:

- **Hypothesis ranking** — which candidates deserve the next unit of budget
  (advisory to the scheduler; the scheduler's UCB math remains
  deterministic).
- **Payload synthesis within a grammar** — a technique's interpreter
  defines the probe grammar; the LLM fills it. Never free-form payload
  generation against third-party scope (the VulnBot objection from the
  first feasibility notes stands).
- **Report prose** — findings → human-readable report, from structured
  evidence only.

Every junction is replayable and cacheable, and — like `enrich.py` — every
one is advisory: with no key, the engine degrades to deterministic
behavior, never to silence. AWE's result (specialized pipelines matched a
GPT-5 generalist's injection results at 2% of the tokens) is the evidence
that this position, not a model-as-orchestrator position, is the efficient
one.

### 1.3 Module shape

```
service/vuln_engine/
  kernel/          contracts only: Effect, Observation, Technique, Verdict,
                   Budget, Evidence, NoiseProfile (no logic)
  transports/      http1, http2, browser, oob — swappable implementations
                   behind Effect; each reports capabilities (stealth-style)
  techniques/      <class>/  hypothesis.py · probes.py · interpret.py ·
                             manifest.json (preconditions, postconditions,
                             noise profile, evidence classes)
  verification/    browser-runner · differential · oob-correlator
  scheduler/       attack tree + UCB selection over receipts/history,
                   noise-budgeted
  world/           event log (append-only JSONL, platform conventions)
                   + derived views (graph, chain candidates)
  memory/          case store keyed by structural features, not targets
  llm/             the typed junctions + prompt registry + replay cache
  policy/          wraps platform dispatch; the only caller of Effect
```

One folder = one technique, same as one folder = one pipeline. Adding
SSTI support must never require editing anything outside
`techniques/ssti/` — if it does, the contract is wrong.

---

## 2. Owned primitives: where the edge actually is

The published systems we reviewed wrap readymade tools (nuclei, sqlmap,
nmap) behind an agent loop. That is the *bare-minimum* architecture — it
passes the boundary the user named, and no further. The R&D refresh
shows the field's best results come from owning the loop (AWE at 98% fewer
tokens); the sharper point is that **the highest-value technique families
are structurally closed to wrapper architectures**. Owning these is the
edge:

### 2.1 A framing-level HTTP engine

Desync-family research (PortSwigger's four waves, through the 2025
"HTTP/1.1 Must Die" work and the 0.CL technique) is *about the client*.
A scanner that sends payloads through a generic HTTP library cannot
observe or manipulate framing, cannot hold connection state across a
smuggled-request boundary, cannot run the probes at all. This is the
clearest case where readymade tools are not just worse — they are
*incapable*. Owning the HTTP stack (HTTP/1.1 and HTTP/2 semantics,
canonicalization quirks, connection lifecycle) opens technique families
that generic scanners cannot express, at any price.

Secondary payoff: one shared client means one coherent traffic identity —
no subprocess-spawn noise, no tool-characteristic request shapes (see §3.4).

### 2.2 An observation model with structure in it

The least glamorous and most load-bearing primitive. Observations must be
typed and structural — DOM context maps (quoted/unquoted attribute, JS
string, raw HTML), sanitization transforms (character-level, tag-family),
byte-accurate diff signatures, timing distributions, OOB interaction
records — not "the response text". Two reasons this is the edge:

- **It is what makes learning possible.** A template scanner cannot learn
  because its observations don't preserve what mattered. With structural
  observations, the memory layer and the scheduler's historical-success
  signal actually have something to generalize over. AWE's filter-inference
  step is this insight applied to one class; done at the platform level it
  applies to every class.
- **It is what makes verification cheap.** "Reflected, looks like XSS" is a
  lead; "script executed in DOM context X after mutation Y" is a finding.
  The evidence vocabulary has to exist in the observation model before any
  verifier can use it.

### 2.3 A technique grammar, not templates

Templates-as-data was Nuclei's genuine breakthrough — it made techniques
enumerable, diffable, community-extensible. The next step past it: a
**declarative probe grammar + interpreter**. Techniques are expressed as
structured probe specifications (parameter positions, context constraints,
mutation operators, oracle predicates), and the engine can enumerate and
mutate the space the template author never wrote. This is also the *safe*
place for LLM involvement: grammar-guided synthesis, where every generated
probe is validated against the grammar before Effect ever sends it. The
GreyNoise PoC-pollution finding (broken AI-generated exploits flooding
public repos) is precisely what grammar-validation prevents.

### 2.4 Verification as a first-class engine, and OOB you own

Verification is the most de-risked capability in the 2026 literature
(browser-backed evidence, independent validation agents — see
`RnD_2026-09.md` §C3). Two owned components, not dependencies:

- **An instrumented browser** — hooked at the DOM/JS API level, observing
  script execution, mutations, dialog triggers — not screenshot-level
  tooling. Loud; goes through stealth pacing like everything else.
- **Your own OOB correlator** — self-hosted DNS/HTTP interaction capture
  with per-probe unique identifiers. Private telemetry (no third party in
  your loop — operationally and strategically different from a shared
  public service), and the interaction record becomes a first-class
  observation type that blind techniques (SSRF, blind SQLi, XXE) return
  as evidence.

### 2.5 Noise-budgeted scheduling — the objective nobody optimizes

Every published system optimizes tokens or wall-clock. Neither is the
right objective for an operator who is patient and must not look like a
scanner. Proposed invariant: **every technique declares a NoiseProfile**
(request volume, timing shape, fingerprint surface), and the scheduler
maximizes *information gain per unit of visibility*, under engagement
budgets measured in hours-to-weeks, not minutes. The recon side already
paces DNS across ~11 hourly windows; this generalizes that from a DNS
budget to the engine's core scheduling objective. This is, as far as the
2025–2026 literature shows, an open differentiator — no system in the R&D
refresh does it.

---

## 3. Campaign properties: the APT lens, translated

What actually makes sophisticated long-duration operations effective is
not exotic tooling — it is five properties, each of which is also a
legitimate requirement for authorized long engagements. Each maps to a
structural choice above:

### 3.1 Campaign state that survives everything

The world model is event-sourced: effects and observations append to the
log; graph views, receipts, scores, and chain candidates are derived and
rebuildable. Consequences: the engine can pause for a week and resume
coherently; any decision can be audited back to its observations
(ARTEMIS's credibility came from evidence-backed submissions, and the
ethics literature's accountability requirement — logs, approvals,
validation evidence — is satisfied structurally); and offline replay
testing works because the log is the environment.

### 3.2 Adaptivity under observation

The defender's stack (WAF rules, rate limiters, challenge pages) is part
of the environment, not an obstacle. Filter behavior is recorded as
*evidence* (§2.2), so the engine models how a target reacts and adapts
probe selection accordingly. This is AWE's filter inference generalized,
and it is the property that makes the difference between a scanner that
gets blocked and an operator that does not.

### 3.3 Chaining as data

Techniques declare preconditions and postconditions in their manifests —
first-class, machine-readable. Chain candidates are computed over the
world model rather than hallucinated; the Kuikka probability layer becomes
computable on that structure; and the scheduler can reason about kill-chain
conjunctions (AND semantics) as ordinary tree nodes. This is also where
the CVE-intel pipeline (once built) joins: a known CVE is just another
node with preconditions the fingerprinting half may already satisfy.

### 3.4 A single, coherent identity

One HTTP engine, one pacing policy, one identity system across recon and
exploitation phases. Generic scanner stacks have characteristic composite
fingerprints — mixed client libraries, telltale header orders, abrupt
volume changes between phases. Coherence is an owned-primitives payoff:
it falls out of §2.1/§2.5 rather than being bolted on, and it extends the
stealth layer's per-host identity work to the whole campaign.

### 3.5 Precision as the survival metric

ARTEMIS beat 9 of 10 humans not by finding more, but by an 82%
valid-submission rate. The engine's report layer inherits the rule the
first feasibility notes derived and the PoC-pollution literature
reinforced: *generated is a lead; executed-and-observed is a finding*.
Every candidate carries its evidence class, and the report states what was
proven, how, and with what reproducibility.

---

## 4. Revisions this imposes on the R&D shortlist

The `RnD_2026-09.md` §10 tiers stand as evidence tiers; two items are
reinterpreted by this thesis:

1. **Technique-observation schema (Tier 1)** — upgraded from "record
   context as evidence" to "build the typed observation model first"
   (§2.2). It is the prerequisite for memory, scheduling, and verification
   simultaneously.
2. **"Specialized exploit agents per class" (Tier 3)** — reframed: not
   *agents*, but pure technique modules under one harness (§1.1), which is
   the stronger version of AWE's lesson and the one compatible with the
   puzzle constraint.

One addition the R&D refresh under-weighted and this thesis promotes:

3. **Owned HTTP engine (§2.1)** — not on the R&D tier list at all, because
   the R&D pass was organized around published systems (which all wrap
   generic clients). It is the clearest case where the literature and the
   no-readymade-tools constraint point the same direction: the technique
   families it unlocks are, by construction, unavailable to every system
   the R&D refresh surveyed.

---

## 5. Invariants checklist (what "done right" means for any new module)

- [ ] Pure at the boundary: no I/O, no clock, deterministic given inputs
- [ ] All effects pass the policy gate; no second path to the network
- [ ] Emits/consumes typed observations, never raw text
- [ ] Manifest declares preconditions, postconditions, evidence classes,
      noise profile
- [ ] One folder; registry-discovered; removable without edits elsewhere
- [ ] Replayable from the event log; tested offline against replays
- [ ] Degrades gracefully when the LLM junction is unavailable
- [ ] Evidence class of a finding differs from the hypothesis source's

---

## 6. Open design questions (carried forward, sharpened)

1. **Effect's shape**: one interface with capability negotiation
   (stealth-style capability reports), or per-transport interfaces with a
   capability registry? Affects how techniques declare transport needs.
2. **Probe grammar scope**: per-class grammars with shared mutation
   operators, or one global grammar? (§2.3)
3. **NoiseProfile quantification**: what units does "visibility" take —
   request volume × timing entropy × fingerprint distance? Needs a
   definition before the scheduler can optimize it. (§2.5)
4. **Verification's budget**: browser-backed verification is loud and
   slow; does it run inline under stealth pacing, or as a separate,
   operator-approved phase? (§2.4; ties to open question 1 of the R&D
   refresh)
5. **Event log retention & privacy**: findings are sensitive; the log is
   replayable — what is the operator-facing story for log custody?

---

*Status: direction-setting document. Consistent with the ground rules of
the companion R&D docs — nothing here is an implementation decision; the
invariants in §5 are constraints any future design must satisfy, and §6 is
where the real decisions live.*
