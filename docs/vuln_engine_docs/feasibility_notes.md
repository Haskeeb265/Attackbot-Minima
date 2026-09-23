# Vuln engine R&D — critical feasibility notes

Companion to [`RnD.md`](./RnD.md). Same rule you set: **no architectural
decisions here** — this is a capability-by-capability feasibility read of every
paper on the list, tested against what the recon side of Attackbot actually
emits today (`graph_state.json`, the receipts, the scope engine, dispatch). Each
section ends with what I'd *watch*, not what I'd build.

Status legend: **sound** / **sound with caveats** / **speculative** /
**challenged** — my honest read of whether the mechanism survives contact with
bug bounty reality.

---

## 1. GoalAct (2504.16563) — core planning

**What it actually is.** Smaller than the marketing reads: the "continuously
updated global plan" is a running transcript of `(Plan step, Action,
Observation)` tuples, re-sent to the LLM every turn with the instruction
"continue; avoid repeating prior thought paths; output Finish if resolved." The
action space is a fixed skill menu — Searching, Coding, Writing, Finish —
so the plan step names a skill and an objective, never tool parameters. It's a
prompt architecture, not a framework: ~one system prompt + JSON output format.
Evaluated on LegalAgentBench, max **10 iterations**, temperature 0. Beats
ReAct/CodeAct/Plan-and-Execute, with gains growing with task depth (+20% at
3-hop). Ablations: removing the global plan costs 8.1%; removing Coding costs
14.1% — the *expressiveness* of the action space matters as much as the planner.

**Transfer to a vuln engine — the honest read.**

- **What maps.** The mechanism is domain-agnostic and cheap; the failure it
  fixes (ReAct local-branch thrash, losing the thread over long horizons) is
  *exactly* the failure mode of an agent that spends 40 steps enumerating one
  subdomain's parameters. The skill-menu idea maps beautifully: our "skills"
  are not Searching/Coding/Writing but Recon/Probe/Fuzz/Verify/Report —
  each skill backing onto different tooling. The plan never names tools, only
  skills + objectives; tool selection happens inside the skill executor. That
  is the correct altitude for an LLM that cannot be trusted to remember that
  `nuclei -tags sqli` is redundant after a receipt recorded `sqli` attempts on
  that URL.
- **What does not map — and this is the central caveat.** GoalAct's eval loop
  runs **10 iterations of a chat model**. A converged recon run already takes
  ~45 minutes and thousands of *real* network actions, each costing real
  tokens. Long-horizon in a legal QA benchmark means "10 tool calls"; long-
  horizon in pentesting means "3 hours and 900 requests." Three things scale
  badly and must be watched before any commitment:
  1. **Context length.** The plan-action-observation transcript grows with
     every network response. LegalAgentBench observations are short strings;
     our observations are HTTP bodies and nmap output. Without an aggressive
     summarization layer between observation and transcript, the re-emitted
     plan degrades by ~step 30 — the exact hallucination-drift the framework
     exists to prevent. (STRUCTUREDAGENT's observation summarizer is the
     companion piece that fixes this; see below.)
  2. **10 iterations → no upper bound.** Nothing in the paper says the loop
     survives 200+ steps. The 12.22% average gain was measured at T=10.
     Extrapolating to long-horizon is *plausible* (the mechanism is precisely
     anti-drift) but **unproven**.
  3. **Idempotent tools.** LegalAgentBench tools read tables. Our tools *do
     things* to a third party's infrastructure, with a WAF on the other end
     and a scope gate that must veto some plan steps. GoalAct has no concept
     of "this action is not allowed" — the replan loop only sees natural
     observations. Our DENYs must be first-class observations the planner can
     learn from, not silent failures.
- **Skills as bounded state machines.** GoalAct is deliberately vague about
  what a "skill" contains internally. For us that vagueness is the risk: a
  "Fuzz" skill that's just a raw LLM loop over a tool would drift exactly like
  ReAct. The honest reading is that **skills should be deterministic tool
  orchestrations** (the deterministic workflows you've already built in the
  recon pipelines are the model) with the LLM choosing *parameters and order*,
  not improvising the logic. That preserves GoalAct's claimed stability benefit
  ("simple probing strategies facilitate error analysis") and maps to the
  ablation result: when they removed Coding — the free-form skill — planning
  degraded most, meaning structure-plus-expressiveness beats freedom.

**Status: sound with caveats.** The mechanism is the right shape for our
problem; the transfer burden is context management at ×20 the horizon and a
DENY-aware replan loop, neither of which the paper provides.

---

## 2. STRUCTUREDAGENT (2603.05294) — extension to GoalAct

**What it actually is.** Not a GoalAct extension in any formal sense — it's a
**separate planning substrate** that solves the problems GoalAct leaves open:
(a) AND/OR trees where AND nodes are ordered subgoals and OR nodes are ranked
alternatives with backtracking; (b) the *framework* owns the tree and invokes
the LLM only for bounded operations (expand a node, repair a node, check
completion, prune) — never "here's the whole plan, continue"; (c) node states
(Entering/Exiting/Failed) with revision budgets and failure back-propagation;
(d) an **Observation Summarizer** between raw HTML and agent context;
(e) structured memory tracking candidate entities × constraints.

**Transfer.**

- **The division of labor is the valuable idea, not the tree.** GoalAct asks
  the LLM to restate the entire plan every turn; STRUCTUREDAGENT asks it only
  bounded local questions with verifiable outputs. For an engine whose actions
  cost real requests, "LLM proposes, framework disposes" is the only safe
  split: the LLM can propose a subtree; the framework validates it against
  scope, budget, and receipts before a single node executes.
- **AND/OR trees map to attack semantics better than to shopping.** AND =
  a kill-chain precondition set (must have foothold AND must have cred
  material AND must have egress); OR = alternative techniques for one
  objective (subdomain takeover via dangling CNAME *or* via abandoned S3
  bucket). The tree *is* an attack graph with a plan attached — which makes
  the Kuikka probability layer (§6) computable *on the tree* rather than as a
  separate artifact.
- **Failure handling is where pentest agents die.** Revision budgets, prune,
  and back-propagation give us a principled answer to "the WAF blocked us /
  the exploit failed" — record `failed`, propagate up, switch OR-branch —
  which matches our receipt rule (only conclusive attempts earn a skip; a
  failed scan records failed and skips nothing).
- **The structured memory module is quietly the best fit of anything on the
  list.** A candidate-entities-×-constraints table is *exactly* what a vuln
  engine needs while iterating: candidate = (url, param, technique), columns
  = (waf behavior, auth required, payload family tried, response delta). That
  is our receipts mechanism generalized from "did we try X" to "what do we
  know about trying X."
- **Caveat:** this is substantially more machinery than GoalAct, and the two
  don't compose trivially — one plan representation must win (see the tension
  note in §10).

**Status: sound with caveats** — high value, but treat as an alternative
substrate to GoalAct rather than a bolt-on; the summary claim in RnD.md
("added on top of GoalAct") understates the integration cost.

---

## 3. GraphAgent (2310.16421) — advisory layer

**What it actually is.** Node classification and link prediction on
*Cora/PubMed/PrimeKG-scale* citation and medical KGs (thousands of nodes,
dense homogeneous structure), by serializing local graph neighborhoods into
text and letting an LLM do inductive+deductive reasoning over them. The
accuracy numbers are on graphs where every node has a meaningful label and
every edge is semantically load-bearing.

**Transfer — here I push back.**

- The paper's own framing is *not* "advisor that reduces false positives."
  It's a graph-reasoning method for classification/prediction tasks on small,
  clean, curated KGs. Our `graph_state.json` is the opposite: heterogeneous,
  sparse, trust-stratified, with ~40% of nodes being ephemeral infrastructure
  (a CNAME here today, gone Thursday) and evidence quality varying by orders
  of magnitude between a verified subdomain takeover signal and a heuristically
  guessed tech stack.
- As an **explanation generator** ("why is this asset scored 7.2 and in
  needs_review") over a bounded local neighborhood, this is genuinely useful
  and cheap — but that's not a research contribution, that's good use of an
  LLM with a subgraph in context.
- As an **FP reducer**, the value depends entirely on whether the graph
  *contains* the discriminating evidence. A false positive in vuln scanning
  is usually suppressed by context the graph doesn't have (response timing,
  WAF fingerprints, content diffs). GraphAgent can only re-rank what recon
  captured; it cannot conjure missing evidence.
- As **prioritization**, link prediction on our graph is plausible but
  unproven at our density — primeKG links are curated; our edges are
  "resolved-from" and "handshake-served-by."

**Status: sound with caveats for explanation + prioritization;
speculative (and oversold in RnD.md's framing) for FP reduction and pattern
learning.** The learning claim especially: GraphAgent is training-free; any
"learn program-specific patterns incrementally" would have to come from
somewhere else (see §4).

---

## 4. TheoryCoder-2 (2602.00929) — skill learning

**What it actually is.** A program-synthesis agent that *writes its own
abstractions*: when a subprocedure recurs across tasks, it lifts the working
code into a named, parameterized library function and reuses it in future
plans. Tested on gridworlds (BabyAI, Sokoban, MiniHack) where a "skill" is a
short Python function over a tiny, fully-observable, deterministic world.

**Transfer.**

- The *mechanism* — "when a workflow worked, freeze it as a callable with a
  schema" — is exactly right for us, and matches how bug bounty actually
  goes: the same 6–10 step recon-to-exploit chains repeat across programs
  with different parameters. Reuse would cut both token cost and variance.
- The *preconditions* do not hold. Our environment is partial, adversarial,
  non-stationary; our "skills" are multi-hour network interactions. A frozen
  skill is only safe if it (a) revalidates its own preconditions at
  invocation time against current scope and receipts, and (b) fails loudly
  when the world moved. Neither exists in the paper because gridworlds don't
  move.
- **Recommendation: inherit the idea, not the algorithm.** Don't auto-lift
  skills from experience initially. Curate them by hand (a skill library of
  ~15–25 vetted chains is realistic at first), record every run's
  plan/attempt trace as the corpus, and let the *human* promote a recurring
  trace into a skill. The paper's contribution — experience → abstraction —
  can be adopted as a process long before it can be automated.
- Note: RnD.md calls this "Theory-Code2"; the paper is **TheoryCoder-2**, and
  it supersedes TheoryCoder (which relied on human-provided abstractions —
  the -2 part is learning them).

**Status: speculative** as automatic skill synthesis in the near term; **sound
as a design direction** for the skill-library concept itself.

---

## 5. SymAgent (2502.03283) — knowledge-base suggestions

**What it actually is.** KG-as-environment for multi-hop QA: an Agent-Planner
extracts symbolic rules from the KG to guide decomposition; an Agent-Executor
calls tools to fill KG gaps from external documents; a self-learning loop
(rejection-sampling-style offline policy update) synthesizes better reasoning
trajectories. Notable: a 7B backbone matches much larger baselines, and the
agent *identifies missing triples*, i.e., knows what it doesn't know.

**Transfer.**

- The **missing-triple identification is the single most transferable idea in
  the whole stack**: our findings database has exactly this incompleteness
  problem, and "the engine noticing its own graph is missing the edge it
  needs" is precisely the trigger for recon escalation (the recon side
  already has this shape — the convergence loop re-runs stages when new
  assets appear). A SymAgent-shaped loop over our internal findings store
  would: notice "I have a web server on host X but no endpoint inventory for
  it" → propose the missing investigation → let the planner schedule it.
  That is *breadth-first lead generation*, and it's the right use of this
  paper.
- **Autonomously suggesting attacks from known surfaces** (RnD.md's framing)
  is the dangerous half and needs a hard gate: in bug bounty, every
  "suggestion" is a potential out-of-scope action against real infrastructure.
  Suggestion generation must terminate in *plan proposals*, which then pass
  the same scope/dispatch gates as everything else — SymAgent's executor
  freely calls tools, which we cannot allow unsupervised.
- The self-learning loop requires a reward signal; "was this lead productive"
  is weak and delayed (a lead pays off days later or not at all). Real risk
  of the loop optimizing for lead *quantity*.

**Status: sound with caveats** for missing-evidence detection; **speculative**
for autonomous attack suggestion without a human (or at minimum a policy-gate)
in the loop.

---

## 6. Attack-graph papers

### CrystalBall (2408.05855)

RAG over CVE/precondition-effect knowledge to chain vulnerabilities into an
attack graph. Conceptually simple and the most directly *compatible with our
data*: our graph already has the node vocabulary (hosts, services, techs,
CVEs-when-we-get-there) and the chaining operation is retrieval + LLM
composition. Two hard limits for us:

1. **Precondition matching is everything.** "CVE A's postcondition satisfies
   CVE B's precondition" is only as good as the structured precondition data,
   which live CVE feeds (CVE/NVD/EPSS) provide unevenly and noisily. The paper
   leans on LLMs to fill the gaps — which is exactly where FPs are born.
2. **It generates candidate graphs, not verified findings.** Every edge is a
   hypothesis. Fine — that's what the verification skill is for — but the
   engine must price this: unverified chain edges are leads, not findings,
   and the report layer must keep that distinction legible.

**Status: sound with caveats** — good fit for the "surface candidate chains"
capability, contingent on a CVE-ingestion capability that doesn't exist yet.

### SBOM chain prediction (2604.04977)

HGAT over CycloneDX dependency graphs + MLP link predictor over documented
multi-vuln chains (ROC-AUC 0.93 on **35 seed chains** — tiny validation set,
authors frame it as a feasibility study themselves). **The capability gap is
bigger than the model choice: Attackbot currently has no SBOM ingestion at
all.** For JS-heavy web targets, a source-map or bundle-analysis collector
could produce a component inventory from live sites, but that's a new pipeline
before this paper is even applicable. Also: the paper predicts *component →
has-vuln* and *vuln → vuln* cascades in dependency space — it says nothing
about *network reachability*, which is our actual question ("can I reach this
vulnerable component from the internet through this host's exposed surface?").

**Status: speculative** for now; a real capability (a future SBOM/JS-analysis
pipeline) unlocks it. Park it, don't shelve it.

### Cybersecurity KG (Sikos 2023, Springer)

Survey of RDF/linked-data cybersecurity KGs (SEPSES etc.). Useful as a
*reference for schema/interoperability* (STIX/CAPEC/CWE alignment, how
standards bodies model vuln metadata), not as a method we implement. The
practical takeaway for us is narrower: when we design the vuln-side schema
(the thing that doesn't exist yet, per CONCERNS.md #8), align node vocabulary
with CAPEC attack patterns and CWE weakness types so that external knowledge
(CVE feeds, EPSS, vendor advisories) joins cheaply later.

**Status: sound as a design reference only.** (406 on direct fetch; assessed
via abstract/metadata and secondary sources — worth one proper read when we
touch schema design.)

### Kuikka et al. (Frontiers 2025) — probabilistic chain-kill scoring

**The sleeper hit of the list.** Influence-spreading model: CVSS-derived
exploitability probabilities as edge weights, then a probability matrix over
the whole graph that combines *all joining paths* with the non-mutually-
exclusive-events rule (not just max-path or single-path counting), giving
per-node exploitability, in/out-centrality, and impact-weighted metrics.
What makes it valuable for us:

- It turns "which of the 400 candidate chains do we spend the next hour on"
  from an LLM judgment call into a **computed quantity** — cheaper, stable,
  and explainable ("this chain is prioritized because 4 independent paths
  converge on this host with combined probability 0.31").
- It's *independent of how the graph was built* (authors say so explicitly:
  the analysis only needs the probability matrix), so it works equally on
  CrystalBall's hypothesized chains and on STRUCTUREDAGENT's AND/OR trees.
  It's the scoring layer under both.
- Cautions: CVSS exploitability ≠ real-world success (no EPSS/env
  conditioning yet — but EPSS can slot in as the prior); probability
  *combination* assumes edge independence, which is false when two paths
  share a credential; and the paper's graphs are 18–39 nodes, ours are
  6,476 assets and growing — matrix cost needs checking (it's
  probabilistic path combination, not matrix inversion, and the
  self-avoiding-path restriction bounds it, but this must be benchmarked at
  our scale).

**Status: sound with caveats** — the highest value-per-effort item on the
attack-graph shelf. Small, pure-math, no LLM in the loop, and it produces
exactly the prioritization signal an agent planner would otherwise have to
guess.

---

## 7. VulnBot (2501.13411) — exploitation execution

**What it actually is.** Multi-agent pentest pipeline (recon → scan →
exploit) where a **Penetration Task Graph (PTG)** — a directed graph of task
nodes with explicit dependency edges — sequences the work, and each node is
executed by a specialized agent. Role specialization + inter-agent
communication + generative behavior. Evaluated on real machines (attack paths
through NASim-style scenarios and real VMs), beating raw GPT-4/Llama3.

**Transfer.**

- **The PTG is the genuinely important object here**, and it quietly answers a
  question GoalAct leaves open: GoalAct's plan is a linear transcript with no
  explicit dependencies — fine for QA, bad for attacks where step 3 literally
  cannot run until step 2 returns a session token. A DAG of task nodes with
  dependencies is the right substrate for attack *execution*, and it is
  compatible with the AND-node semantics of §2 (AND = conjunction of
  preconditions; PTG edge = data/control dependency).
- **The role-specialization finding validates the skill-menu approach**: for
  every capability, there's a natural specialized executor, and specializing
  beat general-purpose generation in their eval.
- **The hard part — generative exploitation — deserves deep suspicion**, and
  RnD.md's "needs deeper investigation" note is correct and then some:
  1. **Payload synthesis by an LLM against third-party production systems is
     the highest-risk component in this entire research stack.** Even in
     authorized-scope bug bounty, generated payloads can be destructive
     (RCE chains, DoS-shaped inputs) and scope drift mid-exploit is how
     real people get banned and real legal exposure happens.
  2. **Legal/authorization asymmetry:** this paper assumes *its own* lab.
     Everything it does must pass our dispatch gate (ALLOW/DEFER/DENY with
     reasons) and the refuse-never-guess scope engine first — the paper has
     no equivalent concept.
  3. **Verification debt:** an LLM that both generates the exploit *and*
     judges success is a closed FP loop. VulnBot's exploitation phase needs
     an independent verifier with a different information source than the
     generator.
- For the near term, the honest scope: adopt the **PTG as execution
  substrate** and the **role-specialization principle**; defer
  *generative* exploitation far behind *curated* exploitation (a fixed
  toolchain executing parametrized techniques — nuclei templates, known
  CVE PoCs under human review gates — before any free-form payload
  generation).

**Status: sound for orchestration substrate; challenged for generative
exploitation** in our context (scope, safety, verification), not because the
paper is wrong but because its assumptions (own lab, own machines) don't
transfer to third-party production targets.

---

## 8. LLM-based semi-autonomous pentest agents (2502.15506)

**What it actually is.** Multi-module HTB workflow: strategy LLM → command
generation LLM → result analysis LLM, looping with a human in the loop, on
Hack The Box machines. Modest paper (7 pages, small eval), but the honest
findings are useful: LLMs need decomposition for multi-step attacks, raw
generation produces excessive unstructured output, and manual intervention
remains substantial.

**Transfer.** Its value is mostly *confirmatory*: semi-autonomy with human
checkpoints works better than full autonomy on adversarial machines —
consistent with everything above. The strategy/command/analysis module split
maps 1:1 onto our skill executors (planner names the objective; a command
builder with tool schema knowledge renders it; an analyst summarizes
observations back into the transcript). Nothing here to challenge; nothing
here to build a pillar on either.

**Status: sound, modest.** A design-pattern citation, not a load-bearing one.

---

## 9. RL papers (A3C; RL-for-pentest comparison)

NASim-simulated training of Q-learning/DQN/A3C agents on small fixed scenarios
(3 scenarios, small state/action spaces). A3C solved all scenarios and
generalized with fewer actions than scripted baselines. Both papers are
honest about scope: simulated, small, predefined.

**Transfer: none today, and that's fine and expected.** The blocker is not
algorithmic — it's that RL needs (a) a faithful simulator of *our* targets
(NASim is toy-topology), (b) a reward signal (finding a real vuln is sparse,
delayed, and noisy), and (c) enormous sample counts, all of which are absent.
The correct near-term relationship to these papers is as **evaluation
harnesses**, not training plans: NASim as a *dry-run environment* where a
GoalAct-style engine can be exercised end-to-end without touching real
targets is valuable *now* for regression and safety testing. The RL training
line stays parked until the engine exists and produces enough trajectory data
to even consider offline RL.

**Status: speculative for training; sound as sim/test harness.**

---

## 10. Cross-cutting findings

### The stack has a consistent shape — and one real tension

Read together, the papers converge on a layered architecture:

```
  propose ──▶ validate ──▶ execute ──▶ verify ──▶ record
  (LLM)      (deterministic gates)  (tools)   (independent)  (receipts)
```

GoalAct supplies the *propose* loop; STRUCTUREDAGENT the *validate/repair*
substrate and structured memory; VulnBot the *execution* DAG and role
specialization; CrystalBall + Kuikka the *candidate generation and scoring*
layer under it; SymAgent the *what-am I-missing* loop; TheoryCoder-2 the
*how-work-compounds* idea; GraphAgent the *explainer*.

The tension: **GoalAct's plan is a linear transcript; STRUCTUREDAGENT's and
VulnBot's are trees/DAGs.** These are not trivially mergeable — you cannot
simultaneously re-emit a flat plan every turn and DFS an AND/OR tree. Whichever
substrate wins determines what "the plan" even is. My honest observation for
the R&D record: *the tree/DAG substrates subsume the linear transcript* — a
plan linearization is just a DFS trace of the tree — so if we ever get past
exploration, the burden of proof sits on the transcript side. But per the
ground rule, that's a decision for later, not now.

### The papers are benchmark-shaped; bug bounty is field-shaped

Every framework here was validated on QA tasks (LegalAgentBench), web
navigation (WebVoyager/WebArena), or CTF-style lab machines (HTB, NASim). None
have run against third-party production infrastructure under an authorization
regime where an autonomous mistake is a policy violation with real
consequences. Three specific transfer debts recur across the whole list:

1. **Tool irreversibility.** Benchmarks reset; prod doesn't. The engine's
   action space must be deny-by-default, receipt-recorded, and budgeted —
   and the papers have no concept of any of these.
2. **Ground truth.** Benchmarks score success; we don't know if a vuln was
   real until triage (or a bounty payout). Evaluation must be designed —
   e.g., replay against a corpus of known-resolved reports, or NASim-style
   simulation — before any capability claim is testable.
3. **Noisy environment.** WAFs, rate limits, honeypots, and decoys mean the
   same action can succeed or fail unpredictably. The stealth/pacing layer
   already built for recon is load-bearing here too, not just plumbing.

### What's missing from the list (gaps, not decisions)

- **Verification methods** — nothing on the list addresses *confirming* a
  candidate vuln independently of the agent that found it. The closed-loop
  FP problem is the most common killer of automated-recon-to-report systems.
- **Report generation** — a real finding must become a structured,
  reproducible report (steps, evidence, PoC) that a triager can verify;
  nothing covers this.
- **Authorization modeling** — the scope engine exists on the recon side;
  every paper here would need to be re-derived under it.
- **Multi-armed bandit / exploration-exploitation for probe selection** —
  which technique to try next on a candidate is a bandit problem; the RL
  papers are overkill, but a simple contextual bandit over (technique ×
  surface) with receipt-derived rewards is a cheap capability the list lacks.

---

## 11. Feasibility summary table

| # | Paper (RnD.md name) | Status | Value if it works | Main risk / debt |
|---|---|---|---|---|
| 1 | GoalAct — core planning | **sound w/ caveats** | Anti-drift long-horizon loop; skill-menu matches our tooling | Context growth at ×20 horizon; unproven past 10 iters; DENY-blind replan |
| 2 | STRUCTUREDAGENT — multi-branch | **sound w/ caveats** | Framework-owned plan w/ bounded LLM ops; failure back-prop; structured memory ≈ receipts 2.0 | Not a GoalAct bolt-on; substrate tension (§10) |
| 3 | GraphAgent — advisor | **sound w/ caveats** (explain/prioritize) · **speculative** (FP learn) | Cheap subgraph explanations; re-ranking | Paper ≠ advisor framing; can't conjure missing evidence; no learning in method |
| 4 | TheoryCoder-2 — skill reuse | **speculative** (auto) · **sound** (direction) | Workflow compounding across programs | Gridworld preconditions don't hold; curate skills by hand first |
| 5 | SymAgent — KB suggestions | **sound w/ caveats** (missing-evidence) · **speculative** (autonomous suggest) | Missing-triple detection ≈ recon escalation trigger | Suggestions must pass scope/dispatch gates; weak reward signal |
| 6a | CrystalBall — attack graphs | **sound w/ caveats** | Candidate chain generation over our own graph | Precondition data quality; chains = leads, not findings |
| 6b | SBOM chain prediction | **speculative** | Supply-chain vuln discovery | No SBOM ingestion exists; 35-seed-chain validation; no reachability |
| 6c | Sikos KG survey | **sound** (reference only) | Schema alignment for future CVE joins | — |
| 6d | Kuikka — chain-kill probability | **sound w/ caveats** | Computed chain prioritization; explainable; substrate-agnostic | CVSS≠reality; independence assumption; scale unbenchmarked |
| 7 | VulnBot — exploitation | **sound** (PTG + roles) · **challenged** (generative exploit) | Task DAG execution substrate | LLM payload synthesis vs. scope/safety/verification; lab-assumption |
| 8 | Semi-autonomous pentest | **sound, modest** | Module split pattern; human-in-loop validation | Nothing load-bearing |
| 9 | RL (A3C/DQN) | **speculative** (training) · **sound** (NASim as harness) | Future; dry-run regression env now | No simulator of our targets; sparse delayed rewards |

---

## 12. Open questions for the next R&D session

1. **Substrate:** if the engine's plan is a tree/DAG (§10 tension), is
   GoalAct's transcript loop still the *propose* mechanism inside tree
   operations, or does it become the fallback rather than the core?
2. **Observation compression:** what is the summarization layer between raw
   HTTP responses and the planning context, and does it preserve the details
   verification later needs (headers, timing, content deltas)? This is the
   single most load-bearing unbuilt piece no paper on the list provides.
3. **Evaluation corpus:** can we build a replay set from publicly disclosed
   HackerOne reports (program-sanitized) to score candidate capabilities
   before any live target is touched?
4. **Scope for exploitation:** what is the *policy* (not architecture) for
   what the engine may do autonomously vs. propose-only? Every capability
   above lands differently depending on where that line sits.
5. **CVE/EPSS ingestion:** CrystalBall and Kuikka both need structured
   vuln-intel input; this is a prerequisite capability nobody's scoped yet.
