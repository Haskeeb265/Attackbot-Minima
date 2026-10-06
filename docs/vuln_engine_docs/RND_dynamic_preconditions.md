# R&D — Dynamic preconditions: making the engine *establish* what it currently *assumes*

**Status:** research / design. No engine code changed.
**Scope:** how to make a known-bug corpus (CVE/CWE/CAPEC) actually fire against a
target whose preconditions are not pre-declared.
**Read against:** `service/vuln_engine/` at the branch tip. Every type, constant
and gate named below was read from source, not from prose. Where a claim is an
inference rather than a citation, it is marked *(inference)*.

---

## 1. The problem, stated precisely

Your framing was "unless the perfect pre- and post-conditions are met, the engine
cannot encounter bugs even if it has them in its glossary." That is close, but
the code says something sharper, and the sharper version points at a different
fix.

**The engine does not test its preconditions. It requires them to be *declared*,
and it has no way to *establish* them.**

The chain that locks the engine's `surfaces()` gate:

```python
# techniques/oob_fetch/hypothesis.py
if not surface.param or surface.capability != CAP_INFLUENCE_REMOTE_FETCH:
    return []                      # never fires
```

`surface.capability` is a single string set at seed construction. Three sources
set it, all of them *declaration*:

1. the operator's `--surface "...;capability=delayed_response"` CLI flag;
2. `seed/from_graph.py`, which hardcodes `CAP_PUBLIC_PARAM` for every parameter
   (`_to_surface`), and upgrades to `CAP_INFLUENCE_REMOTE_FETCH` only on a
   28-name heuristic (`REMOTE_FETCH_PARAM_HINTS`);
3. nothing else.

So the "capability" a technique gates on is **a claim about the world that
nothing measures.** The engine is a measurement instrument, and the instrument
trusts a claim that nothing measures — the same trust the engine was built to
eliminate. Its own docstring for `CAP_INFLUENCE_REMOTE_FETCH` says this out loud:

> **Claimed only in Phase 1**: the engine takes the operator's word for it and
> lets verification do the proving … a capability we cannot measure cheaply
> should be a claim that produces a lead, never a fact.

That was a *safe* Phase 1 choice and it is now the ceiling. The engine will prove
a claim beautifully, but it cannot *raise* one. A surface is offered to a
technique iff someone asserted the right string, and the asserting is manual,
graph-hardcoded, or a name heuristic.

### 1.1 Why "ingest more CVEs" does not, by itself, fix this

The CVE/CWE pipeline in `CVE_ingestion.md` is a *producer of techniques and
payload variants*. It widens the set of things the engine knows how to prove. But
every new technique inherits the same gate: it declares a precondition, and that
precondition must already be declared on a surface or the technique is offered
nothing. Adding SSTI, XXE, path traversal — each is a correct, tested,
un-fireable tool against a graph that supplies one of eight claims
(`README.md` §7, measured).

So the bottleneck is not the *breadth* of the corpus. It is that the corpus is
**inert without a precondition-supply mechanism**, and that mechanism is a
different subsystem from the corpus.

### 1.2 The postcondition half is the same defect, mirrored

`README.md` §7 item 9: all eight manifests declare `postconditions`, the chain
query is computed over the world model, "but nothing in the graph represents
*what this probe established*, so chains stay inert." Same root cause: a
postcondition is *declared* on the manifest and never *recorded* as a fact about
a surface. A technique proves a finding; nothing writes "this surface now carries
`script_execution`" back into the pool of surfaces, so the chain query reads an
empty set.

### 1.3 The sharp diagnosis

The engine has a **planning** defect, not a coverage defect. It is a planner that
will not decompose a goal into sub-goals. "Prove SQLi on surface S" requires
"know S delays on parameter P"; the engine has no move that establishes the
sub-goal, so the goal is unreachable and is dropped silently.

**The fix is backward chaining:** when a technique needs a precondition the world
has not established, the engine should be able to *establish it first*. This is
the standard answer in automated planning (PDDL-style precondition satisfaction,
`arXiv:2407.16928`; attack planning, Obes et al. 2010) and it is missing here.

---

## 2. The insight: you already own every instrument

The four "missing input claims" are described as things recon must supply, and
recon deliberately does not send traffic (`README.md` §7 item 4). But the
*measurements* already exist inside `verification/`:

| Missing capability claim | Measurement the engine already owns | Where |
| --- | --- | --- |
| `http_response_reflects_input` | canary in, reflection + context out | `world/observe.py` (`http_observations`, `find_reflection`) |
| `delayed_response` | two timing populations, re-measured fresh | `verification/timing_verifier.py` |
| `server_stores_input` | submit-then-read-back + browser | `verification/stored_xss_runner.py` |
| `access_differs_by_session` | two sessions, one object, flipped order | `verification/authorization_verifier.py` |
| `can_influence_remote_fetch` | collaborator interaction record | `transports/oob.py` + `verification/oob_verifier.py` |

Each of those verifiers already:

* builds probe specs;
* sends every measurement through `PolicyGate` (verifiers go back through the
  gate for fresh measurements — invariant #1);
* re-derives its population from a candidate's `confirm` spec;
* emits typed observations.

**An elicitor is a verifier with the candidate removed.** Its question is not "is
this claim true of this surface" but "what is true of this surface." The
experiment is identical. The answer is not proof of a bug; it is a **fact about
the surface** a technique may then take as its precondition.

> The verifier already knows how to measure every precondition the corpus needs.
> The corpus cannot see the measurement because it lives one layer up, behind a
> candidate.

---

## 3. The design: Capability Closure

Three claims:

1. **Capability is a measured fact with an evidence grade, not a declared
   string.**
2. **A technique that wants a precondition the world has not established should
   cause that precondition to be *elicited*, not skipped.**
3. **Establishing a postcondition is a fact written back onto the surface pool,
   which closes the chain loop.**

The shapes below are *pseudocode for structure*, not kernel signatures — the same
caution `CVE_ingestion.md` §6.4 applies to its own samples. The real signatures
are the design's to fix.

### 3.1 A third registry-discovered folder family: `elicit/`

Mirror `techniques/`: one folder per capability, four pure functions and a
manifest.

| Function | Gets | Returns |
| --- | --- | --- |
| `applies(surface)` | a surface | whether this elicitor is worth running here (cheap, pure) |
| `probes(surface)` | one surface | `ProbeSpec`s — the measurement, through the gate |
| `interpret(surface, observations)` | the pass's observations | `CapabilityFact`s, or nothing |
| `manifest` | — | `capability`, `noise`, `transports`, `evidence_floor` |

The acid test holds: adding a capability must never require editing anything
outside `elicit/<capability>/`. Deleting a folder leaves the engine running with
one fewer measurable claim.

### 3.2 The record: a capability fact reuses `Evidence`

```python
# kernel/capability.py  (pseudocode — shape, not signature)
@dataclass(frozen=True)
class CapabilityFact:
    surface_key: str          # Surface.key — the join key everything else uses
    capability: str           # one of kernel.technique.CAPABILITIES
    grade: str                # an EVIDENCE_* constant
    probe: str = ""           # which elicitation probe established it
    at: float = 0.0
```

Deliberately *not* a new grading vocabulary. `grade` is an `EVIDENCE_*` constant,
so "the response reflects our canary" is `reflection`, "the browser executed" is
`execution`, "the collaborator saw the fetch" is `oob`, "the two sessions
differed" is `differential`. A technique can then say *how* a precondition was
established, and so can the report.

**The honesty rule that makes this safe:** a capability fact is a claim with a
grade, never a conclusion. Establishing `http_response_reflects_input` at
`reflection` grade does not make an XSS finding — it makes the surface *eligible*
for `xss_reflected`, which still must produce a candidate and pass the browser
verifier in a different class. The evidence lattice is untouched; elicitation
only decides which doors open.

### 3.3 The surface: `capability` becomes `capabilities`

Today `Surface.capability` is a single string, strongest-wins on collision
(`from_graph`). That is `README.md` §7 item 3, the multi-capability gap — a
parameter that is *both* reflected and remote-fetch cannot be both. Minimal,
backwards-compatible widening:

```python
@dataclass(frozen=True)
class Surface:
    ...
    capability: str = ""                        # KEEP: strongest established claim
    capabilities: frozenset[str] = frozenset()  # NEW: every established fact
```

Existing techniques that read `capability` keep working (it is defined as the
strongest member, the same rule the graph bridge already uses); new techniques
may read the set. *(inference: this is the least invasive widening.)*

### 3.4 The driver: an elicit pass before the fire pass, plus backward chaining

Two loops, both bounded.

**Loop 1 — closure pass.** Before the ordinary technique pass, run every
elicitor against every surface it `applies()` to, cheapest first. Collect
`CapabilityFact`s. Enrich the seed: each surface's `capabilities` is the union of
declared and elicited facts. Then run the ordinary pass unchanged. A surface
recon handed over as bare `public_param` now carries `delayed_response` *because
the engine measured it*, and `sqli_blind_time` fires.

**Loop 2 — backward chaining (on demand).** When a technique's `surfaces()` gate
rejects a surface for want of a precondition, the driver asks: *is that
precondition established? no → is there an elicitor for it? yes → run it, then
re-offer the surface.* This is the direct answer to "unless the perfect
preconditions are met." It is precondition satisfaction as a planning action
rather than a scheduling prerequisite.

Boundedness matters: an elicitor that returns "not established" must not be
re-run for the same `(surface, capability)` in the same run. The receipt rule
already does this — file a receipt keyed by the elicitation arm. The ledger does
the dedup for free, exactly as it does for techniques.

### 3.5 The chain: postconditions write facts back

The same `CapabilityFact` record serves the postcondition side. When a technique
proves a finding, the driver writes the manifest's `postconditions` back as facts
about the surface, at the finding's own grade (`execution` for XSS, `oob` for
SSRF, `differential` for the differential techniques). The chain query then has
rows to read, and `generic_differential`'s state-change row — capped today by
`kernel/claim.py`'s `DIFFERENTIAL_PROVABLE` — becomes eligible for a
setup-re-executing verifier, because the "what did this establish" fact is
finally on the record.

**The elegant part:** preconditions and postconditions are the *same record type*,
read in two directions. A postcondition written by technique A is a precondition
read by technique B. That is what makes a chain a chain instead of a hope.

---

## 4. What this buys, against the graph's own numbers

`README.md` §7 measured the live `qbsco.net` graph (3 541 nodes / 2 806 edges):
recon supplies **1 of 8** capability claims; 187 candidates, every one
`public_param`; two of eight techniques can fire.

Under Capability Closure, the same 187 surfaces are offered to the elicitors:

| Elicitor | Cost (visibility) | Claim it can establish | Techniques it unlocks |
| --- | --- | --- | --- |
| reflection | 1 request/surface | `http_response_reflects_input` | `xss_reflected`, `xss_dom` |
| timing | ~6 requests/surface (bursty) | `delayed_response` | `sqli_blind_time`, `command_injection` |
| storage | 2 requests/surface | `server_stores_input` | `xss_stored` |
| sessions | 2 requests/surface × 2 sessions | `access_differs_by_session` | `idor_differential`, `generic_differential` |
| remote_fetch | 1 request + OOB poll | `can_influence_remote_fetch` | `oob_fetch` |

*(inference: the counts are the existing verifiers' own probe sets, read from
`verification/*`.)*

The timing and sessions elicitors are the expensive ones, and the engine already
has the tool: `NoiseProfile.cost` is normative and the UCB selector divides
optimistic reward by it (`kernel/manifest.py`, `scheduler/ucb.py`). Elicitation
is not a new noise problem — it is the same problem the scheduler was built to
solve, applied one layer down. **Elicitors declare a `NoiseProfile` and compete
for budget exactly like techniques do.**

The honest headline: this does not make the engine find *any* bug. It moves the
ceiling from "the operator declared the precondition" to "the engine can measure
the precondition" — the difference between a glossary and a search.

---

## 5. How CVE/CWE/CAPEC ingestion should be re-aimed

Your plan is to ingest CVE/CWE to grow the technique corpus. That is correct and
it is the wrong first step. Here is the re-aim.

### 5.1 CAPEC is the precondition corpus, and it is the missing piece

CAPEC attack patterns carry an explicit `Prerequisites` field and an `Execution
Flow` (MITRE CAPEC schema, `capec.mitre.org/documents/schema/`); CWE entries
carry `Prerequisites`, `Applicable Platforms` and `Common Consequences`. Those
fields are exactly the vocabulary Capability Closure consumes:

* `Prerequisites` → the precondition a technique gates on, and therefore the
  *elicitor* the engine must own;
* `Execution Flow` → the probe sequence;
* `Common Consequences` → the postcondition the technique writes back.

**So invert the pipeline.** `CVE_ingestion.md` §5 maps CWE → `vuln_class` and §6
extracts payloads. Add a stage *before* both: map CAPEC `Prerequisites` → the
`CAPABILITIES` tuple. A prerequisite that maps to an existing capability means
the engine can *elicit* it (the corpus is now fireable). A prerequisite that maps
to nothing means the engine is missing a **capability**, and the honest output is
a new elicitor folder — not a new technique folder that can never fire.

This extends the doc's own discipline (§6.5: "the manifest's preconditions are
not the gate"): *the corpus's preconditions are not the gate either — the
elicitor is.*

### 5.2 The technique pipeline becomes the payload lane

Once capabilities are elicit-able, the CVE pipeline's job narrows to what it is
good at: **payload variants within a class**, merged into an existing technique's
`probes.py` (`CVE_ingestion.md` §7.1). No new folder per CVE; the scale reality
in §7.4 already forbids that. The precondition-supply mechanism is what lets
those variants ever be reached.

### 5.3 The dependency order I would build in

1. **`elicit/reflection` and `elicit/remote_fetch`.** Near-free refactors:
   `observe.find_reflection` and the OOB transport already do the measurement.
   Prove the mechanism on the two cheapest claims.
2. **`Surface.capabilities` + the closure pass in the driver.** Now the silently
   dead techniques have a path to firing from the graph.
3. **`elicit/timing` and `elicit/sessions`.** The expensive ones, behind the
   noise budget. Biggest payoff; the cost is already measured by `NoiseProfile`
   and the UCB selector.
4. **`elicit/storage`** (`server_stores_input`) — the one needing the
   `companions` / `read_back` surface metadata the dataclass has and the graph
   never fills (`README.md` §7 item 5).
5. **Postcondition write-back + chain query** — then the CVE/CAPEC ingestion has
   a real target: variants and chains, not inert folders.

---

## 6. Honest limits, and the one real risk

* **Elicitation is traffic.** It sends requests a declaration does not. That is
  why it belongs *inside the engine*, behind `PolicyGate`, where scope, the
  effects ledger and the circuit breaker already apply — not in recon, which was
  deliberately built not to send. The engine is the traffic-sending half, and the
  gate is already the chokepoint.
* **A capability fact is not a finding.** Restated because it is the invariant at
  risk: elicitation opens doors, it never grades evidence upward. The verifier
  rule (a different class, fresh measurement) is untouched.
* **The elicitor's cost is real.** The timing and session elicitors are the
  loudest thing in the run. The mitigation is already built (`NoiseProfile`,
  UCB). The naive failure is running *every* elicitor on *every* surface, which
  is exhaustive enumeration with a new name. The bounded closure (loop 1) plus
  on-demand chaining (loop 2) plus the existing receipts ledger prevents that.
* **The CVE doc's hard limit still stands.** Prose → working payload is ~17%
  given source (`CVE_ingestion.md` §6.2). Capability Closure does not change
  that. It changes whether the payload, once written, ever reaches a target.
* **One decision before building:** whether `Surface.capabilities` is a
  `frozenset` on the dataclass (recommended — minimal, backwards compatible) or
  a separate `CapabilityLedger` view passed to `surfaces()`. The first keeps the
  technique contract literally unchanged; the second is more explicit but
  touches every technique's `surfaces()`. *(inference: the first is lower risk.)*

---

## 7. The one-line summary

**Stop requiring preconditions to be declared; make them measured.** The
instruments already exist inside the verifiers — extract them into a third
registry-discovered folder family (`elicit/`), write their answers as graded
capability facts onto the surfaces, and let the same record serve as the
postcondition that closes a chain. Then CVE/CWE/CAPEC ingestion has something to
feed: a corpus of preconditions and payloads, against an engine that can finally
establish the conditions those payloads need.
