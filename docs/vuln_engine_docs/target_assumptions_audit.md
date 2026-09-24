# Audit: target-specific assumptions in the engine (2026-09-24)

**The question:** after the first real-target runs, is any engine code — kernel,
techniques, scheduler, observation, transports — assuming things only true of the
fixture or of Juice Shop? The operator layer (`run_engine.py` profiles, compose,
docs) legitimately names targets; the engine must not.

**The falsifiable test** used throughout: *delete the fixture and Juice Shop from
compose; nothing in `service/vuln_engine/` may change meaning.*

---

## What was swept

| Surface | Method | Result |
|---|---|---|
| Hard-coded hosts, ports, paths, target names | `grep` over `service/vuln_engine/`, `run_engine.py`, `tests/` for `127.0.0.1`, `localhost`, `:8080`, `:3000`, `:9009`, `fixture`, `juice`, `dvwa` | clean |
| Param-name special-casing in techniques | grep for quoted common param names in `techniques/` | clean — every grammar reads `surface.param` |
| `where` / architecture branching | grep for `surface.where` in techniques | clean — only surfaced into candidate metadata; eligibility lives in `kernel.technique.EngagementSeed.with_param()` |
| Hypothesis gating | read all four `hypothesis.py` | clean — preconditions are capability names, not target shapes |
| Observation layer | read `world/observe.py` context classification; ran JSON-vs-HTML probe | **finding F1** |
| Calibration constants | read manifest noise profiles, timing margins, settle windows | **finding F3** |
| UCB / campaign priors | read `scheduler/ucb.py`, `campaign.py`, `llm/rank.py` | clean — priors are per-campaign, all-zero without a key, never persisted across engagements |
| Policy gate | read URL/host agreement check | clean — decoupled from target identity |
| Payload constants | read all four probe grammars | **finding F2**, plus a confirmed-clean contrast (`xss_reflected`) |

---

## Findings

### F1 — the wire lens assumes every response is HTML (real, general; the JSON-API cost is measured)

`http_observations` runs `find_reflection` on `exchange.text` unconditionally —
there is no Content-Type gate. `classify_context`'s state machine begins in
`CONTEXT_RAW_HTML` and understands only HTML tokens, so a canary echoed inside a
JSON string value classifies as `raw_html` — which sits in
`SCRIPT_EXECUTABLE_CONTEXTS`. Measured directly:

```
JSON value context:   raw_html      <- a *executable* context, claimed from JSON
HTML attr context:    double_quoted_attribute   (control, correct)
```

Consequence on any JSON API that echoes a parameter (the Juice Shop search API
was exactly this shape in the first breadth run): `xss_reflected` proposes an
"executable" candidate whose context is fiction, the `requires_context` gate
opens, and the verifier burns a loud browser run that structurally cannot
succeed — the browser renders JSON as text, so the payload bytes never parse.
Cost: one wasted loud action per JSON-reflection surface, and a candidate whose
recorded *reason* misstates the world.

**The general fix (not per-target):** gate the reflection lens on response shape —
skip reflection parsing when Content-Type is not HTML-ish (keep the
`observation.http` row either way; the wire canary row stays honest), or teach
`classify_context` a JSON-string context that is non-executable by construction.
The *fuel* is Juice Shop's JSON API; the *rule* is general.

### F2 — `sqli_blind_time` ships one payload, and it is the fixture's (real; timing-only today) — **RESOLVED 2026-09-24**

> **Resolution:** replaced by a four-shape interpolation family (numeric,
> quote_closed, quote_paren, comment) of real `SLEEP(n)` payloads, one injected
> population per shape, winner picked by the interpreter and carried in the
> confirmation spec so the verifier re-measures the same SQL. First live firing:
> DVWA Low `sqli_blind`, `quote_closed` separated 4.00s vs 0.00s, verified
> `grade=differential` on fresh measurement. See `progress.md`.

`SLEEP_PAYLOAD = "ve-sleep"` is a bare substring with no SQL semantics; its only
meaning is that the fixture's `/delay` endpoint sleeps on it. The module
docstring says so out loud ("Against a real target the payload row below is what
changes; the grammar does not"), and the candidate honestly reports "equally
consistent with a slow target" — the evidence bar (fresh differential measurement
beyond a margin) does not depend on the payload being real SQL. So this is not a
false-positive risk; it is a **coverage** claim dressed as a technique name:
`sqli_blind_time` currently measures "does this param change response time," not
"injected SQL causes a delay."

**The general fix:** a small payload family in the technique's own grammar —
boolean/CASE WHEN time-delay variants across common interpolation shapes
(`'`-closed, numeric, `')`-closed) — proposed in cost order exactly like the XSS
breakout table, with the verifier unchanged (it re-measures whatever payload the
candidate carries). No target names enter the grammar; the family is defined by
interpolation shape, which is a property of the class.

### F3 — calibration constants were set by first-target experience (benign, declared)

`sqli_blind_time.SAMPLES_PER_POPULATION = 2` ("Even at the fixture's 2s sleep…"),
the timing verifier's margin, and `browser.DEFAULT_SETTLE = 0.6` were all chosen
against the fixture and then survived contact with Juice Shop because the
A/B-style checks happened outside the engine. They are generic policy numbers
(declared in manifests and specs, visible in the log), not target-shaped logic —
but they are untested against heavy real apps (the Juice Shop A/B showed Angular
booting in ~2s; a slower app could answer the placement questions before the SPA
settles, reading as `dom_absent`). Worth a deliberate re-look when a second SPA
or a slow target shows up, not a code change today.

---

## Verified clean (the load-bearing negatives)

- **Zero target names or shapes in engine code.** The only loopback/port strings
  live in transport plumbing (CDP endpoint negotiation, collaborator defaults)
  and compose files.
- **Every grammar is surface-parameterised.** No technique mentions a param name;
  URL arithmetic goes through one shared `with_parameter`.
- **Capability gating is the operator boundary.** `oob_fetch` fires only on a
  declared `influence_remote_fetch`; hypotheses carry named preconditions. Target
  knowledge stays with the operator, by construction.
- **No cross-target memory.** Receipts are per output directory; UCB history and
  advisory priors are per campaign; nothing persists technique success rates
  between engagements (case memory is a listed future phase, not an accident).
- **The verifier bar is payload-agnostic.** Execution is proven by markers set by
  the payload's own script; the differential verifier re-measures fresh. Neither
  reads target identity.

## Where the "molding Juice Shop" risk actually stands

The Juice Shop work added **no engine code** (`deee653` built `xss_dom` against a
generic fixture; the SPA attempts added docs and compose only). But the
measurement habits it taught us are leaking in two places — F1's fuel and F2's
fixture-shaped payload predate Juice Shop yet would mislead exactly the kind of
target Juice Shop is. Both fixes are grammar-level and class-shaped; both are
tracked below so they compete for the next slot honestly instead of riding in on
the next target anecdote.

## Suggested order (unchanged by the audit, re-justified by it)

1. **DVWA next** (target diversity before grammar growth — the strongest
   anti-overfit move available).
2. **F1: response-shape gate in the observation layer** (small, general, and it
   removes a measured false-lead cost on the *most common* real-world echo
   shape — a JSON API).
3. **F2: a general time-delay payload family** in `sqli_blind_time`'s grammar
   (turns a fixture-only technique into a class-shaped one).
4. `where=fragment` stays **parked** until a second hash-route target demands it
   (n=2 before grammar).
