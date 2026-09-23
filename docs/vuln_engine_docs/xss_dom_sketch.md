# Technique — `xss_dom`: the browser is the parser now

Built and live-verified (2026-09-24); the sketch below is the record of the
design as approved. Companion to [`progress.md`](./progress.md)
§"The first real target" and [`engine_principles.md`](./engine_principles.md).

> **STATUS — BUILT.** 300 tests green (20 new), mypy clean (58 files). Live
> verification against a new fixture endpoint (`/dom`, a client-rendered
> innerHTML sink whose server bytes are parameter-independent): the wire lens
> settled `none`, the placement probe observed the markup probe materialize
> (`raw_html`) beside the text landing (`dom_text`), the `raw_html` candidate
> was confirmed by the verifier at **grade execution** — "the payload's script
> ran in the browser" — and the text placement stayed a lead. Two build-time
> corrections to the sketch: the marker channel is boolean (string answers
> would have been coerced), so placement is established by *which* questions
> answer true, with a custom-element probe (`ve-<mark>`) as the markup test;
> and the markup payload is an `onerror` handler, not a `<script>` tag, which
> the HTML5 parser marks already-started when inserted via `innerHTML`.

---

## The measured gap

`xss_reflected` asks the **server** a question: *did my canary come back, and
where did it land?* The observation layer answers by parsing the **response
bytes** — `classify_context()` walks the HTML up to the reflection offset. On
Juice Shop that question is unanswerable by construction: the server returns the
same `index.html` for every URL, and the search parameter is read by client-side
JavaScript and rendered into the DOM *after* the bytes have left the wire. The
run's honest zero was the measurement of exactly this: a whole class of
injection lives where our lens has no eyes — **the DOM, not the wire**.

The fix is not "parse JavaScript" (a worse swamp than HTML) and not "screenshots"
(a regression to evidence we cannot interrogate). The fix is the one the design
already owns: **the browser is the arbiter — so let it also be the parser.**

## The core idea: land, then ask the DOM where we landed

`xss_reflected`'s canary works because the *server* places our value somewhere
structural and the observation layer reads the placement from bytes. The DOM
technique inverts one half: send the canary, let the page's own JavaScript
render it, then **ask the DOM** where the value ended up — using the same
context vocabulary the byte-parsing layer already speaks
(`kernel/observation.py`'s `REFLECTION_CONTEXTS`). Same facts, new instrument.

The payload is still a **canary, not an exploit**. Proposal-grade evidence only.
What makes a finding remains unchanged: a browser-observed marker or an
independent verifier's confirmation. A DOM placement is a *lead with a
location*, exactly like a byte-level reflection context is today.

## The probe grammar (families, cheapest first)

1. **DOM canary probe** (quiet, HTTP): fetch the page with the canary in the
   parameter. Costs one request. On its own proves nothing new — it is the
   round-trip that tells the browser probe the value survived *into* the page's
   input path (some sinks encode or drop it before any render).
2. **DOM placement probe** (browser): run the page with the canary, then answer
   one question per `Marker` — *where is my value in the DOM tree?* The
   observation is placement, not execution:
   - `element_text` — the canary is text content (like `CONTEXT_RAW_HTML`'s
     weaker cousin: it lands, but as text)
   - `attribute_value` — inside an attribute value (which attribute is recorded
     structurally: `src`, `href`, `title`, …)
   - `raw_html` — injected as markup (a node was *created* by our bytes)
   - `js_string` / `js_code` — landed inside script state (interrogated via
     `window.__ve_*` markers, same spelling the execution payload uses)
   - `absent` / `unknown` — the honest rows: encoding, dropping, or an
     instrument that could not tell. Never silently "safe".
3. **Execution payload probes** (browser, loud, `requires_context`): only where
   a placement row named an *executable* placement. Payloads are **the same
   table** as `xss_reflected`'s (`BREAKOUT_PREFIX`-style breakout, the fixed
   dialog text, the deterministic `__ve_xss_*` marker identifier) — with one
   addition: a **DOM marker** that reports not just "script ran" but *which
   inserted node* it ran from. The verifier's evidence bar is unchanged —
   `OBS_SCRIPT_EXECUTION` + `OBS_DIALOG` — but the provenance row names the
   sink, which is what makes the finding reportable ("executed from an
   innerHTML sink rendering the searchQuery parameter") instead of merely true.

## What the kernel needs (the small list)

- **`OBS_DOM_PLACEMENT = "observation.dom_placement"`** — a new observation
  kind. Payload: `context` (the *same* enum values as reflection contexts, so
  every downstream consumer — verifier, scheduler, memory — needs no new
  vocabulary), `container_tag`, `container_id`, `attribute` (when
  `attribute_value`), `sink_guess` (optional, `""` when unknown).
- **`Contexts` are shared, not duplicated.** The invariant test that pins
  `REFLECTION_CONTEXTS` gains a sibling pinning the DOM placement rows to the
  same enum. One vocabulary, two instruments — this is the load-bearing rule of
  the whole sketch.
- **`RawBrowserRun`** gains nothing: placement markers ride the existing
  `markers: dict[str, str]` channel ("named predicate → JS expression →
  truthy answer"). The DOM questions are just more questions the runner asks
  the page. No transport change, no capability report change.

## What the technique folder looks like (the contract holding)

```
techniques/xss_dom/
    __init__.py      # the thin adapter, same shape as every other technique
    hypothesis.py    # "param P is rendered into the DOM at/after load"
    probes.py        # canary → placement → payload, gated on placement rows
    interpret.py     # placement rows → candidates (proposal-grade, never finding)
    manifest.py      # NoiseProfile: browser multiplier on placement+payload only
```

- `surfaces(seed)`: parameterised surfaces claiming `public_param` or no
  capability — deliberately overlapping `xss_reflected`'s appetite. The two
  techniques ask different questions of the same surface ("did the *server*
  echo?" vs. "did the *page* render?"), which is exactly what the attack tree's
  OR nodes and the scheduler's noise division are for. On Juice Shop the first
  settles `none` and the second gets to work.
- The dedupe question: when `xss_reflected` already found a server-side
  reflection in an executable context, is the DOM technique redundant there?
  **Yes — and that is `interpret()`'s business to respect.** A DOM candidate on
  a surface where a byte-level reflection already produced a candidate is
  dropped as a duplicate *attack path* (same vuln class, same param, same
  execution oracle). What remains unique to this technique is precisely the
  case the fixture could never teach it: no wire reflection, DOM placement all
  the same.

## The honesty rules this technique must inherit

1. **Placement is a lead, execution is the finding.** A `raw_html` placement
   row never becomes a candidate without the payload probes' marker/dialog
   evidence behind it — the same bar, one step later in the pipeline.
2. **`absent` and `unknown` are recorded rows, not absences.** The run log must
   be able to say "the canary did not reach the DOM" as a *fact with a reason*
   (encoded away, dropped by the framework, or our instrument failed), because
   that fact is what the memory layer will one day generalise over.
3. **The DOM questions are predicates, not paragraphs.** Every marker is a
   boolean JS expression the runner evaluates — the same "an oracle is a
   question with a boolean answer" discipline as `xss_reflected`. No marker may
   return "looks suspicious" — that way lies a model's opinion wearing a
   verifier's clothes.
4. **No new evidence class.** DOM placement evidence grades as `reflection`
   (it *is* a reflection — observed by a different instrument). Execution still
   requires the `execution` class. The grading bar does not move because the
   instrument got better eyes.

## What this unlocks beyond Juice Shop

The DOM lens is the general answer to the modern web: SPA frameworks, client
side routing, framework-escaped sinks. It also sets up the two techniques the
roadmap reserved for the attack tree's AND edges — stored injection (payload
lands in a *different* request than the one that rendered it) and post-auth
surfaces (the session shim's territory) both become expressible once "the page
rendered our value" is an observation the engine can record.

## Sequencing

1. Kernel: `OBS_DOM_PLACEMENT` + the shared-vocabulary invariant (half a day).
2. `techniques/xss_dom/`: placement family first, payload family second,
   against a **fixture extension** — the fixture app gains a tiny client-render
   endpoint (a page whose JS writes `location.search` into `innerHTML`), so the
   technique is born tested against the same standard as everything else:
   no network in its tests, the browser runner mocked with canned marker maps.
3. Live: re-declare Juice Shop's `#/search` surface, run the campaign, and let
   the first genuine finding be found by the lens the honest zero demanded.
