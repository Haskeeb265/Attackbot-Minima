# Attribution convention (pinned before the first contested case)

Every attributed miss in a debrief records this block, filled by the scorer and
confirmed or corrected by a human:

```
vuln_id:        <case>/<page>/<param>
outcome:        miss | partial | fp | unadjudicated
primary_stage:  <one stage from the table below>
contributing:   [<stage: short reason>, ...]   # listed, never ranked
evidence:       "<the log rows that prove the primary stage failed>"
attribution_by: scorer | human
confidence:     high | medium | low
```

## The primary-stage rule

**The earliest stage in the causal chain whose absence or failure directly
caused the outcome.**

Rationale: fixes compose downstream. Repairing a later stage changes nothing
while an earlier one still blocks the path, so the earliest blocker is the
actionable one; the contributing stages re-enter the debrief once it is fixed.

**Tie-breaker:** when two stages fail simultaneously with no causal ordering
between them, primary goes to the stage whose fix is *more general* (the
class-shaped candidate), and the attribution carries `confidence: low` so a
human re-reviews it in the debrief.

## The stage table (each stage's log evidence)

| Stage | Question | Log evidence of failure |
|---|---|---|
| DISCOVERY | did recon find the endpoint? | *N/A today — the engine has no discovery; scored as the operator gap* |
| SURFACE | was it declared/represented? | GT surface absent from `run.begin`'s `surfaces` |
| CHARACTERIZE | were inputs characterized? | surface declared, no probe rows reached the param |
| HYPOTHESIS | was a hypothesis generated? | no `note(stage=hypothesis)` row for a plausible technique |
| TECHNIQUE | did the right technique run? | hypothesis exists; `probe.*` rows absent or `probe.gated` |
| OBSERVATION | did probes see enough? | probes ran; no supporting `observation.*` rows |
| VERIFICATION | was a valid candidate confirmed? | `candidate` row exists; no `verdict proven=true` |
| FALSE-POSITIVE | claimed without proof? | `verdict proven=true` matching no GT (post-adjudication) |
| ADVISORY | did the LLM layer fail? | `llm.junction` rows degraded/invalidated where a validated one would have mattered |
| POLICY | did orchestration block a valid test? | `gate.decision` verb ≠ ALLOW on an in-scope surface |
| EVIDENCE | proof thin for the report? | proven verdict whose evidence lacks repro fields |
| REPORTING | can a reader understand it? | qualitative; scored by hand, rarely |

## Worked examples (the two completed bouts, attributed under this convention)

**1. Juice Shop SPA search — outcome: miss; primary: SURFACE; confidence: high.**

```
vuln_id:        juice-shop/search/searchValue
outcome:        miss
primary_stage:  SURFACE
contributing:   [SURFACE: with_parameter cannot aim a param inside a hash-route
                 fragment (the representation half of the same gap)]
evidence:       "run.begin surfaces list the JSON API only; the fragment surface
                 the grammar accepts carries the param in the real query string,
                 which the SPA never reads (0 dom_placement rows, honest)"
attribution_by: human
confidence:     high
```

Why SURFACE and not OBSERVATION: the placement lens ran and answered its
questions honestly — nothing was misobserved. The value never reached the
engine's model of the target at all, which is the SURFACE stage's job. The
fragment gap is the *contributing* representation failure; the fix (where=
fragment) stays parked on the n=2 rule.

**2. DVWA sqli_blind (pre-F2 world) — outcome: would have been miss; primary:
TECHNIQUE; confidence: high.**

Before the payload family landed, the technique's only injected payload was the
fixture's bare substring: hypothesis generated, probes ran, populations did not
separate. Attribution under the rule: TECHNIQUE (the grammar could not express
the class), not OBSERVATION (the timing instrument measured correctly) and not
HYPOTHESIS (the claim was right). F2's fix — an interpolation-shape family — is
the class-shaped repair this convention exists to point at.

**3. F1 JSON echo (pre-gate world) — outcome: would have been fp-shaped;
primary: OBSERVATION; confidence: high.**

A JSON echo classified `raw_html` (executable) produced an executable candidate
whose context was fiction, spending a loud browser run that could not succeed.
OBSERVATION is the primary (the lens misdescribed the world — declared type
ignored), and the fix is the response-shape gate: general, class-shaped, and
now landed (commit 9db1448).

## The fix-review question (attaches to every debrief)

> What is the **class** of this failure, and would the proposed fix help on an
> app we have not run?

A fix whose honest answer names a target, a page, or a payload spelling fails
review. One case's quirk is a roadmap note; two same-class cases earn a
class-shaped grammar change (the n=2 rule).
