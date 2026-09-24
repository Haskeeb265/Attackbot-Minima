# R&D: the VWA training program (2026-09-24)

**The idea.** The engine learns the way a junior pentester does: by working many
deliberately vulnerable apps (VWAs) end to end — not by being fed answers. Each
VWA is a *training bout*: bootstrap as an operator, declare surfaces, run a
campaign, read the log honestly, record what the engine caught and what it could
not see. "Training" here is **measurement and calibration**, not AI training: no
weights change, no corpus is fine-tuned. What accumulates is evidence about the
engine — which lenses fire on which architectures, where the honest zeros come
from, and which generalization debts are real.

The pattern was set by the first two bouts and is deliberately repeatable:

| Bout | Target | Architecture | Result | What it taught |
|---|---|---|---|---|
| 1 | Juice Shop 20.2.0 | Angular SPA, hash routing, JSON API | honest zero + measured capability gap | server-echo lens cannot see client-side rendering; `with_parameter` cannot aim inside a fragment; JSON echoes misclassify as `raw_html` (F1) |
| 2 | DVWA 1.15 (Low) | server-rendered PHP/MySQL, login-walled | **2 findings** (`execution`, `differential`) | the lens pair works on its home architecture; session shim is mandatory; `Submit=Submit` belongs in the declared surface, not the engine; F2's family fired for real |

**Why VWAs and not bug bounties first.** A VWA is a target with known ground
truth (public write-ups, `Impossible` reference implementations) at zero legal
and reputational cost. Ground truth is what makes a training bout *scorable*:
after each campaign we can say precisely which vulnerabilities the engine
proved, which it saw and could not confirm, and which its lenses are blind to
by construction. That scorecard is the training signal. A bounty target gives
no ground truth and tolerates no noisy learning curve.

---

## The anti-coupling rules (the whole point)

The program only works if the targets train the *operators* and calibrate the
*engine*, never rewrite it per target. The rules, already enforced twice:

1. **Target knowledge lives in the operator layer.** Surfaces, cookies, fixed
   params (`Submit=Submit`), security-level choices: all declared via
   `run_engine.py --surface/--cookie`, never read from a target's source inside
   the engine. The falsifiable test stays: *delete every VWA from compose; no
   engine code changes meaning.*
2. **N=2 before grammar.** A gap seen on one target becomes a roadmap note;
   the same gap seen on a second target of the same class becomes a grammar
   change defined by the *class* (interpolation shape, routing style, response
   type), never by the target's name. `where=fragment` is currently parked on
   exactly this rule.
3. **Findings must pass the evidence bar unaided.** A finding is
   browser-execution / collaborator / fresh-differential proof, never "the
   write-up said so". The VWA's known vulns are the *answer key*, consulted
   after the run, never during.
4. **Honest zeros are results.** A lens that cannot see a class is a measured
   fact about the instrument (the Juice Shop bout produced F1, the fragment
   gap, and two CLI bugs — worth more than a lucky find).
5. **Per-bout artifacts are output dirs and docs, not code paths.** No
   `techniques/` module may import, mention, or branch on a training target.

---

## The roster (architecture-first, not brand-first)

Ordered so each new bout stresses a dimension no prior bout covered. Server-
rendered PHP (DVWA) and Angular SPA (Juice Shop) are done; everything else
picks a new axis. All are compose-deployable, Docker Hub images unless noted.

| # | Target | New axis it stresses | Expected lenses | Predicted honest gaps |
|---|---|---|---|---|
| 3 | **WebGoat** (`webgoat/goatandwolf`) | Java/Spring, REST-first, session + CSRF tokens everywhere | `xss_reflected` where echoes exist | token-gated endpoints fail without an operator CSRF shim; JSON echoes → F1 bites |
| 4 | **OWASP Security Shepherd** (`owasp/security-shepherd`) | mixed challenge classes, one app | per-chapter surfaces | multi-class in one app stresses the scheduler's noise budget |
| 5 | **Mutillidae II** (`citizenstig/nowasp` or build) | classic LAMP, many mirrors of the same vuln class | `xss_reflected`, `sqli_blind_time` | same-vuln-many-params tests dedupe/receipt behavior |
| 6 | **bWAPP** (`raesene/bwapp`) | 100+ bug types, PHP, level dial like DVWA | broad sweep at `low` | classes we have no technique for → the roadmap's honest size |
| 7 | **Rails Goat** (`6point6/railsgoat`) | idiomorphic Rails, mass-assignment/SQLi | thin — mostly `oob_fetch`-shaped | framework ERB escaping vs our context classifier |
| 8 | **DVWA Medium/High** (same container) | the *defense* axis: sanitization, tokenization, WAF-ish filtering | same as bout 2 | the false-positive control's real test: Low finds it, High must honestly not |
| 9 | **Juice Shop again** (after `where=fragment`, n=2 rule met) | hash-route fragment params | `xss_dom` | the parked capability, un-parked by a second SPA bout, not by the first |

Bouts 3–7 are breadth (new architecture per bout); bout 8 is depth (the same
target hardened — the closest thing to a regression suite for the *evidence
bar*); bout 9 closes the loop on the first honest zero.

---

## Per-bout protocol (the repeatable pattern)

1. **Compose up, operator bootstrap** — a `docker/<target>_bootstrap.py` that
   does what a pentester does in a browser (DB setup, login, level), prints the
   `--cookie` header value. CSRF token handling lives here, in the open.
2. **Black-box preflight** — curl/httpx the candidate surfaces the way the
   engine will send them (no Submit? encoding? redirects?). Facts found here
   become *surface declarations*, never engine edits.
3. **Declare surfaces** — one `--surface` per input, capability honest
   (`public_param` vs `delayed_response` vs `influence_remote_fetch`).
4. **Run the campaign** (`--campaign 6 --force`, fresh output dir), AI advisory
   on (`--llm-draft` now that the key is wired) or off for a control run.
5. **Score against the answer key** — findings, leads, honest zeros, and the
   *miss list*: VWA vulns the engine never touched (no technique exists).
6. **Record** — progress.md section + the classification: engine gap, operator
   gap, or target-out-of-scope-for-phase.
7. **Debrief into the roadmap** — anything general moves only via rule 2.

## Success metric for the program

Not "found everything" — a VWA has dozens of vulns and Phase 1 has two-and-a-
half lenses. The metric is the **scorecard's trend**: findings per bout stable
across architectures (no overfit to PHP), false positives zero across all
bouts (the evidence bar holding under the level dial), and the miss list
shrinking only through class-shaped grammar additions. If bout 8 (DVWA High)
produces a finding, the bar is broken; if it produces an honest zero with the
refusal reason naming the defense, the bar is working.
