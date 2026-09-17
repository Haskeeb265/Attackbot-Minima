# Documentation Index

Everything the repo's prose documents, and what each one is actually for. If two
documents ever disagree, the **code is the source of truth** and the spec family
below is the intended design — file an update to whichever is wrong.

## Where to start

| You want to… | Read |
|---|---|
| run the project | [`../README.md`](../README.md) |
| run or extend the subdomain/domain/wildcard pipeline | [`../service/recon_pipeline/asset_pipelines/subdomain_domain_wildcards/README.md`](../service/recon_pipeline/asset_pipelines/subdomain_domain_wildcards/README.md) |
| understand how active traffic is shaped, and why (stealth, spec §5.1) | [`../service/recon_pipeline/stealth/README.md`](../service/recon_pipeline/stealth/README.md) — what detectors measure, live-capture evidence, design, knobs, measured cost, and the not-built list |
| understand what the whole system is meant to become | [`recon_docs/recon.md`](recon_docs/recon.md) + [`recon_docs/recon_v2.md`](recon_docs/recon_v2.md) |
| know what is built versus planned | the status section in [`recon_docs/IMPLEMENTATION_PLAN.md`](recon_docs/IMPLEMENTATION_PLAN.md) and [`recon_docs/IMPLEMENTATION_PLAN_V2.md`](recon_docs/IMPLEMENTATION_PLAN_V2.md) |
| work on the scraper or the `bounty_*` schema | [`scraper_docs/schema.md`](scraper_docs/schema.md) |
| get an orientation pass over the codebase | [`codebase/`](codebase) — stack, structure, architecture, conventions, integrations, testing, concerns |

## The document sets

### `codebase/` — generated orientation docs

A snapshot of the repository as it is: stack, structure, architecture,
conventions, integrations, testing, and current concerns. Written to be read in
that order; each file ends with the evidence it was written from.

**These are checked against the code, not against the plans.** Where they describe
a subsystem as not built, that is the plan's state, not a bug in the doc:
[`codebase/CONCERNS.md`](codebase/CONCERNS.md) is the honest list of gaps.

### `recon_docs/` — the recon specification and its plans

A two-layer specification, in the order it was written:

| Document | Role |
|---|---|
| [`recon.md`](recon_docs/recon.md) | **v1 spec** — the ASM architecture: sources, extraction, scoring, recursion gate, stealth, graph-of-record |
| [`recon_v2.md`](recon_docs/recon_v2.md) | **v2 spec** — *extends* v1, does not replace it: the Scope Engine, eleven new source classes, takeover detection, secret-handling contract |
| [`recon_flow.md`](recon_docs/recon_flow.md) | v1 Mermaid flow diagrams (S0–S14) + component glossary |
| [`recon_flow_v2.md`](recon_docs/recon_flow_v2.md) | v2 flow diagrams — the Scope Engine as the safety chokepoint |
| [`IMPLEMENTATION_PLAN.md`](recon_docs/IMPLEMENTATION_PLAN.md) | v1 implementation plan, 15 stages S0–S14, with locked-in decisions and an implementation-status section |
| [`IMPLEMENTATION_PLAN_V2.md`](recon_docs/IMPLEMENTATION_PLAN_V2.md) | v2 implementation plan, 12 stages S15–S26, continuing the same numbering |
| [`graph_crud_contract.md`](recon_docs/graph_crud_contract.md) | the multi-label write contract every graph writer must follow (implemented) |
| [`python_vs_rust.md`](recon_docs/python_vs_rust.md) | the language decision, per stage, and why Python was chosen |

v1 and v2 are **not alternatives**: v2 is an extension layer that inherits v1
unchanged, and the plans chain the same way (S0–S14 first, then S15–S26). Read the
v1 pair first.

### `scraper_docs/` — the HackerOne data layer

| Document | Role |
|---|---|
| [`schema.md`](scraper_docs/schema.md) | the `bounty_*` tables, the API→mapper→DB field mapping, and the write patterns per table |
| [`program_attributes.md`](scraper_docs/program_attributes.md) | which HackerOne program attributes the scraper actually filters on, and the priority tiers it builds from them |

### Outside `docs/`

- Per-stage READMEs under `service/recon_pipeline/asset_pipelines/` — the
  operator-facing documentation for the built pipelines
  (`subdomain_domain_wildcards/`, `port_service_host/`): flags, outputs,
  settings, measured yields and live caveats. These are the most current docs in
  the repo.
- [`stealth/README.md`](../service/recon_pipeline/stealth/README.md) — the stealth
  layer's own doc: what modern detectors measure (JA4 + inter-request signals,
  DNS volume thresholds), the measurements taken on this repo's own toolchain,
  every knob, the measured cost of shaping, and what is deliberately not built.
- [`port_service_host/DESIGN.md`](../service/recon_pipeline/asset_pipelines/port_service_host/DESIGN.md)
  — that pipeline's research doc: passive-first IP intelligence, the L0–L3 scan
  ladder, tool choices with verified vendor claims, efficiency math, and the
  phased plan. Its header records the deltas between this plan and the shipped
  build, so the doc stays true now that the code exists.
- [`commands.txt`](../service/recon_pipeline/asset_pipelines/subdomain_domain_wildcards/commands.txt)
  — raw Docker commands for every bundled tool, for reproducing or debugging one
  tool by hand — including the shaped (identity + impersonation + rate limit)
  variants the stages actually build.
- `ai-agent-workspace/` — agent and skill definitions. Tooling configuration, not
  project documentation.

## Conventions used here

- **Paths in backticks.** A backticked path containing `/` is either
  repo-root-relative or starts with `.../`, the one shorthand used throughout:

  - `.../` = `service/recon_pipeline/asset_pipelines/subdomain_domain_wildcards/`
    — e.g. `.../passive/wildcard.py`

  Runtime artifacts are named without a path (`report.json`, `resolved.txt`,
  `records.jsonl`); a stage writes them into its own `output/`. Names that are
  deliberately **non-existent** are only ever mentioned as history — a renamed
  module (`chaos-client.py`), a deleted fixture (`test_detail_output.json`), or the
  removed project context doc `scope.md`.
- **Specs and plans describe intent; nothing in them is evidence that something
  exists.** The spec family (`recon_docs/recon.md`, `recon_v2.md`, `recon_flow*.md`,
  `IMPLEMENTATION_PLAN*.md`) is the one place where a backticked path may name a
  module that does not exist yet — those are *intended* locations, and each such
  document says so at the top. Everywhere else in `docs/`, a named path resolves to
  a real file.
- **Status is stated, not implied.** What is built lives in one place per plan
  (`IMPLEMENTATION_PLAN.md#implementation-status`), with real paths.
- **Every claim about current behaviour should be reproducible** from a command in
  the doc, or from reading the file it names. A stale reference is treated as a
  bug: outside the spec family, a link/path checker over `docs/` should report
  nothing.
- **Measurement tables carry a date and a target**, because tool yields vary run
  to run.
