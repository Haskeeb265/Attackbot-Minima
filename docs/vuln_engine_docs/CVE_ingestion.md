CVE/CWE Technique Ingestion Pipeline

A build guide for vuln_engine — how to turn public vulnerability data into registered techniques

Scope: known-bug ingestion only. The abductive loop / novelty module is out of scope by request.

Verified against `service/vuln_engine/` at commit **512cc9d**. Every kernel
constant, manifest field and gate named in this file was read from that
commit's source, not from prose about it. If a sentence here names a
kernel value, it cites the file it came from — that rule is what stops
the next draft inheriting an error instead of the code.

    Correction notice. An earlier draft was written from the phase checklists and README without reading the kernel source. Every code sample in it used invented signatures. This version replaces those with either (a) code verified against a live external API, or (b) clearly-labeled pseudocode that does not claim to know kernel signatures. Where the kernel's real shape matters, the doc points at the file instead of guessing.

    The hardest thing in this document, stated up front. Stages 1–2 (fetch by CWE, map to a canonical vuln_class) are buildable today, verified against the live NVD and MITRE APIs, and useful. Stage 3 (extraction from prose to a working probe family) is where the pipeline either does something honest or fails silently. The state of the art for "prose → working exploit" is ~17% given source code. This pipeline has no source, no runtime, and no PoC for roughly 96% of CVEs. §6 and §8 are the sections to read before committing to a build plan.

1. What this pipeline is, and what it is not

Is: a tool that reads public vulnerability data, maps each CVE to the engine's canonical vuln_class vocabulary, extracts a candidate payload variant or candidate technique proposal, and produces something a human can review and merge into an existing technique folder.

Is not: an autonomous technique generator. The engine's design — evidence classes, independent verifiers, the chokepoint — is a measurement discipline, and generating techniques from prose is an authoring discipline. They are different problems and the second is unsolved at this scale.

The engine's receiving end is fixed: TechniqueRegistry.discover() walks techniques/*/, validates manifests, and refuses a technique without postconditions. The pipeline produces artifacts the registry can consume — most of them variants for existing folders, rarely a new folder.
2. The core principle

A CVE is source material, not a technique. The pipeline's job is transformation, not transcription.
text

CVE disclosure ──► classified record ──► variant spec ──► technique folder (rare) or
   (NVD, GHSA)       (CWE → vuln_class)   (payload +         probes.py edit (common)
                                           shape + oracle)

The most important consequence: most CVEs do not need a new technique. They need a new payload variant inside an existing technique. Two XSS techniques gate on the same claim, three share `script_execution` as a postcondition, two timing techniques gate on `delayed_response`, and two differential techniques take `access_differs_by_session`. The payload grammar is the variable; the capability and verifier are the constants.
3. Data sources
Source	Endpoint / Format	What it gives	Verified
NVD API v2.0	https://services.nvd.nist.gov/rest/json/cves/2.0 (JSON)	CWE, description, CPE, references, CVSS	✓ (rate limits, resultsPerPage max 2000, cweId filter all confirmed)
MITRE CWE REST API	https://cwe-api.mitre.org/api/v1/ (JSON)	CWE hierarchy, abstraction level	✓ (response shape confirmed — see §5.3)
MITRE CAPEC	XML download	Attack patterns, CWE links	not called
GitHub Security Advisories	https://api.github.com/advisories	CWE IDs, references	not called
Exploit-DB	CSV / scrape	PoC code	not called
CISA KEV	JSON feed	Exploited-in-the-wild flag	not called
EPSS (FIRST)	JSON API	Exploitation probability	not called

NVD rate limits (confirmed):
Key status	Limit	Practical delay
No API key	5 req / 30 s	~6 s between requests
With API key	50 req / 30 s	~0.6 s between requests

Request a free NVD API key before building. The pipeline is not usable without one for bulk work.
4. Stage 1 — Ingest
4.1 Filter by CWE, not by CVE

Iterate CWEs that map to your canonical vocabulary, not all CVEs. The NVD API supports a cweId parameter:
text

GET https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-89&resultsPerPage=2000

This returns every CVE classified under that CWE in one paginated query. For a pipeline that adds by class, this is the correct entry point.
4.2 The record fields that matter

From the NVD v2.0 response:
text

vulnerabilities[].cve
├── id                          # "CVE-2024-12345"
├── descriptions[].value        # prose
├── weaknesses[]                # CWE classifications
│   └── description[].value     # "CWE-89"
├── configurations[]            # CPE matches
└── references[]
    └── url, tags[]             # "Exploit" tag → possible PoC

weaknesses[].description[].value is the bridge to vuln_class. A CVE may carry multiple CWEs; collect them all and let the classifier pick the canonical one.
4.3 Prioritization

Not every CVE is worth a variant. Rank by:

    CISA KEV membership — known exploited

    EPSS score — exploitation probability

    PoC availability — references[].tags contains "Exploit", or an Exploit-DB entry exists

    CVSS severity — critical/high first

A CVE with a public PoC and a KEV flag is the highest-value target. A CVE with no PoC and no advisory detail is not technique material.
4.4 Fetcher (verified against live API)
python

# ingest/fetch_nvd.py
import os, time, json, httpx
from pathlib import Path

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

#: Confirmed against the live API: 5 req / 30 s with no key, 50 req / 30 s with
#: one. 6.2 s is the keyless floor (5 requests + 1 s of slack per window).
DELAY_KEYED = 0.7
DELAY_KEYLESS = 6.2

def fetch_cves_by_cwe(cwe_id: str, out_dir: Path) -> Path:
    """Paginate NVD for one CWE into a deduped, re-runnable JSONL cache.

    Write-then-merge, not append: a 403 partway through a keyless run would
    otherwise leave a partial file that the next run appends to, and every
    record fetched twice is counted twice by the classifier. Merging on CVE id
    makes a re-run idempotent, which is what lets it be safe to retry.
    """
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    headers = {"apiKey": api_key} if api_key else {}
    delay = DELAY_KEYED if api_key else DELAY_KEYLESS

    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{cwe_id}.jsonl"

    # Existing cache, keyed by CVE id. A NVD record for a given id does not
    # change meaningfully, so the first copy wins and re-fetching is a no-op.
    seen: dict[str, dict] = {}
    if out.exists():
        for line in out.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                seen[rec["cve"]["id"]] = rec
            except (json.JSONDecodeError, KeyError, TypeError):
                continue  # a corrupt line must not poison the whole cache

    start_index, per_page = 0, 2000  # maximum confirmed
    fetched_new = 0
    while True:
        resp = httpx.get(
            NVD_BASE,
            params={"cweId": cwe_id, "resultsPerPage": per_page,
                    "startIndex": start_index},
            headers=headers,
            timeout=30,
        )
        if resp.status_code == 403:
            raise RuntimeError(
                f"NVD rate limit hit at startIndex={start_index}. "
                f"Got {len(seen)} records cached; re-run after a window resets."
            )
        resp.raise_for_status()
        body = resp.json()

        for v in body.get("vulnerabilities") or []:
            cve_id = v.get("cve", {}).get("id")
            if cve_id and cve_id not in seen:
                seen[cve_id] = v
                fetched_new += 1

        total = body.get("totalResults", 0)
        if start_index + per_page >= total:
            break
        start_index += per_page
        time.sleep(delay)

    tmp = out.with_suffix(".jsonl.tmp")
    tmp.write_text(
        "".join(json.dumps(seen[k]) + "\n" for k in sorted(seen)),
        encoding="utf-8",
    )
    tmp.replace(out)  # atomic: a crash mid-write leaves the old cache intact
    return out, len(seen), fetched_new

Cache aggressively. One JSONL per CWE, deduped on CVE id, idempotent on re-run.
Re-fetch on schedule or on a KEV/EPSS signal.

Note the return signature: ``(path, total, newly_fetched)``. A second run
returns ``newly_fetched == 0``, which is the cheap regression test for this
function — if it is ever non-zero on an unchanged corpus, the dedup broke.

4.5 Throughput and eligibility — the honest numbers

The full NVD is roughly 230,000 CVEs. Fetching it takes ~30 minutes with a key. But Stage 3 gates on "a PoC reference exists," and PoC availability is low:

    Householder et al. (USENIX Security 2020): 4.1% ± 0.1% of CVE IDs have public exploit code within 365 days.

    Exploit-DB coverage is lower (~0.4% by some counts).

So the eligible corpus is roughly 900–9,400 CVEs, not 230,000. Build for the eligible set, not the full set. The full set is the fetch; the eligible set is the work.
5. Stage 2 — Classify

Map every CWE in a CVE record to a canonical vuln_class.
5.1 The mapping table
vuln_class	Primary CWE(s)	Engine technique	Status
xss	CWE-79	xss_reflected, xss_dom, xss_stored	built
sqli	CWE-89	sqli_blind_time	built
ssrf	CWE-918	oob_fetch	built
command-injection	CWE-78	command_injection	built
idor	CWE-639, CWE-284	idor_differential	built
path-traversal	CWE-22, CWE-23	—	next
xxe	CWE-611, CWE-776	—	planned (reuses oob verifier)
ssti	CWE-1336, CWE-94	—	planned
open-redirect	CWE-601	—	planned
nosqli	CWE-943	—	planned
code-injection	CWE-94, CWE-95	—	planned
deserialization	CWE-502	—	hard (partial oracle)
missing-headers	CWE-693, CWE-1021	—	planned (passive)

For classes not yet built, the classifier still tags them; the pipeline simply stops at Stage 3 until a verifier exists.
5.2 Abstraction levels

CWE entries exist at four levels: Pillar → Class → Base → Variant. A CVE often carries a Variant CWE that is more specific than the canonical Base. Examples:
CWE	Level	Parent	Canonical
CWE-80	Variant	CWE-79	xss
CWE-83	Variant	CWE-79	xss
CWE-564	Variant	CWE-89	sqli

Rule: walk up the hierarchy until a Base or Class level maps. Cache the hierarchy so a Variant resolves without a network call per CVE.
5.3 MITRE CWE API — the real response shape

The MITRE API returns:
json

{
  "Weaknesses": [
    {
      "ID": "80",
      "Abstraction": "Variant",
      "RelatedWeaknesses": [
        {"Nature": "ChildOf", "CweID": "79", "ViewID": "1000"}
      ]
    }
  ]
}

Three things to get right, all of which an earlier draft got wrong:

    The payload is wrapped in Weaknesses (plural), not at the top level.

    The parent relationship is inside RelatedWeaknesses, filtered on Nature, not a top-level ChildOf key.

    CweID is a string like "79", not a dict.

A resolver that gets any of these wrong returns None for every unmapped CWE, extract() returns None, and the pipeline silently produces nothing — the worst failure mode.
5.4 Resolver (corrected)
python

# classify/cwe_resolver.py
from functools import lru_cache
import httpx

CWE_API = "https://cwe-api.mitre.org/api/v1"

# Static map: Base/Class CWE → canonical vuln_class.
# Extend this table deliberately. Do not add a mapping under pressure.
CWE_TO_VULN_CLASS = {
    "CWE-79": "xss",
    "CWE-89": "sqli",
    "CWE-918": "ssrf",
    "CWE-78": "command-injection",
    "CWE-639": "idor",
    "CWE-284": "idor",
    "CWE-22": "path-traversal",
    "CWE-23": "path-traversal",
    "CWE-611": "xxe",
    "CWE-776": "xxe",
    "CWE-1336": "ssti",
    "CWE-94": "code-injection",
    "CWE-95": "code-injection",
    "CWE-601": "open-redirect",
    "CWE-943": "nosqli",
    "CWE-502": "deserialization",
    "CWE-693": "missing-headers",
    "CWE-1021": "missing-headers",
}

@lru_cache(maxsize=4096)
def resolve_to_canonical(cwe_id: str) -> str | None:
    """Walk up the CWE hierarchy until a canonical class is found."""
    if cwe_id in CWE_TO_VULN_CLASS:
        return CWE_TO_VULN_CLASS[cwe_id]

    # NVD emits sentinel values in weaknesses[] that are not CWEs at all:
    # "NVD-CWE-noinfo" and "NVD-CWE-other". Splitting those yields
    # "CWE-noinfo", which is a guaranteed 404 — one wasted request per
    # occurrence, and they are common. Reject them before the network.
    prefix, _, numeric = cwe_id.partition("-")
    if prefix != "CWE" or not numeric.isdigit():
        return None

    resp = httpx.get(f"{CWE_API}/cwe/weakness/{numeric}", timeout=15)
    if resp.status_code != 200:
        return None

    weaknesses = resp.json().get("Weaknesses", [])
    if not weaknesses:
        return None

    related = weaknesses[0].get("RelatedWeaknesses", [])
    for rel in related:
        # ChildOf means this weakness is a child of the referenced one,
        # so the reference is the parent we want to walk up to.
        if rel.get("Nature") == "ChildOf":
            parent_id = f"CWE-{rel['CweID']}"
            result = resolve_to_canonical(parent_id)
            if result:
                return result
    return None

The static map is the source of truth. The API walk is only a fallback for a Variant CWE that isn't in the map.
6. Stage 3 — Extract: the bottleneck

This is where the pipeline either does something honest or fails. Two things must be said clearly.
6.1 What "extract" means

Given a classified CVE record and optionally a PoC reference, produce a variant spec:
text

VariantSpec:
    technique_name: str          # which existing technique this extends
    payload_fragment: str        # the raw payload bytes (with placeholders)
    interpolation_shape: str     # how the payload is embedded in the parameter
    probe_condition: dict        # header / method / content-type requirements
    source_cve: str
    evidence_class_of_oracle: str  # execution | oob | differential | none
    confidence: float            # extractor's self-assessment
    needs_human_review: bool

A variant spec is small. It is not a technique folder. It is an addition to techniques/<class>/probes.py.
6.2 Why this is hard

The SOTA for "given source code, find and exploit the vulnerability" is roughly 17%:

    CyberGym (1,507 real vulns): best model 17.9% single-trial, given source.

    ExploitGym (898 real vulns, including V8 and Linux kernel): best agent 157/898 = 17.5%, given source code, build instructions, a working PoV, and an interactive container.

This pipeline is strictly harder than both:

    No source code. Only prose from the advisory.

    No runtime. No ability to try a payload and see what happens during extraction.

    No PoC for ~96% of CVEs. The input is largely prose.

    The output must generalize. A technique must work on targets that do not exist yet, not just the CVE's original target.

There is an internal contradiction the pipeline must confront: the review gate says "no hardcoded paths, no vendor names," but a PoC is inherently target-specific. Stripping the vendor and path is the abstraction step, and that step is technique authoring. It is not templating.
6.3 The honest triage tiers
Tier	Input available	What the pipeline can honestly produce
A	PoC code + clear HTTP shape + a matching existing technique	A variant spec with a payload fragment and shape — human review merges it
B	Clear advisory prose + a matching existing technique + no PoC	A variant proposal — a payload fragment guessed from the description, flagged needs_human_review=True
C	Prose only, no PoC, no clear shape	Nothing. Retain the CVE as a priority signal, not a variant.
D	A new class with no existing verifier	A new technique proposal — a folder stub with manifest and hypothesis, interpret left as a TODO. Human authors.

Most CVEs land in C. The pipeline's value at scale is classification and prioritization, not payload invention.
6.4 The extractor, honestly labeled

The extractor is a deterministic pipeline of signal-miners plus a bounded model step. It does not produce a complete technique; it produces a variant spec or a new-technique proposal.
text

# extract/signals.py  (pseudocode — do not use as a code sample)
extract(cve_record, poc_code_or_none) -> VariantSpec | NewTechniqueProposal | None:
    1. vuln_class = resolve_to_canonical(cwe_ids)
       if vuln_class is None: return None
    2. technique = existing_technique_for(vuln_class)
       if technique is None:
           return NewTechniqueProposal(vuln_class, cve_record)
    3. if poc_code is None:
           return VariantProposal(
               technique_name=technique,
               payload_fragment=guess_from_prose(description),
               interpolation_shape=None,
               confidence=0.2,
               needs_human_review=True,
           )
    4. payload_fragment, shape = mine_poc(poc_code)
    5. probe_condition = infer_http_shape(poc_code)
    6. oracle = infer_oracle(vuln_class, poc_code)
    7. if oracle is None:
           return None  # no independent measurement possible
    8. return VariantSpec(...)

The model's role is bounded: it drafts guess_from_prose and it can propose an interpolation_shape from the mined fragment. Every field it writes is validated against the deterministic miner's output. Anything the miner did not see is flagged needs_human_review=True.
6.5 The precondition/postcondition split — the error to avoid

A generated technique declares three things, and only one of them decides
whether it ever runs:

    preconditions (manifest) — declarative metadata: what the world would have
        to look like for the technique to be worth trying.

    surfaces() — THE GATE. Which surfaces the technique is actually offered,
        per run. This is the authority.

    postconditions — the claims the technique establishes on success. These
        are what downstream techniques chain on.

**The manifest's preconditions are not the gate, and writing a generator that
assumes they are produces an inert technique.** Three of the eight built
techniques gate differently from their manifest, on purpose: a loud technique
refuses to spend its probe budget on a surface whose declared purpose is an
ordinary search box. That was a deliberate Phase 2 decision, recorded in
`phase2_checklist.md`: "arm eligibility comes from each technique's own
`surfaces(seed)`, not from manifest preconditions … one authority."

So the gate and the manifest are two separate things to write, and they are
allowed to disagree. What is *not* allowed is for the gate to name something
no surface can carry — that yields zero arms, silently.

The eight built techniques, read from the code at `512cc9d`:
Technique	Manifest preconditions	`surfaces()` gate (authority)	Postcondition	Verifier
xss_reflected	public_param	public_param	script_execution	browser (execution)
xss_dom	public_param	public_param	script_execution	browser (execution)
xss_stored	server_stores_input	server_stores_input	script_execution	stored runner
oob_fetch	can_influence_remote_fetch	can_influence_remote_fetch	server_side_request_observed	collaborator (oob)
idor_differential	access_differs_by_session	access_differs_by_session	cross_account_readable	authorization (flipped)
sqli_blind_time	public_param	**delayed_response**	delayed_response	timing differential
command_injection	public_param	**delayed_response**	delayed_response	timing differential
generic_differential	public_param AND access_differs_by_session	**either** of the two	cross_behavior_readable	differential

**The eligibility matrix.** Rows are the claim a *surface* carries; a `1` is
the number of surfaces that technique is offered. This is the table that
decides whether anything fires at all, and it is worth keeping in front of
anyone designing a gate. Measured by running `surfaces()` for every
technique against a one-surface seed per row, at `512cc9d`:

```
surface claim              cmd_inj generic_dif idor_diff  oob_fetch  sqli_time  xss_dom  xss_refl  xss_stored
public_param                        0           1         0          0          0        1         1          0
can_influence_remote_fetch          0           0         0          1          0        0         0          0
delayed_response                    1           0         0          0          1        0         0          0
access_differs_by_session           0           1         1          0          0        0         0          0
server_stores_input                 0           0         0          0          0        0         0          1
script_execution                    0           0         0          0          0        0         0          0
```

Read the last row first: a surface carrying `script_execution` — which is
every XSS technique's *postcondition* — reaches **nothing**. Declaring a
postcondition as an input claim is the single most likely way to generate a
technique that never fires. What recon actually supplies is discussed in
§12.4.

Four things a generator must get right, each one observed in the table above:

1. **Two postcondition spellings are not kernel constants.**
   `server_side_request_observed` is defined locally in
   `techniques/oob_fetch/manifest.py`, and `cross_behavior_readable` is a bare
   string literal in `techniques/generic_differential/manifest.py`. Neither is
   in `kernel/technique.py`. That is legitimate — postconditions are an open
   vocabulary, and `validate()` only checks that the tuple is non-empty — but
   it means a generator cannot resolve them from the kernel alone. It has to
   read the technique folder, or invent a new one deliberately.

2. **The *precondition* vocabulary is closed at eight constants.**
   `kernel/technique.py`'s `CAPABILITIES` tuple is the whole set, and
   `techniques/generic_differential/eligibility.py` refuses to import if its
   derived gate contains anything outside it. A gate naming a non-constant is a
   bug the engine will catch at import; a postcondition naming one is not caught
   at all.

3. **`generic_differential`'s gate is an OR, its manifest reads as an AND.**
   `plan_table_capabilities()` returns
   `frozenset({CAP_PUBLIC_PARAM, CAP_ACCESS_DIFFERS_BY_SESSION})` and
   `surfaces()` admits a surface whose capability is *in* that set. Copying the
   manifest's shape would make the technique narrower than intended.

4. **`sqli_blind_time` gates on a value that is also its postcondition.**
   That is coherent — the operator declares "time depends on this parameter"
   and the two techniques compete to explain it — but it means the
   postcondition is not automatically a forbidden gate value. Earlier drafts of
   this document treated "don't gate on your postcondition" as absolute. It is
   not. What matters is that the *operator can supply* the claim.

Note on the README: its technique table previously mixed manifest
preconditions with `surfaces()` gates under one column headed "Fires on
claim", so it read as a transposition when it was really an unstated
ambiguity. It now carries both columns separately, and names `surfaces()` as
the authority.
7. Stage 4 — Generate

The generator does not write a folder per CVE. It writes:

    A variant spec (common case): a payload fragment plus an insertion instruction, targeted at an existing technique's probes.py.

    A new-technique proposal (rare): a folder stub with manifest.py and hypothesis.py filled in, probes.py and interpret.py marked TODO. Human authors.

7.1 Variant spec

A variant spec is a data structure, not a folder:
python

# generate/variant_spec.py
from dataclasses import dataclass

@dataclass
class VariantSpec:
    technique_name: str
    payload_fragment: str
    interpolation_shape: str | None
    probe_condition: dict
    source_cve: str
    oracle: str
    confidence: float
    needs_human_review: bool

The human reviewer (or a bounded generator) merges the fragment into the target technique's probes.py. This is a small, reviewable edit. It respects the acid test: adding a variant must never require editing anything outside the technique folder.
7.2 New-technique proposal

Only when the CVE's vuln_class has no existing technique and the CVE has a clear oracle. The folder stub looks like:
text

techniques/<vuln_class>/
├── __init__.py
├── manifest.py       # TechniqueManifest — filled in
├── hypothesis.py     # surfaces() + hypotheses() — filled in
├── probes.py         # TODO: human authors
└── interpret.py      # TODO: human authors

The manifest.py uses the real kernel signature. Two fields the earlier draft got wrong and that must be present:

    produces — the evidence classes the technique can produce. The registry rejects a manifest without it (validate() returns ['no evidence classes declared in produces']).

    postconditions — required; registry rejects a manifest without it. This is deliberate: a technique that cannot be chained would make a chain query silently return nothing.

NoiseProfile is described here, not constructed: cost is a read-only derived property, not a constructor argument. burstiness is a float in [0, 1]. Read kernel/manifest.py before writing this field.
7.3 Import paths

A technique folder's modules import the kernel with a three-dot relative import:
python

from ...kernel.manifest import TechniqueManifest

Not from kernel.manifest import. The earlier draft used the absolute form, which does not resolve from inside a technique folder.
7.4 The scale reality

The earlier draft generated f"{vuln_class}_{cve_id}" folders. Against the live graph (3,476 URLs, 35 parameters), the cost is:
Approach	Folders	Arms	Imports per run
Today	8	~280	8
5 CWEs (~11,400 CVEs)	11,400	~399,000	11,400
Full NVD (~230,000)	230,000	~8,050,000	230,000

registry.discover() imports every folder before a single probe is sent, and the driver has no per-technique budget. The one-folder-per-CVE design is off by five orders of magnitude. One folder per class, variants merged into probes.py.
8. Stage 5 — Validate

Before a variant or technique enters the codebase, it must pass:
8.1 Replay test

Run the technique's interpret() against a recorded observation set and verify it proposes the expected candidate. The observation set is captured from a fixture or a known-vulnerable target.
8.2 False-positive control

Run the technique against a clean target and verify it proposes nothing. A technique that proposes on a non-vulnerable surface is worse than useless.
8.3 Invariant tests

The engine's existing invariant tests enforce:

    No time., requests., or socket. imports in techniques/ (pure at the boundary)

    No module outside policy/ imports a transport

    No observation payload typed str (typed observations only)

A generated technique must pass all three. These are mechanical checks.
8.4 Registry validation

TechniqueRegistry.discover() must find it, and its manifest must pass discover(strict=True) (postconditions required, produces required, no unknown fields).
8.5 What validation cannot do

The validation loop presupposes a known-vulnerable target and a recorded observation set. This is the same fixture problem the benchmark work has already hit: validating a technique against a target you planted a bug in does not validate it against a target you didn't.

A generated technique that passes all four checks above is still not proven against a real target. That is the honest boundary. The technique is a candidate; only a live engagement on a target with unknown bugs is a real test. This is a limit of the entire approach, not a bug in the validation stage.
9. Stage 6 — Human review and register

The engine's Phase 3 contract says the model is advisory, never authoritative. The same rule applies to generated techniques.

Review checklist:

    Capability claim correctness — do preconditions and postconditions use the kernel's exact spellings? Is the surface's claimed precondition genuinely the thing the technique needs?

    Verifier independence — does the confirmation spec require a genuinely different evidence class?

    Payload safety — non-destructive, bounded, no DROP TABLE, no rm -rf, no destructive SQL.

    Target-agnosticism — no hardcoded paths, no vendor names, no benchmark case names. This is the abstraction step and it is the reviewer's job, not the pipeline's.

    Chaining — does postconditions match an existing or planned downstream preconditions? If not, the technique is a leaf.

Only after review does the variant land in probes.py, or the new folder land under techniques/.
10. The pipeline, end to end
text

┌──────────────────────────────────────────────────────────────┐
│  INGEST (verified, buildable now)                            │
│  fetch_cves_by_cwe("CWE-89") → cache/CWE-89.jsonl            │
│  ...                                                         │
└──────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  CLASSIFY (verified, buildable now)                          │
│  cwe_ids → resolve_to_canonical (cached) → vuln_class        │
│  annotate → classified.jsonl                                 │
└──────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  TRIAGE                                                      │
│  Tier A: PoC + shape + existing technique → VariantSpec      │
│  Tier B: prose + existing technique → VariantProposal        │
│  Tier C: prose only → retained as priority signal            │
│  Tier D: new class + clear oracle → NewTechniqueProposal     │
└──────────────────────────────────────────────────────────────┘
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
┌──────────────────────────┐  ┌──────────────────────────┐
│  VARIANT MERGE (common)  │  │  NEW TECHNIQUE (rare)    │
│  human adds fragment to  │  │  stub folder; human      │
│  techniques/<class>/     │  │  authors probes+interpret│
│  probes.py               │  │                          │
└──────────────────────────┘  └──────────────────────────┘
              │                           │
              └─────────────┬─────────────┘
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  VALIDATE (replay + FP control + invariants + registry)      │
└──────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  HUMAN REVIEW                                                │
│  claim correctness · verifier independence · payload safety  │
│  · target-agnosticism · chaining                             │
└──────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  REGISTER                                                    │
│  git add techniques/<folder>/ or probes.py edit              │
│  TechniqueRegistry.discover() → N techniques                 │
└──────────────────────────────────────────────────────────────┘

11. Mapping tables (reference)
CWE → vuln_class → manifest precondition → postcondition → verifier

The Precondition column is the **manifest's**, not the gate. The gate is
`surfaces()`, and for the two timing classes it is `delayed_response`
rather than the `public_param` below — see §6.5. Read the gate, not this
column, when deciding whether a technique can fire. For the `next` and
`planned` rows this column is a *recommendation* for what a new technique
for that class should gate on, not a description of existing code — and it
must satisfy the same test: a claim the operator can actually supply.
`generic_differential` has no row here because it is keyed on a plan table
rather than a CWE; its gate is `public_param` OR `access_differs_by_session`.

CWE	vuln_class	Manifest precondition	Postcondition	Verifier	Status
CWE-79	xss	public_param	script_execution	browser (execution)	built
CWE-89	sqli	public_param	delayed_response	timing differential	built
CWE-78	command-injection	public_param	delayed_response	timing differential	built
CWE-918	ssrf	can_influence_remote_fetch	server_side_request_observed	collaborator (oob)	built
CWE-639 / CWE-284	idor	access_differs_by_session	cross_account_readable	authorization (flipped)	built
CWE-22 / CWE-23	path-traversal	public_param	(to define)	reflection diff	next
CWE-611 / CWE-776	xxe	can_influence_remote_fetch	(to define)	collaborator (oob)	next
CWE-1336 / CWE-94	ssti	public_param	script_execution	browser (execution)	planned
CWE-601	open-redirect	public_param	(to define)	30x status	planned
CWE-943	nosqli	public_param	(to define)	response diff	planned
CWE-693 / CWE-1021	missing-headers	(passive)	(to define)	response hygiene	planned

The precondition for a new class must be a claim the surface can plausibly carry before the technique runs. If no such claim exists, a new kernel constant may be needed — a deliberate, infrequent change.
Oracle → verification need
Oracle	verification_needs	Independent measurement
Reflection context	execution	Browser CDP events
Timing separation	differential	Fresh timing populations, flipped order
Collaborator hit	oob	Interaction record keyed by probe ID
Status-code differential	differential	Flipped session order
Stored reflection	execution	Re-inject + browser execution

The hard rule: if no oracle supports an independent measurement, the technique cannot produce a finding. It can only produce a lead. This is the sentence from §7 of the earlier draft that is the strongest thing in the document. A CVE tells you what is broken; it essentially never tells you how you would independently confirm it — and that second thing is the entire barrier to generating a technique.
12. Operational notes
12.1 Rate limits and caching

The NVD API is the bottleneck. Cache every fetched CVE record in JSONL; re-fetch on a schedule or on KEV/EPSS signal. With a key, 50 requests / 30 seconds is workable for bulk ingestion.
12.2 PoC sourcing

Exploit-DB and GitHub PoC repositories are the richest source of payload fragments. Not every CVE has a PoC; those without are not Tier A or B material. Tag references with "Exploit" in the NVD record are the cheapest signal.
12.3 The 80/20

Most CVEs do not need a new technique. They need a new payload variant inside an existing technique. The pipeline's first question should always be: does this CVE fit an existing precondition and verifier? If yes, it is a small addition to probes.py. If no, it is a new class — a deliberate kernel change.
12.4 What this pipeline does not do

It does not advance the novelty goal. A CVE-derived variant finds a known bug on a declared surface. It does not reach L3/L4 or produce a P1–P4 claim. The abductive loop is the other pipeline — complementary, separable, out of scope here.

**It also does not fix the binding constraint, which sits upstream in recon.**

A generated technique is bottlenecked by what surfaces *exist*, not by how
many techniques were generated. `seed/from_graph.py` derives every surface
from an observed parameter and assigns it **one of two** capabilities
(`from_graph.py:178`):

* `public_param` — the default, for every parameter;
* `can_influence_remote_fetch` — chosen instead when the parameter *name* is
  URL-shaped (`url`, `uri`, `href`, `src`, `redirect`, … in
  `REMOTE_FETCH_PARAM_HINTS`) and `infer_remote_fetch` is on. That is a
  **name-based claim, not a measured one**.

So two of the eight gates are reachable from a graph-seeded run, and one of
those two is a guess. Against the eligibility matrix in §6.5:

| Gate a surface must carry | Reachable from the graph? |
| --- | --- |
| `public_param` | yes — every observed parameter |
| `can_influence_remote_fetch` | only for a URL-shaped parameter *name* |
| `delayed_response` | no — recon collects no timing baseline |
| `server_stores_input` | no — no submit-then-read-back |
| `access_differs_by_session` | no — one identity only |

Five of the eight techniques therefore produce **zero arms from a
graph-seeded run** regardless of how many techniques exist. `--surface
...;capability=` is how an operator reaches them today, by hand.

The practical consequence for this pipeline: generating a well-formed
`command_injection` or `sqli_blind_time` variant changes nothing, because
both gate on `delayed_response` and nothing supplies it. The scarce resource
is measured capability claims on the recon side, not generation quality, and
building this before the measured-claim collector lands would be optimising
the wrong stage.

This is a boundary of what the pipeline can deliver, not a defect in it,
and not something an edit to this document can fix. The fixes are the
measured-claim collector on the recon side, or an operator declaring the
claim by hand via `--surface ...;capability=`. The engine README §7 records
the same five missing input claims.
12.5 What is verified and what is not
Claim	Verified against
NVD rate limits, resultsPerPage max 2000, cweId filter	live API
MITRE CWE API response shape	live API
Real kernel technique signatures (preconditions/postconditions pairing)	kernel source
Folder-per-class vs folder-per-CVE cost	live graph + registry behavior
PoC availability ~4%	Householder et al., USENIX Security 2020
SOTA ~17% for prose-to-exploit	CyberGym, ExploitGym

Everything else in this document — the extractor's structure, the triage tiers, the variant-spec shape — is a proposal and should be treated as one until built and tested against the checks in §8.
13. Build plan
Priority	Action	Effort	Confidence
1	Request NVD API key	1 day	certain
2	ingest/fetch_nvd.py — verified against live API	1 day	high
3	classify/cwe_resolver.py — static map + corrected API walk	1 day	high
4	extract/ — triage classifier + PoC miner for Tier A only	3–5 days	medium
5	generate/variant_spec.py — data structure, no folder writing	1 day	high
6	validate/ — replay + FP control + invariants	2 days	high
7	Run the pipeline for CWE-22 (path traversal, Tier A only)	2 days	medium
8	Human review, merge into a new path_traversal technique	3 days	human task
9	Repeat for CWE-611 (XXE) and CWE-1336 (SSTI)	1 week	medium

Stage 3 (extraction) is the long pole. Do not commit to weeks of work there until Tier A has been tested on a handful of CVEs with clean PoCs. The pipeline's value at scale is classification and prioritization; the payload generation is a bounded, human-reviewed addition on top of that. If the triage tiers fill mostly with Tier C, the pipeline is still useful — as a reader of the CVE corpus, not as a writer of techniques.