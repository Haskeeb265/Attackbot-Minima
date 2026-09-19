"""The sibling-artifact reader: where candidate bucket names come from.

The sibling pipelines already carry bucket claims nobody interprets — a CNAME
pointing at ``<name>.s3.amazonaws.com`` *is* a bucket claim the target's own
DNS made; a JS bundle hosted on ``<name>.storage.googleapis.com`` says the same
thing about GCS.  This module reads those artifacts and turns every match into
a :class:`~.normalize.Candidate`, then derives extra names from the target's
brand tokens.  Zero network.

Reading discipline — the one every sibling enforces (``graph_normalize``'s
wording): **missing is a state, not an error.**  A sibling that has not run yet
means fewer candidates, and the report says exactly which artifacts were
absent.  Empty is not missing, and a corrupt line is counted per line by the
shared reader.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from pathlib import Path

from service.recon_pipeline.platform.common.io import read_jsonl, read_lines, read_text

from . import providers, settings
from .normalize import Candidate, canonicalize_name, validate_name

log = logging.getLogger("cloud_resource.seeds")

#: Origins a candidate can carry, in the vocabulary the report uses.
ORIGIN_CNAME = "cname"
ORIGIN_URL = "url"
ORIGIN_JS = "javascript"
ORIGIN_ENDPOINT = "endpoint"
ORIGIN_DERIVED = "derived"
ORIGIN_EXPLICIT = "explicit"

#: The sibling artifacts this stage reads (paths relative to each pipeline root).
RECORDS_REL = "active/output/records.jsonl"
LIVE_HOSTS_REL = "output/live_hosts.txt"
URLS_JSONL_REL = "output/urls.jsonl"
URLS_TXT_REL = "passive/output/urls.txt"
JS_REL = "output/javascript.txt"
ENDPOINTS_REL = "output/endpoints.txt"

#: Host-label words that appear in *every* organisation's host list.  A bucket
#: name derived from one of these (``mail-app``, ``cdn-static``) is a name
#: anyone on the internet could own — S3/GCS names are globally namespaced —
#: so candidates carrying only generic tokens get a weak ownership hint
#: (DESIGN.md §9, the live-run lesson).
GENERIC_TOKENS = frozenset({
    "mail", "www", "app", "web", "cdn", "static", "assets", "media", "files",
    "data", "backup", "uploads", "docs", "dev", "staging", "prod", "api",
    "hr", "ci", "db", "logs", "config", "internal", "public", "private",
    "site", "downloads", "releases", "archive", "deploy", "deployments",
    "artifacts", "invoices", "payments", "secrets", "autodiscover",
    "cpcalendars", "cpcontacts", "webdisk", "webmail",
})


def token_is_distinctive(token: str) -> bool:
    """True when *token* plausibly belongs to *this* target's namespace.

    ``qbsco`` and ``ocac`` are distinctive; ``mail`` is a word every company's
    DNS has.  The rule is deliberately dumb and explainable: a token is
    generic exactly when it is on the stoplist.
    """
    return token not in GENERIC_TOKENS


#: The name shapes derivation proposes for the target's brand tokens.  Small
#: on purpose (see ``settings.MAX_DERIVED`` and DESIGN.md §5): derivation
#: exists to suggest plausible names, not to brute-force the provider.
NAME_SHAPES: tuple[str, ...] = (
    "{brand}",
    "{brand}-assets",
    "{brand}-static",
    "{brand}-backups",
    "{brand}-backup",
    "{brand}-dev",
    "{brand}-staging",
    "{brand}-prod",
    "{brand}-media",
    "{brand}-data",
    "{brand}-logs",
    "{brand}-uploads",
    "{brand}-files",
    "{brand}-public",
    "{brand}-private",
    "{brand}-cdn",
    "{brand}cdn",
    "{brand}app",
    "{brand}-app",
    "{brand}-web",
    "{brand}-site",
    "{brand}-config",
    "{brand}-docs",
    "{brand}-downloads",
    "{brand}-releases",
    "{brand}-archive",
    "{brand}-db",
    "{brand}-secrets",
    "{brand}-deploy",
    "{brand}-deployments",
    "{brand}-ci",
    "{brand}-artifacts",
    "{brand}-invoices",
    "{brand}-payments",
    "{brand}-hr",
    "{brand}-internal",
)


def _add(
    rows: dict[tuple[str, str], Candidate],
    refusals: list[tuple[str, str, str]],
    name: str,
    provider: str,
    origin: str,
    source: str,
    evidence: str,
    *,
    distinctive: bool = True,
) -> None:
    """Fold one claim into *rows*, or record a refusal with its reason."""
    canonical = canonicalize_name(name)
    if not canonical:
        return
    reason = validate_name(canonical, provider)
    if reason:
        refusals.append((canonical, provider, reason))
        return
    candidate = Candidate(
        name=canonical,
        provider=provider,
        origins={origin},
        sources={source},
        evidence=[evidence],
        distinctive=distinctive,
    )
    existing = rows.get(candidate.key)
    if existing is None:
        rows[candidate.key] = candidate
    else:
        existing.merge(candidate)
        if distinctive:
            existing.distinctive = True


def _text_lines(path: Path) -> list[str]:
    """A text artifact as lines, so the state row's ``rows`` counts lines."""
    return read_text(path).splitlines()


def _note_state(
    states: list[dict],
    counts: dict[str, int],
    stream: str,
    path: Path,
    reader: Callable[[Path], list],
) -> bool:
    """Read one artifact if present; record its state either way."""
    if path.is_file():
        data = reader(path)
        states.append(
            {"artifact": stream, "path": str(path), "state": "read", "rows": len(data)}
        )
        return True
    states.append({"artifact": stream, "path": str(path), "state": "missing", "rows": 0})
    counts["artifacts_missing"] += 1
    return False


def _claims_from_text(
    rows: dict[tuple[str, str], Candidate],
    refusals: list[tuple[str, str, str]],
    text: str,
    origin: str,
    source: str,
) -> int:
    """Every provider claim inside a text artifact; returns the claim count."""
    claims = 0
    for line in text.splitlines():
        for provider, name in providers.match_provider(line):
            claims += 1
            _add(rows, refusals, name, provider, origin, source, line.strip())
    return claims


def brand_tokens(apex: str, live_hosts: list[str]) -> list[str]:
    """The target's brand tokens, most specific first.

    ``mail.qbsco.net`` under apex ``qbsco.net`` yields ``qbsco`` — and, from the
    live-host set, second-level tokens like ``qbsco-mail`` that a bucket might
    carry.  Tokens shorter than 3 characters are dropped (they cannot be a
    legal bucket name anywhere).
    """
    tokens: list[str] = []
    labels = [label for label in apex.split(".") if label and label != "www"]
    if labels:
        root = "-".join(labels[:-1]) if len(labels) > 1 else labels[0]
        tokens.append(root)
    for host in live_hosts:
        host = canonicalize_name(host)
        suffix = f".{apex}"
        local = host[: -len(suffix)] if host.endswith(suffix) else ""
        if not local or local == "www":
            continue
        for part in local.split("-"):
            if part and part not in labels and len(part) >= 3 and part not in tokens:
                tokens.append(part)
    return [token for token in tokens if len(token) >= 3]


def derive_names(
    tokens: list[str], provider: str, *, max_derived: int
) -> list[tuple[str, bool]]:
    """Brand tokens × name shapes, validated for *provider*, capped.

    Returns ``(name, distinctive)`` pairs: distinctive tokens are the ones the
    ownership hint will call strong.  Azure's 24-character account-name
    ceiling eats long shapes; those are dropped here — derivation skips shapes
    that cannot exist, the same rule the harvest applies.
    """
    names: list[tuple[str, bool]] = []
    for token in tokens:
        distinctive = token_is_distinctive(token)
        for shape in NAME_SHAPES:
            candidate = shape.format(brand=token)
            if validate_name(candidate, provider) is None:
                names.append((candidate, distinctive))
                if max_derived and len(names) >= max_derived:
                    return names
    return names


def harvest(
    target: str,
    *,
    output_dir: Path | str | None = None,
    names_dir: Path | str | None = None,
    urls_dir: Path | str | None = None,
    explicit_names: Iterable[str] = (),
    use_siblings: bool = True,
    max_derived: int | None = None,
) -> tuple[list[Candidate], dict[str, int], list[dict]]:
    """Read sibling artifacts, derive candidates, write ``candidates.jsonl``.

    Returns ``(candidates, counts, artifact_states)`` — the merged candidate
    set, the report counts, and one state row per artifact consulted.
    """
    output_dir = Path(output_dir) if output_dir else settings.PASSIVE_OUTPUT_DIR
    names_root = Path(names_dir) if names_dir else settings.NAMES_DIR
    urls_root = Path(urls_dir) if urls_dir else settings.URLS_DIR
    max_derived = settings.MAX_DERIVED if max_derived is None else max_derived

    apex = canonicalize_name(target)
    if not apex or "." not in apex:
        raise ValueError(f"target {target!r} is not a valid domain (expected e.g. 'example.com')")

    rows: dict[tuple[str, str], Candidate] = {}
    refusals: list[tuple[str, str, str]] = []
    counts: dict[str, int] = {
        "cname_claims": 0,
        "url_claims": 0,
        "js_claims": 0,
        "endpoint_claims": 0,
        "derived_candidates": 0,
        "explicit_candidates": 0,
        "refused": 0,
        "artifacts_missing": 0,
    }
    states: list[dict] = []

    # ------------------------------------------------------------------ #
    # 1. CNAME claims — the names stage's records.jsonl
    # ------------------------------------------------------------------ #
    if use_siblings:
        records_path = names_root / RECORDS_REL
        if _note_state(states, counts, "records", records_path, read_jsonl):
            for row in read_jsonl(records_path):
                for value in row.get("cname") or ():
                    if isinstance(value, str):
                        for provider, name in providers.match_provider(value):
                            counts["cname_claims"] += 1
                            _add(rows, refusals, name, provider, ORIGIN_CNAME, "records.jsonl", value)

        # ------------------------------------------------------------------ #
        # 2. URL claims — the URL pipeline's union (jsonl preferred, txt fallback)
        # ------------------------------------------------------------------ #
        urls_jsonl = urls_root / URLS_JSONL_REL
        if urls_jsonl.is_file():
            _note_state(states, counts, "urls", urls_jsonl, read_jsonl)
            for row in read_jsonl(urls_jsonl):
                for field in ("url", "host"):
                    value = row.get(field)
                    if isinstance(value, str):
                        for provider, name in providers.match_provider(value):
                            counts["url_claims"] += 1
                            _add(rows, refusals, name, provider, ORIGIN_URL, "urls.jsonl", value)
        else:
            urls_txt = urls_root / URLS_TXT_REL
            if _note_state(states, counts, "urls-txt", urls_txt, _text_lines):
                counts["url_claims"] += _claims_from_text(
                    rows, refusals, read_text(urls_txt), ORIGIN_URL, "urls.txt"
                )

        # ------------------------------------------------------------------ #
        # 3. JavaScript bundle URLs
        # ------------------------------------------------------------------ #
        js_path = urls_root / JS_REL
        if _note_state(states, counts, "javascript", js_path, _text_lines):
            counts["js_claims"] += _claims_from_text(
                rows, refusals, read_text(js_path), ORIGIN_JS, "javascript.txt"
            )

        # ------------------------------------------------------------------ #
        # 4. Endpoint list (same shape as JS)
        # ------------------------------------------------------------------ #
        endpoints_path = urls_root / ENDPOINTS_REL
        if _note_state(states, counts, "endpoints", endpoints_path, _text_lines):
            counts["endpoint_claims"] += _claims_from_text(
                rows, refusals, read_text(endpoints_path), ORIGIN_ENDPOINT, "endpoints.txt"
            )

        # ------------------------------------------------------------------ #
        # 5. Brand tokens — from the names stage's live hosts
        # ------------------------------------------------------------------ #
        live_hosts_path = names_root / LIVE_HOSTS_REL
        live_hosts: list[str] = []
        if _note_state(states, counts, "live-hosts", live_hosts_path, read_lines):
            live_hosts = read_lines(live_hosts_path)
        tokens = brand_tokens(apex, live_hosts)
    else:
        # --no-sibling-input: no claims, no derivation, no brand tokens —
        # explicit --name seeds only (the flag's documented contract).
        tokens = []
        states.append(
            {"artifact": "siblings", "path": "", "state": "skipped (--no-sibling-input)", "rows": 0}
        )
    enabled = [
        provider
        for provider in providers.ALL_PROVIDERS
        if provider == providers.PROVIDER_S3 and settings.S3_ENABLED
        or provider == providers.PROVIDER_AZURE and settings.AZURE_ENABLED
        or provider == providers.PROVIDER_GCS and settings.GCS_ENABLED
    ]
    for provider in enabled:
        for name, distinctive in derive_names(tokens, provider, max_derived=max_derived):
            before = len(rows)
            _add(
                rows, refusals, name, provider, ORIGIN_DERIVED, "brand-shapes",
                token_source(tokens), distinctive=distinctive,
            )
            if len(rows) > before:
                counts["derived_candidates"] += 1

    # ------------------------------------------------------------------ #
    # 6. Explicit operator names — probed against every enabled provider
    # ------------------------------------------------------------------ #
    for explicit in explicit_names:
        for provider in enabled:
            before = len(rows)
            _add(
                rows, refusals, explicit, provider, ORIGIN_EXPLICIT, "cli", str(explicit)
            )
            if len(rows) > before:
                counts["explicit_candidates"] += 1

    counts["refused"] = len(refusals)

    candidates = sorted(rows.values(), key=lambda c: c.key)
    output_dir.mkdir(parents=True, exist_ok=True)
    candidates_path = output_dir / "candidates.jsonl"
    _write_jsonl(candidates_path, (candidate.to_dict() for candidate in candidates))
    _write_lines(output_dir / "candidates.txt", (c.name for c in candidates))
    report = {
        "target": apex,
        "counts": counts,
        "refusals": [
            {"name": name, "provider": provider, "reason": reason}
            for name, provider, reason in refusals
        ],
        "artifacts": states,
    }
    _write_json(output_dir / "report.json", report)
    log.info(
        "harvest: %d candidate(s) (%d CNAME, %d URL, %d JS, %d endpoint, %d derived, "
        "%d explicit), %d refused, %d artifact(s) missing",
        len(candidates),
        counts["cname_claims"],
        counts["url_claims"],
        counts["js_claims"],
        counts["endpoint_claims"],
        counts["derived_candidates"],
        counts["explicit_candidates"],
        counts["refused"],
        counts["artifacts_missing"],
    )
    return candidates, counts, states


def token_source(tokens: list[str]) -> str:
    """The provenance string for derived names (the token list, for the report)."""
    return f"brand tokens: {', '.join(tokens[:8])}"


def _write_jsonl(path: Path, records) -> None:  # noqa: ANN001
    import json

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(
        "".join(json.dumps(dict(record), sort_keys=False) + "\n" for record in records),
        encoding="utf-8",
        newline="\n",
    )
    tmp.replace(path)


def _write_lines(path: Path, lines) -> None:  # noqa: ANN001
    path.parent.mkdir(parents=True, exist_ok=True)
    unique = sorted({line for line in lines if line})
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text("".join(f"{line}\n" for line in unique), encoding="utf-8", newline="\n")
    tmp.replace(path)


def _write_json(path: Path, payload) -> None:  # noqa: ANN001
    import json

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(
        json.dumps(payload, indent=2, sort_keys=False), encoding="utf-8", newline="\n"
    )
    tmp.replace(path)
