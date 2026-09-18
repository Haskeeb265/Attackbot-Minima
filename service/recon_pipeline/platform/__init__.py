"""The ASM platform layer: services the asset pipelines consume.

Layout (each subpackage is independently importable and testable):

- :mod:`.common`      — shared primitives: host/IP canonicalization, env parsing,
                        deterministic IO, the Docker tool runner, HTTP helpers
- :mod:`.scoring`     — S2: the pure scoring engine (weights/penalties/audit)
- :mod:`.scope`       — S15: scope state on every candidate, §5.4 gate
- :mod:`.graph`       — Neo4j schema + CRUD + S4 ingestion + asset writers
- :mod:`.cache`       — S8: Redis hot cache (graceful degrade)
- :mod:`.queueing`    — S9: Redis Streams topology, workers, DLQ
- :mod:`.dispatch`    — S10: active dispatcher, rate limits, recursion gate
- :mod:`.lifecycle`   — S11: re-scoring, pruning, differential monitoring
- :mod:`.enrich`      — S13: LLM classification (key-gated, advisory)
- :mod:`.observability` — S14: run registry, metrics, DLQ ops surface
- :mod:`.stealth`     — identity/pacing/detection/quarantine/DNS budget

Everything here is asset-agnostic.  Asset logic lives in
``service/recon_pipeline/pipelines/<name>/`` folders, which consume this layer
through the :mod:`.contract`.
"""
