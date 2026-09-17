# =============================================================================
# url_endpoint_image
# -----------------------------------------------------------------------------
# All-in-one historical-URL tool image for the urls / endpoints / parameters
# asset pipeline.
#
# Bundled tools (each driven by a stage module - see README.md):
#   Passive : gau  (Wayback + Common Crawl + AlienVault OTX + urlscan in one pass)
#
# Why an image at all, when three of the four sources are keyless Python?
# Because gau is the only source that reaches AlienVault OTX, and because it is
# an *independent* implementation of the same four datasets - agreement between
# it and a native source is genuine corroboration rather than a tautology (the
# same argument the names stage makes for running seven overlapping CT sources).
#
# Build:
#   docker build -t url_endpoint_image \
#     service/recon_pipeline/asset_pipelines/url_endpoint/
#
# Run (see commands.txt for per-tool examples):
#   docker run --rm url_endpoint_image gau --subs example.com
# =============================================================================

# ----------------------------- Stage 1: Go tools ---------------------------
FROM golang:1.26-bookworm AS go-builder

ENV GO111MODULE=on \
    CGO_ENABLED=0

RUN go install -v github.com/lc/gau/v2/cmd/gau@latest

# ----------------------------- Stage 2: Runtime -----------------------------
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=go-builder /go/bin/gau /usr/local/bin/gau

# -----------------------------------------------------------------------------
# Build-time smoke test - fail fast if the tool is missing or broken
# -----------------------------------------------------------------------------
RUN command -v gau > /dev/null \
    && gau --version > /dev/null 2>&1 \
    && echo "All tools installed OK (gau = $(gau --version 2>&1 | head -1))"

WORKDIR /work
CMD ["/bin/bash"]
