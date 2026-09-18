# =============================================================================
# port_service_host_image
# -----------------------------------------------------------------------------
# All-in-one ports / services / hosts tool image.
#
# Bundled tools (every one of them driven by a stage module - see README.md):
#   Active   : naabu (port scan), nmap (service identification), httpx (CDN 80/443
#              probe), dnsx (reverse DNS + address-gap resolution)
#
# Why one image instead of the upstream image per tool (the passive stage's
# model): every tool here is driven through the same registry and the same
# mounted /work volume, so pulling four images would mean four different
# filesystem layouts and four different working directories to reason about.
# The stage checks the image exists *before* doing any work and aborts with the
# exact build command, so a missing image is a clear message rather than a
# confusing tool error halfway through a run.
#
# Build:
#   docker build -t port_service_host_image \
#     service/recon_pipeline/pipelines/port_service_host/
#
# Run (see commands.txt for per-tool examples):
#   docker run --rm port_service_host_image naabu -host 1.1.1.1 -p 443 -s c
#
# Capabilities: naabu's CONNECT scan needs nothing; its SYN scan needs NET_RAW.
# Standard Docker grants NET_RAW by default, but a hardened runtime may not, so
# the stage passes --cap-add=NET_RAW explicitly for SYN and falls back to
# CONNECT if the kernel refuses (see active/naabu.py).
#
# Note on naabu: the upstream image ships a musl-linked binary with no libpcap,
# i.e. naabu v2 is pure Go for raw sockets. That is why this builds with
# CGO_ENABLED=0 like its sibling stage, and why no libpcap package is installed
# anywhere here.
# =============================================================================

# ----------------------------- Stage 1: Go tools ---------------------------
FROM golang:1.26-bookworm AS go-builder

ENV GO111MODULE=on \
    CGO_ENABLED=0

RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# ----------------------------- Stage 2: Runtime -----------------------------
FROM python:3.12-slim

# nmap is the only tool that is not a Go binary. `ca-certificates` is required by
# the HTTP tools; `dnsutils` is kept for hand-debugging a resolver by hand inside
# the container (and is what the sibling stage uses for its AXFR attempts).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        ca-certificates \
        dnsutils \
    && rm -rf /var/lib/apt/lists/* \
    && nmap --version | head -1

# Go binaries (naabu, httpx, dnsx)
COPY --from=go-builder /go/bin/ /usr/local/bin/

# -----------------------------------------------------------------------------
# Build-time smoke test — fail fast if any tool is missing or broken
#
# The naabu check is a real (loopback) CONNECT scan rather than `-version`:
# a binary that runs but cannot open a socket would pass a version check and
# fail on the first scan, which is exactly the failure this step exists to
# catch before an operator does.
# -----------------------------------------------------------------------------
RUN for tool in naabu nmap httpx dnsx; do \
        command -v "$tool" > /dev/null || { echo "MISSING: $tool"; exit 1; }; \
    done \
    && naabu -host 127.0.0.1 -p 1 -s c -silent -duc -nc -Pn > /dev/null \
    && dnsx -version > /dev/null \
    && httpx -version > /dev/null \
    && nmap --version > /dev/null \
    && echo "All tools installed OK (nmap $(nmap --version | head -1))"

WORKDIR /workspace
CMD ["/bin/bash"]
