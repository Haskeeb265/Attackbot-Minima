# =============================================================================
# subdomain_domain_wildcards_image
# -----------------------------------------------------------------------------
# All-in-one subdomain / domain / wildcard recon tool image.
#
# Bundled tools (every one of them driven by a stage module - see README.md):
#   Passive      : amass (v4.2.0 — streams graph relations), assetfinder, chaos, findomain, subfinder
#   Active       : amass, dnsx, massdns, puredns, shuffledns, dig (dnsutils)
#   Permutation  : dnsgen
#   Bridge       : httpx (opt-in HTTP probing of resolved hosts - see
#                  active/README.md; not used by the DNS-only default path)
#
# amass is pinned to v4.2.0 on purpose: amass v5 (the 2024 rewrite) removed
# the stdout "graph relations" output and persists results to a SQLite
# asset.db instead. v4 streams one relation per line to stdout, e.g.:
#   qbsco.net (FQDN) --> a_record --> 104.21.81.2 (IPAddress)
#
# Build:
#   docker build -t subdomain_domain_wildcards_image \
#     service/recon_pipeline/asset_pipelines/subdomain_domain_wildcards/
#
# Run (see commands.txt for per-tool examples):
#   docker run --rm subdomain_domain_wildcards_image subfinder -d example.com -silent
# =============================================================================

# ----------------------------- Stage 1: Go tools ---------------------------
FROM golang:1.26-bookworm AS go-builder

ENV GO111MODULE=on \
    CGO_ENABLED=0

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    && go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest \
    && go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/tomnomnom/assetfinder@latest \
    && go install github.com/d3mondev/puredns/v2@latest

# ------------------------- Stage 2: massdns (C) ----------------------------
FROM debian:bookworm-slim AS massdns-builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        build-essential \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns \
    && make -C /tmp/massdns \
    && install -m 0755 /tmp/massdns/bin/massdns /usr/local/bin/massdns \
    && mkdir -p /usr/local/share/massdns \
    && cp /tmp/massdns/lists/resolvers.txt /usr/local/share/massdns/ \
    && rm -rf /tmp/massdns

# ----------------------------- Stage 3: Runtime -----------------------------
FROM python:3.12-slim

# Base packages (curl/unzip for findomain; dnsutils for DNS debugging)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        wget \
        unzip \
        ca-certificates \
        dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Go binaries (subfinder, dnsx, shuffledns, chaos, httpx, assetfinder, puredns)
COPY --from=go-builder /go/bin/ /usr/local/bin/

# massdns binary + bundled resolver lists (used by shuffledns/puredns too)
COPY --from=massdns-builder /usr/local/bin/massdns /usr/local/bin/massdns
COPY --from=massdns-builder /usr/local/share/massdns/ /usr/local/share/massdns/

# findomain — precompiled Rust binary from GitHub Releases
RUN wget -q https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip \
    && unzip -o findomain-linux.zip \
    && chmod +x findomain \
    && mv findomain /usr/local/bin/findomain \
    && rm -f findomain-linux.zip

# amass — v4.2.0 precompiled Go binary from GitHub Releases (pinned: v5 dropped
# the stdout graph-relations output; v4 streams it live as it is found)
RUN wget -q https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip \
    && unzip -o amass_Linux_amd64.zip \
    && chmod +x amass_Linux_amd64/amass \
    && mv amass_Linux_amd64/amass /usr/local/bin/amass \
    && rm -rf amass_Linux_amd64 amass_Linux_amd64.zip

# dnsgen — subdomain permutation generator (Python)
RUN pip install --no-cache-dir dnsgen

# -----------------------------------------------------------------------------
# Build-time smoke test — fail fast if any tool is missing or broken
# -----------------------------------------------------------------------------
RUN for tool in amass subfinder dnsx shuffledns chaos httpx assetfinder puredns \
         massdns findomain dnsgen; do \
        command -v "$tool" > /dev/null || { echo "MISSING: $tool"; exit 1; }; \
    done \
    && echo example.com | dnsgen - > /dev/null \
    && amass -version 2>&1 | grep -qi 'v4\.' \
    && massdns --help 2>&1 | grep -qi 'resolvers' \
    && echo "All tools installed OK (amass = $(amass -version 2>&1 | head -1))"

WORKDIR /workspace
CMD ["/bin/bash"]
