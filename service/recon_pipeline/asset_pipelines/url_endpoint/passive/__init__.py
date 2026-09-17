"""Passive URL sources for the ``url_endpoint`` pipeline.

Every source here harvests URLs from a **third party's** dataset — the Wayback
Machine, Common Crawl, urlscan.io, or ``gau`` fanning out across all of them.
None of them sends a request to the target, which is what makes this stage
passive in the same sense the names stage's crt.sh source is.
"""
