"""``url_endpoint`` — the URLs / endpoints / parameters asset pipeline.

The third built asset pipeline (after the names pipeline
``subdomain_domain_wildcards`` and the ports/services pipeline
``port_service_host``).  Where those answer "what names exist" and "what is
listening", this one answers **"what did the target expose over HTTP, ever"** —
the historical URL surface that outlives the pages it belonged to.

It exists because the sibling passive stage already harvests archived URLs from
the Wayback CDX API and then *throws the paths away*, keeping only hostnames
(``passive/wayback.py`` extracts ``legacy-internal.example.com`` from
``https://legacy-internal.example.com/admin`` and discards ``/admin``).  A
forgotten API route, an old backup path or a javascript bundle is exactly the
kind of asset that never appears in a DNS or port scan.

See ``README.md`` for the stages, outputs and measured behaviour.
"""
