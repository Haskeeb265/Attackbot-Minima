"""``graph_normalize`` — every pipeline's artifacts, normalised into one model.

The four asset pipelines each answer their own question in their own vocabulary:
the names stage speaks hostnames and DNS records, the ports stage speaks
addresses and ports, the URL stage speaks URLs and parameters, the network stage
speaks ASNs and CIDRs.  Nothing in the tree states what those facts have to do
with *each other*.

This pipeline is that statement.  It reads the sibling artifacts (files only —
no imports of their code, no re-running them) and normalises every row into a
single **node + edge model** with three properties that make it worth having:

* **One vocabulary.**  A hostname is a ``domain`` node with one canonical
  identity no matter which pipeline mentioned it, so ``www.example.com`` seen by
  passive OSINT, by an active DNS resolution and by a historical URL is *one*
  node carrying three pieces of evidence — not three findings.
* **Context, not just values.**  Every node and edge carries its provenance
  (which pipeline, which artifact, which source strings), the trust class of the
  claim (``observed`` by us, ``discovered`` from a third party, ``declared`` by
  the operator, ``inferred`` by arithmetic), and — when a scope engine is
  supplied — the platform's scope verdict for it.  A bare list of hosts cannot
  answer "who says so, and may we touch it"; this can.
* **A shape a graph can take.**  Nodes and edges are emitted as JSONL with
  stable ids and a separate mapping file for labels and relationship types.

**This pipeline deliberately does not touch the graph database.**  The
pre-run schema guess was removed on 2026-09-19 (it predated any observed
recon output); the replacement schema is to be designed *from* this
pipeline's artifacts — ``graph_state.json`` is the observed-reality anchor
that discussion starts from.  ``emit`` writes files; once the schema
exists, the platform's ``GraphSink`` is the seam it writes through, and the
only file that has to change then is :mod:`~.vocabulary` — the mapping from
neutral kinds to whatever the new schema labels things.
"""

from __future__ import annotations
