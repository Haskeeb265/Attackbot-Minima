"""``asn_cidr`` — the network-ownership asset pipeline (ASNs and CIDRs).

The names pipeline answers *what hosts exist* and the ports pipeline answers
*what is listening*.  Neither asks the question that widens a target's footprint
beyond what DNS happens to resolve today: **which networks does the organisation
own or announce, and what is inside them that DNS never pointed at?**

Two asset classes, one pipeline, and a hard rule that keeps them apart:

* an **ASN** is an announcement claim — an AS *announces* which prefixes reach
  its addresses.  Announcements change with routing, not with ownership.
* a **CIDR** is an allocation fact — a registry (via RDAP) says an organisation
  is responsible for a range.  That is the closest thing to ground truth the
  public internet offers, and it is the only kind of network claim the sibling
  ports stage treats as scan-authorising input (its ``seed_builder``).

The pipeline is **keyless by default and never scans**.  Its job is discovery
and emission: it hands the ports stage a CIDR file in the exact shape that
stage's declared-scope input takes, and marks every network it found as
``discovered`` so the ports stage's own scope gate (declared vs. advisory,
§5.4 of the design) decides what may be touched.  Nothing here sends a packet
to any address it discovered.
"""
