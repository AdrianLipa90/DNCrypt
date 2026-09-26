# DNCrypt × NOEMA Relational Phase Flow V3 Challenge

Status: **IMPLEMENTATION CONFORMANCE — VALIDATION NOT YET RUN**.

V2 used the absolute phase of one prime/twin/dyadic frame and did not beat the matched random-locus null. V3 changes the mathematical object instead of tuning the V2 score.

For each arithmetic stream independently, V3 consumes three ordered samples `(t-2,t-1,t)`. For every shell `Λ in {6,30,210,2310}` and observable `o`, it computes

`d_prev = wrap(phi_{t-1} - phi_{t-2})`,

`d_now = wrap(phi_t - phi_{t-1})`,

`kappa = wrap(d_now - d_prev)`.

The orbital activity is

`q = 0.5 |sin(d_now)| + 0.5 |sin(kappa)|`.

The dynamic 36D tensor is the Z3 flavour orbit of **signed phase flow** `d_now`, while the lane-selection score combines `q` with flavour-orbit alignment. Thus stationary relations have zero activity, direction is retained, and second-order curvature contributes without replacing the DNCrypt entropy source.

The prime-gap, twin-prime-start-gap and `v2(p+1)` streams are ordered independently; they are not falsely zip-aligned as one physical event.

A standalone DNCrypt core reproduces the NOEMA Telekom V3 reference fixture byte-exactly. Reference state hash:

`09d6d2059bfaae9d3825827b8f5fcff9aca9846912d864d8c23152e44d80a4e1`.

Reference ranking prefix under the frozen fixture entropy:

`[2,9,13,10,7,6,12,1,0,15,18,21]`.

The validation comparison will be `E_RELATIONAL_PHASE_FLOW_V3 - B_RANDOM_LOCUS_NULL`. Both arms must share parent, Genetic IR phenotype, fresh population entropy, route, phase seed, mutation nonce, selection corpora, paired ciphertext entropy schedule and sealed holdout. Only admitted operator-locus ordering may differ.

No ciphertext result in this document. V3 remains observation-only; it cannot grant security admission, replace cryptographic entropy, alter frozen AEAD, or verify a physical neutrino carrier.