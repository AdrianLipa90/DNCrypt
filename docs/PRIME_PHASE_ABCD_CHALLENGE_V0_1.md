# DNCrypt × NOEMA Prime-Phase A/B/C/D Challenge v0.1

Status: **EXPERIMENT / OBSERVATION ONLY — NO SECURITY ADMISSION**

This experiment tests whether the NOEMA prime/twin-prime fractal-orbital phase
geometry changes DNCrypt's mutation-search behaviour under the repository's
existing real ciphertext evaluator.

## Fixed parts

Every A/B/C/D arm uses the same:

- parent genome and parent 36D surface per replicate;
- fixed public Genetic IR program and compiled native DNCrypt phenotype;
- fresh mutation entropy block;
- native DNCrypt unconstrained mutation substrate;
- route, phase seed and mutation nonce candidate-by-candidate;
- mutation budget and allowed-locus set;
- selection-fold message corpora;
- paired ciphertext entropy schedule;
- sealed holdout corpus;
- ChaCha20-Poly1305 / HKDF-SHA3-512 frozen v0.2 cryptographic anchor.

Only the ordering used to choose admitted operator-vector loci changes.

## Arms

**A — Native Genetic IR.**
Exact DNCrypt v0.6.1 mutation-locus ordering. A conformance test requires the
experimental implementation to reproduce `mutate_genome_with_program()` exactly.

**B — Random locus null.**
A domain-separated entropy-only permutation over the same allowed loci. It is the
null control for changing the ordering without using prime structure.

**C — Raw flavour phase v1.**
Ranks the individual 36 coordinates by the magnitude of their wrapped phase.
This intentionally preserves the earlier raw-flavour construction as a falsifiable
historical arm; it may exhibit flavour-index bias.

**D — Orbital flavour phase v2.**
Ranks the 12 `(shell, observable)` orbital groups first using the flavour-independent
base phase, then uses fresh mutation entropy only to choose a flavour member inside
the `Z3` orbit. This prevents the fixed `0, 2π/3, 4π/3` flavour offsets from becoming
an accidental ranking advantage.

The public tensor basis is:

`{6,30,210,2310} × {prime_gap,twin_start_gap,v2(p+1)} × {nu_e,nu_mu,nu_tau}`.

## Evaluator

The experiment reuses `tools/cryptanalysis_challenge_v042.py` and specifically its
paired actual-ciphertext evaluator. It performs real DNCrypt encrypt/decrypt and
tamper rejection and measures:

- decrypt failures;
- integrity failures;
- ciphertext bit bias / byte structure;
- lag predictability;
- avalanche bias;
- wall-clock throughput.

The paired entropy schedule is independent of genome id, so parent and candidates
see the same salt/nonce schedule for the same message corpus.

## Causality firewall

The current DNCrypt v0.4.2 causality registry classifies ciphertext-distribution
metrics as `DIAGNOSTIC_ONLY`, throughput as `PERFORMANCE_OBSERVATION`, and
decrypt/integrity failures as `HARD_INVARIANT`.

Therefore this challenge **does not** promote prime-phase, twin-prime, or spectral
metrics into security-admission evidence.

The script uses the multifold/statistical machinery only as an observation-only
selector to compare search geometry. Any selected exploratory candidate is opened
on the sealed holdout only after selection is complete.

## Primary endpoint

For each arm and replicate:

`sealed holdout diagnostic adversarial-risk delta of the selection-fold exploratory winner versus the matched parent`.

Pairwise comparisons report `D - A`, `D - B`, and `D - C` with paired sign tests.

A lower value is only evidence that one search geometry found candidates with
lower measured diagnostic risk on this controlled software benchmark. It is **not**
a proof of stronger cryptography, a theorem about primes, or evidence for a physical
neutrino communication carrier.
