# NOEMA Mutation-Word Native V5.3

Status: **EXPERIMENTAL / CANDIDATE ONLY / NO SECURITY PROMOTION**.

## Purpose

V5.3 binds the mutation-word token parameters to bounded arguments of the native DNCrypt v0.6.2 Genetic IR operators while preserving the matched-null design of V5.1.

The four native operators are:

- `DUPLICATE_CHILD`
- `INVERT_CHILDREN`
- `TRANSLOCATE_CHILD`
- `RECOMBINE_CHILDREN`

Each candidate receives the same four operators and the same per-operator `parameter_u64` / parameter commitments in both the relational and matched-null arms. The intended experimental variable is operator order only.

## Semantic parameter binding

The binding is defined against named anchors `r1..r4`, not against fixed array positions. This keeps the meaning of a parameter stable even after earlier operators have changed the child order.

- Duplicate: selects one named anchor and a deterministic namespace tag.
- Invert: selects one of the six unordered pairs of original anchors; runtime indices are resolved in the current state.
- Translocate: selects one of the twelve ordered source/destination anchor pairs; runtime indices are resolved in the current state.
- Recombine: keeps the complete current left program and selects a donor suffix (`right_cut` in 0..3) plus a deterministic namespace tag.

No operator deletes the four original anchors, so every later token remains resolvable for every permutation.

## Native provenance

The execution gate is bound to DNCrypt source commit:

`428fe3f0ac1707f935f833cc73be398fc136c2d3`

Byte-exact source blobs used locally:

- `genetic_ir.py`: `fb1b57e1d0054b8e30575793cb962e9a74e5eaa2`
- `genetic_operators.py`: `359f94414639b4ad94b83550ab218c692670af2b`
- `util.py`: `81dbbcfb121a15810bb990431abb49d7fdf1d57c`

Their Git blob hashes were recomputed locally before execution.

## Closure results

The fixed-anchor native closure gate executed all 24 permutations using real DNCrypt classes:

- 24/24 closed;
- 4 distinct final semantic states;
- exact 24/24 match to the earlier restricted semantic replay;
- native pytest: 2/2 PASS.

## Matched-state native stress

A deterministic On-Primes trajectory was constructed from prime gaps, twin-prime-start gaps, and `v2(p+1)`. A V5.1 matched state-shuffle null preserves the exact global word distribution, exact operator-position marginals, and candidate-wise operator parameter multiset.

With fixed semantic anchors, 4,096/4,096 paired executions closed. Operator order differed in 85.55% of pairs; among those, 77.63% reached different native `GeneticIR.semantic_id` states.

With V5.3 parameter binding enabled, 4,096/4,096 paired executions again closed. Exact order-distribution and position-marginal matching remained true, and the semantic parameter map was identical for every paired candidate. Every final state was unique within each arm (4,096 distinct relational and 4,096 distinct null states). Operator order differed in 85.57% of pairs; among those, 61.85% reached different final native semantic states.

This establishes native typed-IR closure and noncommutative order sensitivity. It does **not** establish ciphertext-security improvement.

## Authority boundary

V5.3 remains search/control only. It does not:

- derive keys, salts, nonces, or cryptographic entropy;
- modify the frozen DNCrypt AEAD anchor;
- grant security-admission authority;
- establish a number-theory theorem;
- establish a physical neutrino-carrier claim.

## Next gate

The next valid experiment is a fresh preregistered matched evaluator in which the relational and state-shuffle arms use the same parent, entropy budget, operator multiset, operator parameter map, evaluator, folds, and sealed holdout. The holdout must not be used for tuning V5.3.