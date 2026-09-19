# DNCrypt Fitness Causality Firewall v0.4.2

Status: `IMPLEMENTED_CANDIDATE / CAUSAL_ADMISSION_FIREWALL / PAIRED_EVALUATION`

Target: DNCrypt v0.4 closure.

## Purpose

v0.4.2 binds every promotion-driving fitness metric to an explicit causal path:

`genome field -> mechanism -> observable metric -> falsification test`.

A metric classified `ADMISSION` may contribute to promotion only when this path is declared. `DIAGNOSTIC_ONLY` metrics remain measurable evidence but are zeroed at the promotion boundary. `HARD_INVARIANT` metrics remain fail-closed constraints. `PERFORMANCE_OBSERVATION` remains outside deterministic security admission.

## Frozen v0.2 causal classification

The frozen Python anchor binds `genome_id` into HKDF domain separation and authenticates genome/surface/provenance metadata through AEAD AAD. The ChaCha20-Poly1305 and HKDF-SHA3-512 primitives remain fixed across candidates.

For that anchor the default registry classifies:

- `decrypt_failures`, `integrity_failures` -> `HARD_INVARIANT`;
- `structural_leakage`, `predictability`, `avalanche_bias`, `delta_bits`, `delta_alpha` -> `DIAGNOSTIC_ONLY` until an attack-specific causal binding exists;
- `throughput` -> `PERFORMANCE_OBSERVATION`.

The default frozen registry therefore has zero promotion-driving risk fields. A candidate cannot be promoted merely because one finite ciphertext sample looks statistically cleaner.

## Paired evaluation schedule

The earlier challenge derived salt/nonce entropy from candidate identity and parent/candidate labels. v0.4.2 uses one corpus-bound entropy schedule for every genome evaluated on the same corpus:

`entropy_i = SHAKE256(seed || paired-domain || corpus-commitment || i)`.

This removes salt/nonce schedule changes from parent-vs-candidate comparisons. Because candidate message keys are domain-separated by genome identity, reuse of the evaluation nonce schedule across different candidate keys is a controlled benchmark construction.

## Frozen-anchor null replay

A 6-replicate development replay with 3 generations, population 12, 5 folds, 16 messages/fold, 64 holdout messages, and 128-byte messages produced:

- promotions: `0.0` mean;
- adaptive wins: `0`;
- static wins: `0`;
- ties: `6`;
- mean holdout risk delta: `0.0`;
- all holdouts excluded from selection: `true`.

Two independent executions produced the same deterministic security commitment:

`ebc634dde1db25455d1fea84306145b3c380b779d4f4e01feada9679287edf70`

and different wall-clock measurement commitments, as expected.

This is the correct null behavior for the frozen anchor under the current causal registry. Future adaptation requires a genome-controlled security mechanism and its falsification test before its metric can enter `ADMISSION`.
