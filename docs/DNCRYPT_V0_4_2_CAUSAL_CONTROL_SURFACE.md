# DNCrypt v0.4.2 — Causal Control Surface

Status: CANDIDATE_FRONTIER

## Dependency

`v0.4.1 deterministic security admission -> v0.4.2 causal security-control state -> v0.4 closure gate`

## Measured dataflow

The frozen v0.2 cryptographic anchor is HKDF-SHA3-512 followed by ChaCha20-Poly1305. The current executable dataflow binds DNCrypt adaptive state to that anchor through:

- `genome.genome_id` in HKDF `info`;
- `genome.genome_id` and `genome.generation` in authenticated metadata;
- `surface.commitment` and `surface.tick` in authenticated metadata.

The 36D candidate fields `operator_vector`, `route`, `phase_seed_hex`, and `mutation_nonce_hex` contribute to the identity commitment from which `genome_id` is formed. The causal audit receipt records the exact source hashes and AST-observed attribute accesses.

## Consequence for the v0.4 evaluator

Ciphertext bit-bias, lag agreement, byte chi-square, and avalanche metrics primarily probe the frozen ChaCha20-Poly1305 output distribution. The next adaptive objective is therefore a security-control state whose decisions are causally driven by the genome while the standard primitive anchor remains frozen.

## Candidate control dimensions

The next implementation may expose bounded, fail-closed policy dimensions such as:

1. key-rotation request threshold;
2. message/byte exposure budget per key epoch;
3. adversarial-risk trigger window;
4. nonce-domain/replay tracking policy;
5. quarantine and rollback trigger receipts.

Cryptographic integrity gates remain frozen. Candidate policy parameters may affect operational response and exposure budgeting, while primitive selection remains governed by the frozen protocol until the planned v0.7 crypto-agility stage.

## Admission rule

A v0.4.2 candidate may advance only when:

- its policy is derived deterministically from committed genome state;
- all decrypt/integrity invariants pass;
- security selection is independent of wall-clock throughput;
- multifold generalization passes;
- sealed holdout remains excluded from selection;
- every promotion has a content-addressed receipt.

The v0.5 State Memory frontier remains blocked until this v0.4 evidence gate is closed.
