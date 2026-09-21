# DNCrypt v0.5.2 candidate

**Dynamic Noncommutative Cryptography — provenance-preserving AEAD, causal adversarial evolution, exact rollback and relational 36D diagnostics.**

## Frozen security anchor

The application-data cryptographic anchor remains intentionally conservative:

- 256-bit master key;
- ChaCha20-Poly1305 authenticated encryption;
- per-message 256-bit HKDF salt;
- per-message 96-bit nonce;
- HKDF-SHA3-512 message-key derivation;
- authenticated binding of genome generation, 36D surface commitment, internal tick, parent receipt and user AAD.

The wire/protocol anchor remains `dncrypt.frozen-protocol/v0.2`. Later repository versions harden orchestration, provenance, evaluation and rollback around that anchor rather than replacing the standard AEAD primitive.

## Current hardening

### AEAD boundary

Production `encrypt()` generates salt and nonce entropy internally. Deterministic entropy injection is separated into `encrypt_deterministic_for_test()` for reproducible conformance fixtures only.

`decrypt()` now validates the salt+nonce entropy commitment and reconstructs the authenticated-AAD schema before AEAD verification. Envelope metadata such as `parent_receipt`, generation, tick, genome id and surface commitment must agree with the authenticated AAD.

Unkeyed BLAKE2b/SHA3 receipts remain content commitments; they are not treated as substitutes for AEAD authentication.

### External evaluator boundary

`SignedEvaluationEnvelope` binds an external fitness report to an evaluator identity with Ed25519. `load_signed_external_evaluation()` admits a report only when the evaluator id is trusted, the signature verifies, the request id matches the exact evaluation request, and the report covers the exact candidate population/generation.

The legacy unsigned loader remains for historical fixtures. Security-sensitive deployments should use the signed boundary.

### Causality firewall

Metrics do not become security-admission evidence merely because they correlate with ciphertext statistics. The v0.4.2 causality registry keeps unsupported metrics `DIAGNOSTIC_ONLY`, preserves decrypt/integrity as hard invariants, and requires an explicit controlled mechanism plus falsification test before a metric can become `ADMISSION`.

### Generalization and rollback

Multifold promotion uses independent folds with a sealed holdout excluded from selection. v0.5 candidate layers provide content-addressed checkpoints, ancestry verification, rollback receipts, checkpoint wire formats and an append-only logical state-memory journal.

The journal can now be bound to an external monotonic compare-and-swap witness. `MonotonicAnchorPort` records the journal receipt, event count, head event, active checkpoint/state and a chained anchor digest. Replaying an older local journal is rejected whenever the external anchor retains the newer head. The in-memory implementation is a test reference only; TPM/HSM or remote append-only persistence remains the production deployment gate.

### Statistical admission hardening

`StatisticalAdmissionPolicy` adds a second fail-closed layer after multifold generalization: exact one-sided sign evidence across folds, explicit median effect-size thresholds and Benjamini-Hochberg false-discovery-rate control across the searched population. `select_generation_multifold_statistically_hardened()` cancels promotion if the multifold winner does not survive that population-level gate.

### Parser hardening

Checkpoint wire decoding now enforces bounded payload size, exact field sets, canonical JSON, typed vector containers and a single fail-closed `ValueError` surface for malformed nested bodies. Hypothesis property fuzzing covers both checkpoint-wire and binary-envelope decoders, including arbitrary byte streams and single-bit mutation campaigns.

### Relational twist geometry

Twist v0.2 adds the relative route:

`sigma_rel = sigma_B o inverse(sigma_A)`

and derives its cycle decomposition plus per-cycle phase holonomies. The relational-class fingerprint excludes raw coordinate labels so simultaneous relabeling does not create false novelty. A NumPy batch path evaluates all 36 cyclic twists at once.

Twist metrics remain `EXPERIMENTAL_DIAGNOSTIC_ONLY / NO_SECURITY_ADMISSION`.

## Evidence status

Status: `IMPLEMENTATION_CONFORMANCE_PROTOTYPE / INDEPENDENT_CRYPTANALYSIS_OPEN`.

The repository contains fail-closed protocol tests, deterministic reference fixtures, binary-envelope and BioOS DN36 AAD conformance, signed-evaluator tests, causal-admission controls, FDR/effect-size statistical gates, monotonic anti-rollback tests, property-fuzzed wire parsers, rollback/lineage tests and twist-geometry invariance tests.

No claim is made that DNCrypt improves the cryptographic security of ChaCha20-Poly1305 or HKDF. Independent cryptanalysis remains required before any novel adaptive or relational mechanism is treated as a security advantage.
