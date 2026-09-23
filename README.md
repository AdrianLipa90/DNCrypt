# DNCrypt v0.6.1a0 candidate

**Dynamic Noncommutative Cryptography — provenance-preserving AEAD, causal adversarial evolution, typed Genetic IR, exact rollback and relational 36D diagnostics.**

## Frozen security anchor

The application-data cryptographic anchor remains intentionally conservative:

- 256-bit master key;
- ChaCha20-Poly1305 authenticated encryption;
- per-message 256-bit HKDF salt;
- per-message 96-bit nonce;
- HKDF-SHA3-512 message-key derivation;
- authenticated binding of genome generation, 36D surface commitment, internal tick, parent receipt and user AAD.

The wire/protocol anchor remains `dncrypt.frozen-protocol/v0.2`. v0.6 does not replace or modify the standard AEAD primitive.

## Genetic IR v0.6

DNCrypt now has a typed Genetic IR compatible with the pinned CIELingo genomic-grammar research contract:

```text
KAKU -> RADICAL -> CONCEPT -> SENTENCE -> PARAGRAPH -> CHAPTER -> BOOK
```

The IR is strict and fail-closed: non-atomic nodes may contain only the immediately lower level, relations must connect immediate children, unknown schema fields are rejected, and every program receives a canonical BLAKE2b-256 semantic commitment.

The source contract is pinned to `AdrianLipa90/cielingo-canon` PR #29, commit `59297d21fba563e17c7a656e0cb3139a5a302ee5`. That branch is treated as a candidate research binding, not as biological canon.

### Grammar-constrained evolution

The first semantic mutation surface supports payload rewrites, adjacent-child transposition and child deletion with incident-relation cleanup. Every operation reconstructs the typed tree and emits a parent/child semantic-commitment receipt.

A deterministic 36D projection of Genetic IR is available for diagnostics and relational comparison. It is explicitly not cryptographic entropy and has no automatic security-admission authority.

### Authenticated Genetic IR binding

`genetic_user_aad()`, `encrypt_with_genetic_ir()` and `decrypt_with_genetic_ir()` bind the exact Genetic IR commitment inside the existing authenticated `user_aad` field.

This preserves `dncrypt.frozen-protocol/v0.2`: key derivation, nonce generation, salt generation and ChaCha20-Poly1305 remain unchanged. A ciphertext bound to one Genetic IR program is rejected when verified against another program.

### .pdna

`PDNARecord` adds a canonical content-addressed `.pdna` container carrying the cipher genome, Genetic IR, cipher/genetic 36D projections, parent lineage, source provenance and metadata.

A `.pdna` record must never contain master keys, AEAD salt/nonce secrets or evaluator private keys.

See `docs/GENETIC_IR_V0_6.md` and `provenance/GENETIC_IR_V0_6_SOURCE_BINDING.json`.

## Genetic state closure v0.6.1

v0.6.1 adds a bounded compiler from Genetic IR into a **mutation-control phenotype**. The phenotype may constrain which genome loci and route topology are explored, but it is public search control rather than cryptographic entropy. Every candidate still requires fresh external mutation entropy; the frozen v0.2 key, salt, nonce and AEAD path is unchanged.

`UnifiedDNCryptState` closes the logical generation across the active `CipherGenome`, `CipherSurface`, Genetic IR program, compiler commitment, optional evidence commitment and parent `.pdna` lineage. Its PDNA metadata binds the active surface and a cross-plane closure commitment.

Candidate rollback now has a matching full-state path: `UnifiedCheckpoint`, `UnifiedStateMemoryJournal` and `UnifiedMonotonicAnchor` bind the active PDNA identity alongside the state commitment. This prevents a research-layer rollback from restoring crypto state while silently retaining Genetic IR from another logical generation.

Hierarchical diagnostics no longer require flattening the entire grammar to one phase point. `genetic_phase_tree()` emits one 36D diagnostic projection per node, with per-level coherence and immediate parent/child phase distances. These values remain diagnostic-only.

`bounded_genetic_ir_from_mapping()` preflights untrusted nested Genetic IR using explicit node, relation, depth, fanout and payload budgets before the recursive typed parser is entered.

See `docs/DNCRYPT_GENETIC_STATE_CLOSURE_V0_6_1.md`.

## Existing hardening

### AEAD boundary

Production `encrypt()` generates salt and nonce entropy internally. Deterministic entropy injection is separated into `encrypt_deterministic_for_test()` for reproducible conformance fixtures only.

`decrypt()` validates the salt+nonce entropy commitment and reconstructs the authenticated-AAD schema before AEAD verification. Envelope metadata such as `parent_receipt`, generation, tick, genome id and surface commitment must agree with the authenticated AAD.

Unkeyed BLAKE2b/SHA3 receipts remain content commitments; they are not treated as substitutes for AEAD authentication.

### External evaluator boundary

`SignedEvaluationEnvelope` binds an external fitness report to an evaluator identity with Ed25519. `load_signed_external_evaluation()` admits a report only when the evaluator id is trusted, the signature verifies, the request id matches the exact evaluation request, and the report covers the exact candidate population/generation.

The legacy unsigned loader remains for historical fixtures. Security-sensitive deployments should use the signed boundary.

### Causality firewall

Metrics do not become security-admission evidence merely because they correlate with ciphertext statistics. The v0.4.2 causality registry keeps unsupported metrics `DIAGNOSTIC_ONLY`, preserves decrypt/integrity as hard invariants, and requires an explicit controlled mechanism plus falsification test before a metric can become `ADMISSION`.

### Generalization and rollback

Multifold promotion uses independent folds with a sealed holdout excluded from selection. v0.5 layers provide content-addressed checkpoints, ancestry verification, rollback receipts, checkpoint wire formats and an append-only logical state-memory journal.

The journal can be bound to an external monotonic compare-and-swap witness. `MonotonicAnchorPort` records the journal receipt, event count, head event, active checkpoint/state and a chained anchor digest. Replaying an older local journal is rejected whenever the external anchor retains the newer head. The in-memory implementation is a test reference only; TPM/HSM or remote append-only persistence remains the production deployment gate.

### Statistical admission hardening

`StatisticalAdmissionPolicy` adds a second fail-closed layer after multifold generalization: exact one-sided sign evidence across folds, explicit median effect-size thresholds and Benjamini-Hochberg false-discovery-rate control across the searched population. `select_generation_multifold_statistically_hardened()` cancels promotion if the multifold winner does not survive that population-level gate.

### Parser hardening

Checkpoint wire decoding enforces bounded payload size, exact field sets, canonical JSON, typed vector containers and a single fail-closed `ValueError` surface for malformed nested bodies. Hypothesis property fuzzing covers both checkpoint-wire and binary-envelope decoders, including arbitrary byte streams and single-bit mutation campaigns.

### Relational twist geometry

Twist v0.2 adds the relative route:

`sigma_rel = sigma_B o inverse(sigma_A)`

and derives its cycle decomposition plus per-cycle phase holonomies. The relational-class fingerprint excludes raw coordinate labels so simultaneous relabeling does not create false novelty. A NumPy batch path evaluates all 36 cyclic twists at once.

Twist metrics remain `EXPERIMENTAL_DIAGNOSTIC_ONLY / NO_SECURITY_ADMISSION`.

## Genetic operators and candidate policy compiler

v0.6.2 adds bounded structural Genetic IR operators for duplication, inversion, translocation and crossover. Every operator produces a content-addressed receipt and remains `CANDIDATE_ONLY`; the operators do not derive keys, salts, nonces or evaluator credentials and do not alter the frozen v0.2 AEAD anchor.

`compile_genetic_security_policy()` deterministically maps a Genetic IR program into a bounded `SecurityControlPolicy` proposal. The compiler locks nonce-domain tracking and fail-closed quarantine invariants on, constrains every numeric field to the existing frozen safe ranges, and marks the result as non-entropy / non-admission. A compiled policy must still pass the existing causal, multifold, statistical and signed-evaluator evidence pipeline before any deployment-specific admission decision.

## Evidence status

Status: `IMPLEMENTATION_CONFORMANCE_PROTOTYPE / INDEPENDENT_CRYPTANALYSIS_OPEN`.

The repository contains fail-closed protocol tests, deterministic reference fixtures, binary-envelope and BioOS DN36 AAD conformance, signed-evaluator tests, causal-admission controls, FDR/effect-size statistical gates, monotonic anti-rollback tests, property-fuzzed wire parsers, rollback/lineage tests, twist-geometry invariance tests and Genetic IR/PDNA conformance tests.

No claim is made that Genetic IR, relational geometry or adaptive mutation improves the cryptographic security of ChaCha20-Poly1305 or HKDF. Independent cryptanalysis remains required before any novel adaptive or relational mechanism is treated as a security advantage.
