# DNCrypt v0.2 threat model

## Defensive goal

Protect arbitrary application data against an observer who may know the full DNCrypt implementation, public genome state, public surface metadata, provenance records, mutation policy and ciphertext while lacking the 256-bit master key.

## Adversarial evolution model

An external cryptanalytic evaluator acts as a controlled red-team component. DNCrypt receives bounded metric records and validates their provenance and population coverage before allowing a generation transition.

The evaluator may attempt to detect structural leakage, predictability, rank advantage, scaling advantage, avalanche bias and performance regressions. The adaptive loop converts those findings into selection pressure on the experimental genome.

## Frozen security boundary

Confidentiality and integrity are anchored in ChaCha20-Poly1305 with HKDF-SHA3-512-derived per-message keys. Mutation policy has no authority to alter the anchor suite, master-key size, nonce size, salt size, authenticated metadata contract or provenance schemas in v0.2.

## Fail-closed conditions

Promotion is blocked by:

- incomplete or extra external evaluation records;
- duplicate candidate IDs;
- request-ID mismatch;
- generation mismatch;
- decrypt failures;
- integrity failures;
- insufficient risk improvement;
- throughput below the frozen ratio.

## Evidence boundary

Current evidence is software conformance plus synthetic orchestration fixtures. Production use requires hardened implementation, side-channel analysis, independent cryptographic review and sustained adversarial testing.
