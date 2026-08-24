# DNCrypt v0.2

**Dynamic Noncommutative Cryptography — Vectorized Adversarial Evolution Core.**

DNCrypt v0.2 extends the v0.1 provenance-preserving AEAD runtime with a complete external-adversary mutation cycle.

## Frozen security anchor

Every application payload is protected by:

- 256-bit master key;
- ChaCha20-Poly1305 authenticated encryption;
- per-message 256-bit HKDF salt;
- per-message 96-bit nonce;
- HKDF-SHA3-512 message-key derivation;
- authenticated binding of genome generation, 36D surface commitment, internal tick, parent receipt and user AAD.

The adaptive layer operates around this anchor. Genome mutation changes the public experimental state while the AEAD invariants remain frozen by protocol.

## v0.2 adversarial evolution cycle

```text
parent genome + parent surface
        |
        v
external parent fitness report
        |
        v
vectorized mutation proposal
        |
        v
population commitment + evaluation request
        |
        v
external adversary evaluates every candidate
        |
        v
exact-coverage validation
        |
        v
multi-objective Pareto filter
        |
        v
fail-closed promotion gate
        |
        v
promoted child + surface transition + evolution receipt
```

The external evaluator supplies only bounded metrics. Its implementation remains a separate component.

## Fitness contract

Each candidate receives:

- structural leakage;
- predictability;
- adversarial delta-bits advantage;
- adversarial scaling advantage (`delta_alpha`);
- avalanche bias;
- throughput;
- decrypt failure count;
- integrity failure count;
- aggregate adversarial p-value.

The report must cover the exact candidate population once each. Missing, extra, duplicate or wrong-generation records stop promotion.

## Promotion gate

A candidate can be promoted only when:

1. decrypt and integrity invariants pass;
2. the candidate is a Pareto survivor;
3. adversarial risk improves over the parent by the frozen minimum margin;
4. throughput remains above the frozen parent ratio;
5. the external report is cryptographically bound to the exact population request.

Promotion advances the persistent 36D cipher surface under the child genome while preserving its internal tick lineage.

## Provenance

v0.2 has two append-only provenance streams:

- message ledger: ciphertext receipt -> exact historical genome + surface;
- evolution ledger: proposal and promotion receipts -> parent, population commitment, policy digest, external evaluation digest and selected child.

The v0.1 full archive is preserved byte-for-byte under `lineage/`.

## DNA transport

Authenticated DNCrypt envelopes retain reversible A/C/G/T 2-bit transport encoding.

## Evidence status

Status: `IMPLEMENTATION_CONFORMANCE_PROTOTYPE`.

The included evidence establishes deterministic protocol binding, fail-closed report validation, vectorized population generation, promotion-gate behavior, state persistence, provenance integrity and encryption/decryption conformance. Independent cryptanalytic evaluation remains the next evidence gate.
