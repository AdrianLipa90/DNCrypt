# DNCrypt v0.2 architecture

## 1. Frozen invariants

- 256-bit master key.
- ChaCha20-Poly1305 AEAD.
- HKDF-SHA3-512 per-message key derivation.
- Fresh 256-bit salt and 96-bit nonce for each encryption.
- Genome, surface, tick, lineage and user AAD authenticated with the ciphertext.
- 36D genome and 36D persistent cipher surface.
- Append-only message and evolution provenance.
- External adversary boundary with exact population binding.

## 2. Internal computational time

The surface carries its own integer `tick`. Host wall time is outside the cryptographic state contract. A genome promotion advances the existing surface under the child dynamics through `transition_surface()`, preserving time continuity instead of resetting the surface.

## 3. Mutation proposal

A parent fitness record is bound to the parent genome ID and generation. If the frozen adversarial-risk threshold is exceeded, `propose_generation()` creates a vectorized population of children using fresh mutation entropy.

The proposal receipt binds:

- parent genome ID;
- parent fitness digest;
- policy digest;
- population commitment;
- entropy commitment;
- proposal decision.

## 4. External evaluation bus

`make_evaluation_request()` produces an immutable contract containing the parent ID, target generation, ordered candidate IDs, population commitment and required metric set.

`load_external_evaluation()` validates the returned report against that exact request and exact population.

## 5. Multi-objective selection

The objective matrix minimizes:

- structural leakage;
- predictability;
- positive delta-bits attack advantage;
- positive delta-alpha scaling advantage;
- avalanche bias;

while maximizing throughput.

Frozen decrypt/integrity invariants are evaluated before Pareto selection.

## 6. Promotion

The best deterministic Pareto survivor is compared against the parent risk and throughput gate. Promotion returns a child genome, transitioned surface and cryptographically digestible promotion receipt. A failed gate returns the unchanged parent state with an explicit reason.

## 7. Provenance graph

Message provenance and evolutionary provenance form separate append-only streams that can be joined by genome ID, generation, surface commitment and message receipt.
