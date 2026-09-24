# DNCrypt v0.6 Genetic IR

Status: **experimental diagnostic layer / no security-admission authority**.

DNCrypt v0.6 introduces a typed intermediate representation for genomic-language
programs while preserving the frozen v0.2 AEAD anchor.

## Representation

The IR follows the pinned CIELingo research hierarchy:

```text
KAKU -> RADICAL -> CONCEPT -> SENTENCE -> PARAGRAPH -> CHAPTER -> BOOK
```

Every non-atomic node may contain only children from the immediately lower
level. Relations are allowed only between immediate children. Unknown fields,
invalid levels, duplicate relation endpoints and non-canonical containers fail
closed.

The source binding is pinned to:

- repository: `AdrianLipa90/cielingo-canon`
- branch: `feature/cielingo-gremlin-genomic-grammar-v01-20260922`
- commit: `59297d21fba563e17c7a656e0cb3139a5a302ee5`
- source schema: `CIELINGO_GENOMIC_GRAMMAR_V0_1`

This is a candidate research binding, not a claim that the CIELingo branch is
canonical or that DNA is literally a natural language.

## Genetic IR commitment

Every IR tree has a canonical BLAKE2b-256 semantic commitment. A deterministic
36D projection is derived with SHAKE-256 for diagnostics and relational
comparison.

The 36D Genetic IR projection is explicitly forbidden as:

- master-key material;
- nonce material;
- salt material;
- evaluator-signing entropy;
- automatic security-admission evidence.

## Grammar-constrained mutation

The first mutation surface supports:

- payload rewrite;
- adjacent-child transposition;
- child deletion with incident-relation cleanup.

Each mutation reconstructs and revalidates the complete typed tree. Mutations
that would create an empty non-atomic node or violate level adjacency fail
closed. Mutation receipts bind parent and child semantic commitments.

## Authenticated AEAD binding

Genetic IR does not change `dncrypt.frozen-protocol/v0.2`.

Instead, `genetic_user_aad()` wraps the caller AAD with the Genetic IR
commitment and places that canonical object inside the already authenticated
`user_aad` field.

`decrypt_with_genetic_ir()` verifies the exact IR commitment before returning
plaintext. A different program is rejected even when the cipher genome and
surface otherwise match.

## .pdna

`PDNARecord` provides a canonical `.pdna` serialization containing:

- the current `CipherGenome`;
- the complete Genetic IR tree;
- cipher-genome 36D phase;
- Genetic IR 36D phase;
- parent `.pdna` lineage commitment;
- pinned source binding;
- caller metadata;
- a content-addressed `pdna_id`.

A `.pdna` record MUST NOT contain master keys, AEAD salts/nonces, evaluator
private keys or other secret key material.

## Security boundary

The cryptographic security anchor remains:

- ChaCha20-Poly1305;
- HKDF-SHA3-512;
- fresh internally generated per-message salt and nonce;
- authenticated envelope metadata;
- existing signed evaluator / causality / statistical / rollback gates.

Genetic IR is a representation, provenance and experimental evolution layer.
Independent cryptanalysis is still required before any Genetic IR-derived
diagnostic can be promoted to a security claim.
