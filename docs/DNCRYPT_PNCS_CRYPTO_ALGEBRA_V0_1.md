# PNCS Cryptographic Algebra v0.1

Status: `IMPLEMENTATION_CONFORMANCE_PROTOTYPE`

## Scope

This module realizes the deterministic cryptographic core used by DNCrypt v0.2 through PNCS relational paths and a bit-exact conformance implementation.

The canonical relation alphabet remains:

`IDENTITY`, `DIFFERENCE`, `COMPOSITION`, `TRANSFORM`, `CONDITION`, `RESOLVE`, `DERIVE`, `ORDER`.

The cryptographic layer adds named compositions and radicals built from that relation alphabet.

## Native algebra

### Word and byte layer

- `ADD_MOD32`
- `XOR32`
- `ROTL32`
- `ROTL64`
- byte XOR
- concatenation
- canonical padding
- truncation
- little-endian 32-bit and 64-bit conversion

### ChaCha20

ChaCha20 is represented as the ordered ARX path

`ADD_MOD32 -> XOR32 -> ROTL32`

with the RFC 8439 rotation schedule `16, 12, 8, 7`. The native hierarchy is:

`ARX -> QUARTER_ROUND -> COLUMN_ROUND / DIAGONAL_ROUND -> DOUBLE_ROUND -> ROUNDS20 -> FEED_FORWARD -> BLOCK -> STREAM`.

### Poly1305

Poly1305 is represented through key clamping, block interpretation, accumulator addition, multiplication, reduction modulo `2^130 - 5`, and final addition modulo `2^128`.

### Keccak / SHA-3 / SHAKE

Keccak-f[1600] is represented by the FIPS 202 round ordering

`THETA -> RHO -> PI -> CHI -> IOTA`

for 24 rounds. The sponge specializes to SHA3-256, SHA3-512, and SHAKE256 through their rate, suffix, and output-length parameters.

### HMAC / HKDF

HMAC-SHA3-512 is composed from key normalization, `ipad`, inner hash, `opad`, and outer hash. HKDF follows RFC 5869:

`EXTRACT -> EXPAND_STEP* -> EXPAND`.

DNCrypt uses a 32-byte HKDF-SHA3-512 result with the existing v0.2 salt and genome-bound `info` domain.

### BLAKE2b-256

BLAKE2b uses the RFC 7693 64-bit mixing function, 12 compression rounds, byte counter, final-block flag, and 32-byte digest specialization used by DNCrypt commitments and receipts.

## DNCrypt binding

`DNCRYPT_NATIVE_PNCS_V0_2.pnv` binds:

- deterministic expansion -> `CRYPTO.SHAKE256`
- content commitments -> `CRYPTO.BLAKE2B_256`
- independent receipt digest -> `CRYPTO.SHA3_256`
- message-key derivation -> `CRYPTO.HKDF.SHA3_512`
- AEAD -> `CRYPTO.CHACHA20_POLY1305.ENCRYPT/DECRYPT`
- entropy acquisition -> explicit OS CSPRNG effect boundary

The master-key, salt, nonce, AAD, genome, surface, mutation, Pareto, promotion, provenance, and DNA-transport contracts remain bound to DNCrypt v0.2.

## Conformance gates

The implementation is required to pass:

1. RFC 8439 ChaCha quarter-round vector.
2. RFC 8439 ChaCha20 block vector.
3. RFC 8439 ChaCha20 stream-cipher vector.
4. RFC 8439 Poly1305 vector.
5. RFC 8439 ChaCha20-Poly1305 AEAD vector.
6. AEAD fail-closed tag mutation test.
7. SHA3-256, SHA3-512, and SHAKE256 differential tests against Python standard-library implementations, including rate-boundary messages.
8. HMAC-SHA3-512 differential tests.
9. HKDF-SHA3-512 differential tests against `cryptography`.
10. RFC 7693 BLAKE2b-512 `abc` vector and BLAKE2b-256 differential tests.
11. Deterministic ChaCha20-Poly1305 differential population against `cryptography`.
12. Exact DNCrypt v0.2 envelope ciphertext, receipt, SHAKE, and message-key conformance.
13. PNCS relation-alphabet closure.
14. Live NOEMA/PhaseNav admission with `/dev/shm/ciel_noema` active.

## Evidence boundary

Current evidence establishes implementation conformance for the algebraic rewrite against the cited public specifications and the DNCrypt v0.2 reference implementation. Cryptanalytic evaluation and side-channel characterization are separate evidence gates.
