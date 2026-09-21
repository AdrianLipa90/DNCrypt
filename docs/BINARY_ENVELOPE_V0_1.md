# DNCrypt Binary Envelope v0.1

Status: TRANSPORT CODEC CANDIDATE / frozen crypto protocol unchanged

## Purpose

Provide a compact lossless representation of the existing `DNCryptEnvelope` for bounded persistence and transport surfaces such as BioOS PNStore/PAUX.

The codec does not change encryption, key derivation, nonce/salt rules, authenticated AAD, genome/surface binding or provenance receipts. `DNCryptEnvelope.to_bytes()` remains canonical JSON and remains the receipt authority.

## Invariant

For every admitted envelope `E`:

```text
B = pack_envelope(E)
E2 = unpack_envelope(B)

E2 == E
E2.to_bytes() == E.to_bytes()
E2.verify_receipt() == true
```

The binary representation therefore changes representation only; it does not create a second cryptographic protocol.

## Wire format

Big-endian header:

```text
magic             4 B   DNCB
codec_version     1 B   1
flags             1 B
reserved          2 B   zero
generation        8 B
tick              8 B
parent_len        2 B
aad_len           4 B
ciphertext_len    4 B
```

Then:

```text
genome_id                   32 B raw digest
surface_commitment          32 B raw digest
salt                        32 B
nonce                       12 B
entropy_commitment_blake2b  32 B raw digest
receipt_blake2b             32 B raw digest
receipt_sha3_256            32 B raw digest
parent_receipt              variable UTF-8
AAD                         variable raw bytes
ciphertext                  variable raw bytes
```

Canonical envelope version and protocol ID are fixed by the existing `DNCryptEnvelope` constructor and are reconstructed rather than redundantly serialized.

## Failure policy

Unknown magic/version/flags, non-zero reserved bits, truncation, trailing bytes, invalid component lengths, invalid UTF-8 parent receipt, or reconstructed receipt mismatch fail closed.

The default unpack path verifies the original DNCrypt provenance receipt before returning an envelope.

## BioOS relation

PNStore v0.1 provides at most 3936 payload bytes per 4096-byte generation extent. The existing JSON/base64 representation can exceed this budget for moderate PAUX payloads. The binary profile removes JSON keys and base64 expansion while retaining the exact cryptographic envelope semantics.

BioOS should treat the resulting binary bytes as an encrypted representation with a distinct `dncrypt:binary-envelope:sha256:*` identity. Canonical PNV/PNObject identity remains outside and unchanged.

## Evidence boundary

Capacity and latency claims must be measured from the committed codec and pinned test/benchmark receipts before promotion. This document defines the representation contract only.
