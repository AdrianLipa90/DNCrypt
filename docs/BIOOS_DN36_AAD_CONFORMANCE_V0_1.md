# BioOS DN36 AAD Conformance v0.1

Status: IMPLEMENTED CONFORMANCE CANDIDATE / CHYBA / canon_allowed=false

This gate verifies one bounded compatibility path between the BioOS DN36 auxiliary commitment and the existing DNCrypt v0.2 authenticated-encryption and binary-envelope implementation.

## Source pins

BioOS evidence source:

- repository: `AdrianLipa90/PNCore-BioOS`
- branch: `feat/bioos-dn36-fundamental-code-v0.1`
- evidence head: `430dfc8080edc8c30d95a946663b0c1c2195fafb`
- workflow run: `35240603224`
- artifact digest: `sha256:13cf2a5829027161043a31f3ca74cd4f813a301ef6cfa3788f48581effb79842`
- BioOS auxiliary receipt: `691eb7ccbb5fd1d74a5ec8e68f9f1581e00d4f2a2a715a845dc0d9aac7870884`

The BioOS auxiliary receipt itself pins:

- DNCrypt source: `20f53a9b297b6208d74841aee7c3bb4b8b17ce2a`
- Resonant-Chemistry source: `6a9f21678ba4f07e5bdbb1a98a0cafe5c4838697`
- TIR source: `45b54c0c8aa60ec92607e6132b69aca9ab766d75`

Actual DNCrypt implementation executed by this gate:

- base branch: `feat/dncrypt-v0.4-binary-envelope`
- base head: `88439967b97d4d607ab2c7d30211f91e1fe87a72`
- `src/dncrypt/crypto.py` Git blob: `694523cadd7b44417a3c04de08d5f44b0717b86e`
- `src/dncrypt/binary_envelope.py` Git blob: `9c5bbe595462ca848c67803c7b1febdd88d561c2`

## Tested path

```text
BioOS PAUX exact payload, 288 bytes
  -> deterministic BioOS DN36 auxiliary record
  -> exact canonical BioOS user_aad
  -> DNCrypt v0.2 ChaCha20-Poly1305 AEAD
  -> DNCrypt binary-envelope/v0.1
  -> binary roundtrip
  -> provenance receipt verification
  -> AEAD decrypt
  -> exact PAUX recovery
  -> current PNStore payload-capacity check, max 3936 bytes
```

The gate also performs fail-closed cases against the actual DNCrypt AEAD path. It mutates authenticated BioOS user AAD while recomputing the outer provenance receipt, mutates ciphertext while recomputing the outer provenance receipt, uses a wrong master key, and mutates the packed binary envelope. These cases must all reject.

Recomputing the provenance receipt in the first two negative cases is deliberate. It prevents the outer receipt check from being the only reason for rejection and forces the ChaCha20-Poly1305 authentication tag to enforce the AAD/ciphertext binding.

## Authority boundary

DN36 remains auxiliary. This gate does not assign DN36 cryptographic authority, identity authority, AEAD authority, or canon authority. DNCrypt remains the AEAD authority for this path. PNStore remains the durability/order authority. BioOS/PNV State Memory remains the logical identity/reconstruction authority where that layer is used.

`security_claim=false` and `canon_allowed=false` are mandatory outputs.

## What this proves

A PASS proves that the pinned BioOS DN36-augmented authenticated metadata can be carried through the pinned DNCrypt v0.2 AEAD and binary-envelope implementation, that the exact 288-byte PAUX payload is recovered, that the packed envelope fits the current 3936-byte PNStore payload bound, and that the listed deterministic mutation cases fail closed.

It does not prove cryptographic strength of DN36, replace standard cryptographic primitives, establish collision/preimage resistance for DN36, prove physical storage durability, or promote the result to canon.
