# DNCrypt External Cryptanalysis Challenge v1

Status: frozen target ready for external evaluation.

## Frozen target

- Repository: `AdrianLipa90/DNCrypt`
- Target commit: `8651c3914e060cad5fd6ca1751f4420eb7a8360d`
- Target package version: `0.8.1a0`
- Frozen data-encryption protocol: `dncrypt.frozen-protocol/v0.2`
- Challenge ID: `3503af1b8eefe524348701ba5d2a03f7c776e2f6ee122691b6a79e0deb7b4d6b`

The challenge ID is the BLAKE2b-256 commitment of the canonical manifest payload
stored in `provenance/DNCRYPT_EXTERNAL_CRYPTANALYSIS_CHALLENGE_V1.json`.

## Scope

The evaluation is a system-security evaluation. DNCrypt does not claim a novel
cipher replacing ChaCha20-Poly1305 or HKDF. Reviewers should distinguish defects
in standard primitives from defects in DNCrypt's orchestration, provenance,
adaptation, parser, rollback, witness, KEM-composition, secret-backend and
authenticated-evidence layers.

The frozen tracks are:

1. AEAD authentication and tamper handling.
2. Nonce and entropy misuse boundaries.
3. Parser and binary-envelope fuzzing.
4. Rollback and external-witness replay.
5. Signed-evaluator forgery and causality/admission bypass.
6. Hybrid KEM transcript/provider confusion.
7. Secret-backend handle isolation.
8. Spectral-evidence header/lineage tamper.
9. Adaptive-control holdout/generalization.

## Required external evidence

An external report should provide raw results, tool source or an immutable tool
commitment, environment manifest, exact reproduction instructions, explicit
limitations and a signed submission.

The submission protocol in `dncrypt.cryptanalysis_release` binds:

- evaluator identity and evaluator key id;
- exact challenge id and target commit;
- evaluator-tool bytes;
- raw-result bytes;
- canonical summary;
- Ed25519 signature.

A result is not treated as independent merely because it uses the challenge
format. Independence requires the evaluator, signing key, execution environment
and analysis to be controlled outside Adrian Lipa / DNCrypt development.

## Existing internal benchmark

`tools/cryptanalysis_challenge_v01.py` remains useful controlled software
evidence, but it is explicitly classified as an internal benchmark. It is not
external cryptanalysis and must not be cited as such.

## Submission verification

The reviewer supplies their public Ed25519 key out of band. DNCrypt verifies the
signature and, when raw artifacts are available, checks that the signed
`tool_commitment` and `result_commitment` match those exact bytes.

A valid signature establishes provenance, not correctness of the evaluator's
methods or conclusions. Methodological review remains separate.
