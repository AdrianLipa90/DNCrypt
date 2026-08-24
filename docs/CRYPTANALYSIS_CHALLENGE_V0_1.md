# DNCrypt Cryptanalysis Challenge v0.1

## Objective

Measure whether the DNCrypt adaptive genome/surface layer reduces independently measured ciphertext-level attack indicators relative to the same DNCrypt frozen ChaCha20-Poly1305/HKDF anchor with evolution disabled.

The primary endpoint is evaluated only on a holdout corpus that is never used for genome selection.

## Frozen comparison

A. `STATIC_DNCRYPT_FROZEN_ANCHOR`

- one initial genome;
- one initial 36D surface;
- ChaCha20-Poly1305;
- HKDF-SHA3-512 per-message key derivation;
- DNCrypt provenance/AAD binding;
- no genome promotion.

B. `ADAPTIVE_DNCRYPT`

- identical anchor suite;
- identical master-key size and message format;
- candidate populations evaluated on attack-train only;
- existing exact-coverage external-evaluation contract;
- existing Pareto filter and fail-closed promotion gate;
- final score computed on independent holdout.

## Frozen reference configuration

- replicates: 12
- generations per replicate: 3
- population size: 24
- train messages: 64
- holdout messages: 192
- message size: 256 bytes
- deterministic corpus/entropy seed: SHA-256 of `DNCrypt Cryptanalysis Challenge v0.1 frozen seed`
- minimum throughput ratio: 0.50

## Attack indicators

The v0.1 evaluator measures from real DNCrypt ciphertexts:

1. ciphertext bit bias;
2. lag-1 bit predictability;
3. byte-frequency chi-square deviation;
4. chosen-plaintext avalanche deviation under an offline same-entropy probe;
5. decryption failures;
6. ciphertext-tamper authentication failures;
7. throughput as a secondary engineering metric.

The aggregate adversarial-risk score is the existing DNCrypt `FitnessRecord.adversarial_risk()` over structural leakage, predictability and avalanche bias. `delta_bits` and `delta_alpha` are zero in v0.1 because this benchmark does not claim a calibrated differential/scaling cryptanalysis model.

## Primary endpoint

For each replicate:

`holdout_risk_delta = adaptive_holdout_risk - static_holdout_risk`

Negative values favor adaptation. Positive values favor the static frozen anchor.

The cross-replicate decision uses win/loss counts plus an exact two-sided sign test. `HOLDOUT_ADVANTAGE_DEMONSTRATED` requires a negative mean delta, more adaptive wins than static wins, and sign-test `p < 0.05`.

## Reference run 2026-08-24

- adaptive holdout wins: 4/12
- static holdout wins: 8/12
- ties: 0
- mean adaptive-minus-static holdout risk delta: +0.0235005554
- median adaptive-minus-static holdout risk delta: +0.0365400618
- exact two-sided sign-test p: 0.3876953125
- mean train risk delta: +0.0069340506
- mean holdout-minus-train generalization gap: +0.0165665048
- mean adaptive/static throughput ratio: 0.9855056029
- mean promotions: 3.0

Verdict: `NO_HOLDOUT_ADVANTAGE_DEMONSTRATED`.

Evidence status: `CONTROLLED_SOFTWARE_CRYPTANALYSIS_BENCHMARK`.

The result is intentionally preserved even though it does not favor the adaptive layer. It establishes a falsifiable baseline for independent cryptanalysis and for later changes to the selection/evaluator design.

## External tester procedure

Run from repository root:

```bash
PYTHONPATH=src python tools/cryptanalysis_challenge_v01.py \
  --replicates 12 \
  --generations 3 \
  --population-size 24 \
  --train-messages 64 \
  --holdout-messages 192 \
  --message-bytes 256 \
  --output evidence/CRYPTANALYSIS_CHALLENGE_V0_1.json
```

An external tester may add new evaluator modules, but should preserve the frozen static/adaptive comparison and keep attack-train data disjoint from the final holdout.
