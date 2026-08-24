# DNCrypt v0.2 external adversarial evolution protocol

## Request

The DNCrypt side emits `dncrypt.evaluation-request/v0.2` with:

- parent genome ID;
- target generation;
- population commitment;
- ordered candidate genome IDs;
- frozen required metric list;
- request ID = BLAKE2b-256 over canonical request content.

## Response

The evaluator returns `dncrypt.external-evaluation/v0.2` with the matching request ID and exactly one record for every candidate.

Each record binds the genome ID and generation to the measured metric vector.

## Selection semantics

Decrypt and integrity failure counts are hard gates. Remaining valid candidates enter Pareto selection. The deterministic final tie-break is:

1. adversarial risk;
2. avalanche bias;
3. higher throughput;
4. genome ID lexical order.

## Risk

For significance threshold `alpha`, positive delta-bits and positive delta-alpha contribute to adversarial risk only when the aggregate attack p-value is at or below `alpha`. Structural leakage, predictability and avalanche bias always contribute.

## Promotion

The selected child must improve parent adversarial risk by the frozen minimum margin and meet the minimum throughput ratio. The promoted surface advances from the parent tick under child dynamics.
