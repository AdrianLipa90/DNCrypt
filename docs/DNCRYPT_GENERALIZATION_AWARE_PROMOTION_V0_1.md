# DNCrypt Generalization-Aware Promotion v0.1

Status: `IMPLEMENTATION_CANDIDATE / FAIL_CLOSED / SEALED_HOLDOUT_EXCLUDED_FROM_SELECTION`

Version target: DNCrypt v0.4

## 1. Purpose

DNCrypt v0.4 replaces single-report candidate promotion with a robust multifold admission gate while preserving the frozen DNCrypt v0.2 cryptographic anchor and compatibility path.

The v0.1 cryptanalysis challenge demonstrated that repeated promotion on one attack-train view did not generalize to an independent holdout. The v0.4 selector therefore treats generalization evidence as part of the promotion predicate rather than as a post-hoc commentary layer.

## 2. Frozen compatibility boundary

The following existing path remains unchanged:

```text
EvolutionPolicy
-> propose_generation()
-> PopulationFitnessReport
-> select_generation()
```

That path remains the frozen v0.2 compatibility behavior.

The v0.4 path is additive:

```text
parent state
-> mutation proposal
-> independent fold evaluations
-> candidate multifold score
-> robust threshold gate
-> robust Pareto filter
-> deterministic tie-break
-> promotion / fail-closed retention
```

## 3. Sealed holdout firewall

Before the first mutation proposal, the final holdout corpus is committed by digest.

The promotion API receives only:

```text
sealed_holdout_commitment
```

and never receives holdout measurements, holdout risk, holdout throughput, win/loss state, or any statistic derived from the holdout.

The commitment proves that a holdout was fixed before selection. It is provenance, not a fitness input.

The challenge opens the holdout only after all promotion decisions for the replicate are complete.

## 4. Multifold candidate score

For fold `f` and candidate `g`, define

```text
Delta_f(g) = Risk_f(g) - Risk_f(parent)
```

where negative values favor the candidate.

For every candidate, v0.4 records:

```text
mean_delta
median_delta
worst_fold_delta
population_stddev(delta)
winning_fold_count
required_winning_fold_count
minimum_observed_throughput_ratio
frozen invariant status
```

A fold is a win exactly when `Delta_f(g) < 0`.

## 5. Generalization admission predicate

The candidate passes the multifold gate when all declared conditions are true:

```text
I_invariant
AND I_winning_fraction
AND I_median_improvement
AND I_worst_fold
AND I_variance
AND I_throughput
```

The default policy is:

```text
minimum_folds = 3
minimum_winning_fraction = 0.60
minimum_median_risk_improvement = 0.0
maximum_worst_fold_regression = 0.0
maximum_delta_stddev = 0.05
minimum_throughput_ratio = 0.50
```

Challenge v0.2 may freeze a different explicit configuration for evidence generation. Every such configuration is included in output provenance.

## 6. Robust Pareto selection

Only candidates that already pass the multifold gate may enter robust Pareto selection.

The Pareto objective vector is minimized as:

```text
(
  median_risk_delta,
  worst_fold_risk_delta,
  delta_stddev,
  -minimum_observed_throughput_ratio
)
```

A deterministic final rank uses the same tuple followed by `genome_id`.

Thus a candidate cannot compensate for a failed hard generalization gate merely by excelling on another objective.

## 7. Fail-closed behavior

If any of the following occurs, the parent state remains authoritative:

```text
insufficient fold count
parent/fold identity mismatch
candidate population mismatch
failed frozen decrypt/integrity invariant
insufficient winning folds
insufficient median improvement
excess worst-fold regression
excess fold variance
insufficient throughput
no candidate passing the multifold gate
invalid sealed holdout commitment
```

No child surface is published when the promotion verdict is false.

## 8. Receipt

`GeneralizationPromotionReceipt` binds:

```text
parent genome
parent surface commitment
parent tick
population commitment
parent fold report digests
candidate fold report digests
policy digest
sealed holdout commitment
holdout_used_for_selection = false
selected genome and score digest, when present
selected fold deltas
selected surface commitment and tick, when promoted
verdict and reason
```

The receipt is content-addressable through its BLAKE2b-256 digest.

## 9. PNCS / GREMLIN / State Memory binding

The v0.4 selector is intended to sit behind the existing DNCrypt native PNCS program boundary.

Cross-repository roles remain separated:

```text
DNCrypt
  -> owns cryptographic adaptation and promotion semantics

PNCS
  -> owns native relational execution and exact crypto-algebra realization

GREMLIN
  -> may generate candidate adversarial relations / KAKU / RADICALS / OPERATORS
     but remains CANDIDATE_ONLY and has no promotion authority

PNV-State-Memory
  -> next-stage authority for crystallizing an accepted promotion as a causal checkpoint
```

A later v0.5 receipt may bind the successful v0.4 promotion receipt directly into a State Memory checkpoint object. This v0.4 implementation deliberately keeps that persistence step separate from promotion correctness.

## 10. Evidence gate

`tools/cryptanalysis_challenge_v02.py` compares:

```text
STATIC_DNCRYPT_FROZEN_ANCHOR
vs
GENERALIZATION_AWARE_DNCRYPT
```

using fresh independent fold corpora for each generation and one sealed final holdout per replicate.

Primary endpoint:

```text
sealed_holdout_adversarial_risk
```

A positive claim requires the predeclared cross-replicate verdict, rather than successful internal promotion alone.
