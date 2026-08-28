# DNCrypt Security Admission v0.4.1

Status: `IMPLEMENTED_CANDIDATE / DETERMINISTIC_SECURITY_EVIDENCE / PERFORMANCE_OBSERVATIONAL`

Target: DNCrypt v0.4 closure.

## Purpose

v0.4.1 separates deterministic security admission from wall-clock performance evidence. Multifold risk, frozen decrypt/integrity invariants, robust Pareto ordering, sealed-holdout provenance, and deterministic tie-breaking remain inside the security decision. Measured wall-clock throughput remains evidence, but it does not change the security promotion verdict.

## Security admission boundary

`select_generation_multifold_security_only()` normalizes throughput to `1.0` in the reports passed to the v0.4 selector and fixes the security-side minimum throughput ratio to `1.0`. Original reports remain available to the caller as observational performance evidence.

This yields two commitments:

- `security_evidence_commitment_blake2b`: deterministic projection excluding wall-clock throughput and measurement-only commitments;
- `measurement_commitment_blake2b`: measured-run commitment that may change with runtime scheduling and host performance.

## Holdout firewall

The sealed holdout remains excluded from all promotion decisions. Only its precommitted digest crosses the selector boundary. The holdout is opened after all promotion decisions for a replicate.

## Replay gate

For the frozen v0.4.1 development configuration used on 2026-08-28, two independent executions produced the same security commitment:

`6c25c831d86448f23a89a7f6da1d9cd4c06849219780233729d0ca5860aefe3d`

while producing different measurement commitments, as expected for wall-clock observations.

The measured endpoint remained `NO_SEALED_HOLDOUT_ADVANTAGE_DEMONSTRATED`: 3 adaptive wins, 3 static wins, mean holdout risk delta `-0.0056835640943992405`, two-sided sign-test `p=1.0`.

This closes the deterministic-admission defect only. It does not promote a security-advantage claim.

## Cross-repository role boundary

- DNCrypt owns security admission and promotion receipts.
- PNCS owns native relational execution and exact cryptographic algebra realization.
- GREMLIN may produce candidate adversarial KAKU/RADICAL/OPERATORS but has no promotion authority.
- PNV-State-Memory remains the next-stage target for accepted-promotion checkpoint crystallization in v0.5.
