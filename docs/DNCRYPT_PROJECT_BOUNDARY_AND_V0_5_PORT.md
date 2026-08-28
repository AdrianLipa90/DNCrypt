# DNCrypt Project Boundary and v0.5 Rollback Port

## Status

`CANDIDATE_STACK / TECHNICAL_IP_CARVEOUT`

DNCrypt is maintained as a standalone transferable package. Adjacent projects remain separate development lineages and connect only through explicit interfaces.

## Retained project boundary

The DNCrypt transaction package excludes PNCS, GREMLIN, NOEMA, CIEL, PhaseNav, PNV-State-Memory, PNFS and PNH5. Their repositories, general-purpose algorithms, memory architectures, file formats and independent development rights remain outside the DNCrypt package boundary.

`src/dncrypt/project_boundary.py` converts that separation into a testable build invariant. The scanner parses every Python source file and fails closed if DNCrypt introduces a direct import from a retained project namespace.

This is a technical provenance control. A future licence, asset sale or acquisition agreement should repeat the same exclusions in its asset schedule and retained-IP clauses.

## v0.5 checkpoint port

`src/dncrypt/checkpoint_port.py` begins the v0.5 State Memory + exact rollback frontier without importing PNV-State-Memory. It provides:

- deterministic state commitments;
- content-addressed DNCrypt checkpoints;
- parent-checkpoint lineage;
- exact reconstruction of genome, 36D surface, ticks and receipt pointers;
- fail-closed rollback authorization using the expected current-state commitment;
- rollback receipts binding source state, target checkpoint and restored state;
- a minimal `CheckpointPort` protocol so a future State Memory adapter can be implemented outside DNCrypt.

The in-memory store is a reference implementation for conformance tests. Durable PNFS/PNH5 storage remains the separate v0.6 frontier.

## Transaction-safe dependency rule

```text
DNCrypt core -> DNCrypt CheckpointPort <- external adapter -> PNV-State-Memory
                                         external adapter -> PNFS/PNH5
```

A buyer or licensee can receive DNCrypt without receiving the adjacent projects, while the adjacent projects can continue to use compatible DNCrypt interfaces under separately defined terms.
