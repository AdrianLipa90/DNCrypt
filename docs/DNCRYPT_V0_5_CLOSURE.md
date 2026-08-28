# DNCrypt v0.5 Evidence Gate — State Memory + Exact Rollback

## Current status

`CANDIDATE_MODEL_PASS_PARTIAL_LOCAL / EXACT_TREE_REPLAY_PENDING / RELEASE_CI_BLOCKED_BEFORE_RUNNER`

The implemented v0.5 checkpoint, rollback, lineage, State Memory journal and project-boundary mechanisms have passed the local development suite that exercised them. A later byte audit established that this development harness was not a complete byte-exact reconstruction of the current GitHub branch: it omitted some v0.3/v0.4 source/tests and contained non-canonical development bytes in selected files.

Accordingly, the earlier `52/52` result is retained as **partial local development evidence**, not as exact-branch closure evidence. Promotion to `main` remains blocked and v0.6 remains blocked by the v0.5 exact-tree gate.

## Implemented candidate mechanisms

- complete-state content-addressed checkpoints;
- exact reconstruction of genome, 36D surface, tick and receipt pointers;
- compare-and-swap current-state rollback guard;
- ancestry-constrained rollback with unrelated-branch rejection;
- missing-parent and cycle detection;
- deterministic lineage and rollback receipts;
- append-only hash-chained State Memory journal;
- rollback-aware post-rollback branch binding;
- frozen journal receipt for tail-event mutation detection;
- neutral checkpoint wire format;
- byte-only checkpoint storage port;
- AST-enforced import boundary for retained projects;
- retained shared interoperability contract for independent adapters.

## Evidence correction

Previous local development evidence: `52/52 pytest PASS` and `compileall PASS`.

Evidence classification: `PARTIAL_LOCAL_SUITE_PASS`.

Exact-tree requirement: reconstruct the full current branch from GitHub bytes, verify source/test/tool blob identities, then run the complete repository test suite and compile check. Only that result may close the v0.5 model evidence gate.

The previous model-closure receipt is superseded by the corrected evidence-state receipt in `evidence/DNCRYPT_V0_5_CLOSURE_RECEIPT.json`.

## CI boundary

For exact head `1fcbbfcdd76a42f9b84c7c40916de42c051d56be`, GitHub Actions run `33191091017` created Python 3.10/3.12 jobs but executed no workflow steps. GitHub account notices also show the current billing cycle has reached both `2,000 / 2,000` included Actions minutes and `0.5 / 0.5 GB` included Actions storage, both scheduled to reset on 1 September 2026. The account budget setting has not been independently verified, so the conservative classification remains `CI_INFRA_BLOCKED_BEFORE_RUNNER` rather than a code-test failure.

## Version dependency

`v0.5 = EXACT_TREE_REPLAY_PENDING`

`v0.6 = BLOCKED_BY_V0_5_EXACT_TREE_GATE`

Durable PNFS/PNH5 implementations remain retained external projects. The transaction/project carve-out and retained interoperability rights remain in force independently of this evidence correction.

No merge to `main` is requested.
