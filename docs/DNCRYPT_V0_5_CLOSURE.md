# DNCrypt v0.5 Evidence Gate — State Memory + Exact Rollback

## Current status

`MODEL_CLOSED_EXACT_LOCAL / RELEASE_CI_BLOCKED_BEFORE_RUNNER`

The v0.5 checkpoint, rollback, lineage, State Memory journal and project-boundary mechanisms have now been replayed against a byte-exact reconstruction of the executable GitHub test surface.

The earlier `52/52` local development result remains recorded as superseded partial-local evidence. The closure result below is a separate exact replay and is the canonical local model/evidence result for v0.5.

## Implemented mechanisms

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

## Exact replay evidence

Tested executable snapshot source: GitHub code/test/tool bytes at commit `1fcbbfcdd76a42f9b84c7c40916de42c051d56be`.

The subsequent branch commits up to `57ca18ad17bd513d153e007ac1f7166d9602506d` changed only this closure document and the closure receipt; no `src/`, `tests/`, `tools/`, native/registry or build configuration bytes changed before the replay manifest was committed.

Reconstructed and Git-blob verified test surface:

- `26/26` `src/dncrypt/*.py` blobs exact;
- `18/18` test files exact;
- `6/6` tool/runner files exact;
- `4/4` directly referenced native/registry support artifacts exact;
- `pyproject.toml` exact;
- total manifest entries: `55`;
- manifest commitment: `6aeeb79d970d9376a48aa322fdfef954d1bfe8e5920ee6ecbaecb046dcc512d2`.

Execution result:

- `python -m compileall -q src tools tests` → `PASS`;
- complete pytest collection: `90` tests across `18` test files;
- `python -m pytest -q` → `90/90 PASS`.

The exact blob list is committed as `evidence/DNCRYPT_V0_5_EXACT_REPLAY_MANIFEST.json`.

## CI boundary

GitHub Actions remains separate from the local exact replay. Run `33191091017` created Python 3.10/3.12 jobs but executed no workflow steps. GitHub account notices show the current billing cycle reached both `2,000 / 2,000` included Actions minutes and `0.5 / 0.5 GB` included Actions storage, with both scheduled to reset on 1 September 2026. The account budget setting has not been independently verified.

Therefore CI remains classified `CI_INFRA_BLOCKED_BEFORE_RUNNER`, not as a code-test failure.

## Version dependency

`v0.5 = MODEL_CLOSED_EXACT_LOCAL`

`v0.5 main/release promotion = BLOCKED_BY_RELEASE_CI`

`v0.6 PNFS/PNH5 persistent security state = CANDIDATE_STACK_ALLOWED`

`v0.6 release promotion = BLOCKED until its own evidence gates and the applicable release gate close.`

Durable PNFS/PNH5 implementations remain retained external projects. The DNCrypt v0.6 layer may define DNCrypt-specific persistence contracts/adapters, but the retained PNFS/PNH5 repositories, formats, general-purpose implementations and independent development rights remain outside the DNCrypt transaction boundary.

No merge to `main` is requested.
