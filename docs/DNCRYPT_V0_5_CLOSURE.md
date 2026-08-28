# DNCrypt v0.5 Closure — State Memory + Exact Rollback

## Closure status

`MODEL_CLOSED_LOCAL / RELEASE_CI_BLOCKED_INFRA_BEFORE_RUNNER`

DNCrypt v0.5 closes the logical State Memory and exact rollback model on the feature branch. Promotion to `main` remains blocked.

## Closed model gates

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

Local exact-branch evidence: `52/52 pytest PASS` and `compileall PASS`.

Canonical v0.5 model receipt: `cc4c457b16bcd80ba735bac1191508d03b9cc64bae5aa4a3a60bce1b12350caf`.

## Release boundary

The latest observed GitHub Actions jobs terminate before runner steps execute. This remains `CI_INFRA_BLOCKED_BEFORE_RUNNER`; it is kept separate from local code/test evidence.

## Next frontier

v0.6 may open as a stacked candidate for persistent security state. Durable PNFS/PNH5 implementations remain retained external projects. DNCrypt v0.6 should expose portable, byte-oriented persistent-state contracts and bundles; retained-project adapters implement those contracts independently.

No merge to `main` is requested by this closure.
