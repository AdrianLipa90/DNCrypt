# DNCrypt native adapter for NOEMA Prime-Gap Mutation Codons V6.1

Status: **EXPERIMENTAL / CONFORMANCE GATE / NO SECURITY ADMISSION**.

The adapter consumes the frozen NOEMA V6.1 word envelope. It verifies the complete word hash, exact authority block, 12-group bijection and Z3 phase-triplet closure before invoking DNCrypt v0.6.2 structural Genetic IR operators.

All structural operations are bounded by persistent semantic anchors `r0..r7`. Repeated operators are allowed. Parameters control bounded anchor/cut/tag choices; they never become key, nonce, salt, evaluator credential or entropy.

After all 12 operations the final typed Genetic IR must compile under the existing DNCrypt Genetic compiler. A deterministic test-only mutation may then verify that the resulting phenotype can generate a bounded candidate genome. This is conformance only and has no security-admission authority.

Source binding: NOEMA-Telekom `69b5fbcdcc37094831d04061ea88a876fe6b84af`.