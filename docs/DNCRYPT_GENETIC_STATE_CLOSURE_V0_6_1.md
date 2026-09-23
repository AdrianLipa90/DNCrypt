# DNCrypt Genetic State Closure v0.6.1

Status: **candidate research implementation / no novel security-admission claim**.

## 1. Purpose

v0.6.1 closes the research-level DNCrypt state across four previously separate
lineages:

1. `CipherGenome` evolution;
2. persistent `CipherSurface` time;
3. Genetic IR / `.pdna` lineage;
4. checkpoint / journal / anti-rollback state.

The frozen application-data cryptographic anchor remains DNCrypt v0.2:
ChaCha20-Poly1305, HKDF-SHA3-512, fresh salt and nonce generation are unchanged.

## 2. Genetic dictionary and compiler

`genetic_dictionary_v1()` declares the admitted search-operation vocabulary for
KAKU -> RADICAL -> CONCEPT -> SENTENCE -> PARAGRAPH -> CHAPTER -> BOOK.

`compile_genetic_program(P)` maps a public Genetic IR program to a bounded
mutation phenotype

[
\Theta(P)=(L_P,b_P,s_P,d_P),
]

where:

- (L_P\subseteq\{0,\ldots,35\}) is the admitted genome-locus set;
- (b_P\) is the maximum operator-locus mutation budget;
- (s_P\) is a route stride;
- (d_P\in\{-1,+1\}) is the route direction.

The compiler is deterministic and public. Its output is **not entropy**.

Candidate generation is therefore

[
G_{t+1}=M(G_t,\Theta(P_t),\epsilon_t),
]

with fresh external mutation entropy (epsilon_t) mandatory. Genetic IR never
replaces or supplies master-key, salt, nonce or evaluator-signing entropy.

## 3. Unified logical state

The candidate unified state is

[
X_t=(G_t,S_t,P_t,E_t,D_{t-1}),
]

represented by `UnifiedDNCryptState`.

It binds:

- active genome ID and generation;
- active surface commitment and tick;
- exact Genetic IR semantic ID;
- exact compiler commitment;
- optional evidence commitment;
- parent PDNA commitment.

The cross-plane closure commitment is

[
C_t=H(G_t,S_t,P_t,E_t,D_{t-1},\Theta_t).
]

The current PDNA record includes (C_t), the active surface commitment and
compiler/evidence commitments in canonical metadata. The resulting `pdna_id`
is then included in the unified-state commitment. This ordering avoids a hash
cycle while still forcing all planes to agree.

## 4. Full-state checkpoint and rollback

`UnifiedCheckpoint` commits the complete serialized `UnifiedDNCryptState`,
not only the legacy genome/surface pair.

A unified rollback receipt therefore records the restored:

- state commitment;
- genome ID;
- surface commitment;
- Genetic IR ID;
- PDNA ID.

`UnifiedStateMemoryJournal` maintains an append-only checkpoint/rollback event
chain and rejects rollback receipts whose restored state or PDNA do not match
the recorded target checkpoint.

`UnifiedMonotonicAnchor` extends the external anti-rollback witness with the
active PDNA identity. The in-memory implementation is test-only; durable
production authority still requires an external monotonic store such as an
HSM/TPM-backed or remote append-only service.

## 5. Hierarchical Genetic IR geometry

The original global projection

[
P\mapsto\Phi_P\in T^{36}
]

is preserved for compatibility, but no longer needs to be the only diagnostic
view.

`genetic_phase_tree()` emits one deterministic 36D projection per IR node.
`level_phase_coherence()` computes a local order parameter separately at each
grammar level, and `parent_child_phase_distance()` measures immediate
hierarchical displacement.

These observables are explicitly **diagnostic only**.

## 6. Resource hardening

`bounded_genetic_ir_from_mapping()` performs an iterative preflight before the
recursive typed parser is entered. The default guard limits:

- total nodes;
- total relations;
- maximum nesting depth;
- maximum child fanout;
- total canonical payload bytes.

`PDNARecord.from_bytes()` additionally rejects oversized raw PDNA payloads
before JSON decoding and uses the bounded Genetic IR loader.

## 7. Security invariants

The following are non-negotiable in v0.6.1:

1. Genetic IR is never master-key entropy.
2. Genetic IR is never AEAD salt or nonce entropy.
3. Genetic IR phase values are never security-admission evidence by default.
4. Fresh external mutation entropy is mandatory for every generated genome.
5. The frozen v0.2 AEAD implementation is unchanged.
6. Rollback of the unified candidate state restores crypto and Genetic IR
   together.
7. A PDNA / unified-state mismatch fails closed.
8. Resource-limit violations fail before recursive Genetic IR parsing.
9. Candidate implementation status does not imply improved cryptographic
   security.
10. Independent cryptanalysis remains required before any adaptive mechanism is
    promoted as a security advantage.

## 8. GREMLIN audit mapping

The implementation follows the Library GREMLIN audit result:

- **SPIDER:** close the genome/surface/genetics/checkpoint dependency graph;
- **RAVEN:** preserve the recursive grammar hierarchy rather than flattening it;
- **HOUND:** reject cross-plane state mismatches;
- **MOLE:** define one explicit state commitment and transition boundary;
- **OWL:** keep phase geometry diagnostic and epistemically separated;
- **ANT:** bound mutation and parser combinatorics;
- **MANTIS:** adversarially test drift, rollback and resource-bomb cases;
- **BELZEBUB/GREMLIN:** aggregate only after the above boundaries pass.

## 9. Promotion boundary

This branch is an implementation candidate. It must remain outside `main`
until exact-head CI is green and the project owner explicitly authorizes merge.
