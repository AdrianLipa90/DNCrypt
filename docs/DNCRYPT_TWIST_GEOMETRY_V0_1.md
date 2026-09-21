# DNCrypt Twist Geometry v0.1

Status: `EXPERIMENTAL_DIAGNOSTIC_ONLY / NO_SECURITY_ADMISSION`

## Origin of the gate

Inspection of the earlier CIEL-T36 hash prototype exposed a specific structural limitation that matches the current chemistry/spectroscopy work.

The legacy CIEL-T36 phase schedule has the form

\[
\phi_i(k)=\phi_i^{(0)}+\Delta(k) \pmod{2\pi},
\]

because the `q_k mod 5` term adds the same phase offset to every one of the 36 coordinates. Consequently, corresponding-coordinate comparisons between many nominally different phase slices contain only a common global rotation. In a direct audit over the first 40 identifiers, the legacy generator produced only five distinct slice patterns and the 36D order-parameter magnitude was constant.

The missing operation is not another absolute phase. It is a **relative twist between slices**.

## v0.1 definition

For two 36D phase slices \(A\) and \(B\), and a declared permutation \(\sigma\), define

\[
\delta_i=\operatorname{wrap}\!\left(B_{\sigma(i)}-A_i\right).
\]

A common global rephasing

\[
A_i\to A_i+\alpha,\qquad B_i\to B_i+\alpha
\]

cancels from \(\delta_i\). The first cross-order parameter is

\[
Z_1=\frac1{36}\sum_i e^{i\delta_i},
\qquad
R_1=|Z_1|.
\]

DNCrypt v0.1 reports

\[
\nu=1-R_1
\]

as **relational novelty**. A pure common rotation has \(\nu=0\). A coordinate twist of a nonuniform slice generally has \(\nu>0\).

Higher harmonic magnitudes \(|Z_m|\), residual RMS after removing the best common rotation, and cyclic gradient RMS are retained as additional diagnostics.

## Why this belongs in DNCrypt

The existing genome already contains:

- a 36D operator vector;
- a 36D phase seed;
- a permutation route;
- a persistent 36D phase surface.

The current causality firewall correctly prevents descriptive statistics from driving security promotion without a mechanism and falsification test. Twist geometry therefore enters first as a diagnostic of **relational diversity**, not as a new cryptographic primitive and not as a reason to alter ChaCha20-Poly1305 or HKDF-SHA3-512.

The immediate use is to distinguish:

- raw byte/genome differences;
- pure common rotations of a phase slice;
- genuine changes in relative 36D geometry.

This is the cryptographic analogue of the spectroscopy lesson: the observable structure can live in the relation between representations rather than in either representation separately.

## Next gate

1. Measure twist signatures across deterministic mutation populations.
2. Quantify whether nominal genome diversity collapses into repeated relational classes.
3. Add a sealed benchmark comparing byte diversity with relational diversity.
4. Only if a genome-controlled mechanism changes an attack observable may any twist-derived quantity be considered for `ADMISSION` under the existing causality firewall.

No security advantage is claimed by v0.1.
