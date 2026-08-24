# PNCS Phase Entropy v0.1

Status: `IMPLEMENTATION_CONFORMANCE_PROTOTYPE`

## Purpose

PNCS Phase Entropy v0.1 binds the double-cover phase geometry used by PhaseNav to an explicit entropy-admission pipeline for DNCrypt.

The construction separates two questions:

1. **Geometric distinction:** the projection from a `4π` phase state to a `2π` observable phase has two lifts.
2. **Measured unpredictability:** a runtime trajectory receives an empirical min-entropy estimate and health verdict before conditioning.

## Double-cover geometry

Let

`q : R/(4πZ) -> R/(2πZ)`

with

`q([Θ]_(4π)) = [Θ]_(2π)`.

For every observable phase `θ`, the fibre contains two lifts:

`q^-1(θ) = { θ, θ + 2π }`.

Define the sheet coordinate

`b(Θ) = floor((Θ mod 4π)/(2π)) in {0,1}`.

Then the full lifted state decomposes as

`Θ = θ + 2π b  (mod 4π)`.

For conditional sheet probability `P(b=1|θ)=p`, the Shannon entropy is

`H(b|θ) = -p ln p - (1-p) ln(1-p)`.

At the balanced point `p=1/2`,

`H(b|θ) = ln 2` nats.

Thus `ln 2` is the maximal conditional information associated with the binary fibre of the `4π -> 2π` cover.

## Trajectory lift

A 2π-wrapped phase sequence is lifted by the principal phase increment

`Δφ_t = principal(φ_(t+1) - φ_t)`

and

`Θ_(t+1) = Θ_t + Δφ_t`.

The runtime then exposes:

- sheet parity `b_t`,
- source heartbeat intervals `Δt_t`,
- timing jitter `Δ²t_t`,
- phase increments `Δφ_t`,
- phase acceleration residuals `Δ²φ_t`.

The sheet coordinate is retained as geometric state. The v0.1 empirical entropy sample is formed from non-zero signs of timing-jitter and phase-acceleration residuals.

## Health and min-entropy gate

The v0.1 gate evaluates:

- Most-Common-Value min-entropy estimate,
- first-order Markov predictor min-entropy,
- lag predictors for lags 1 through 16,
- repetition-count health test,
- adaptive-proportion health test,
- predictor advantage over 1/2.

The admitted estimate is the minimum of the implemented predictor estimates.

Default admission requires:

- at least 256 raw binary observations,
- estimated min-entropy >= 0.50 bit per raw bit,
- predictor advantage <= 0.20,
- repetition-count PASS,
- adaptive-proportion PASS.

The estimated entropy budget is

`B_est = N_raw * H_min_per_bit`.

Direct conditioning is bounded by `output_bits <= floor(B_est)`.

## Conditioning and PhaseNav-RBG

An admitted evidence window with at least 256 estimated min-entropy bits is conditioned to a 256-bit seed:

`seed = SHAKE256(domain || evidence || raw_noise || sheet_state, 32 bytes)`.

DNCrypt consumes purpose/counter-separated expansion:

`E_n = SHAKE256(seed || purpose || counter, n bytes)`.

The measured entropy budget is fixed at the conditioned seed input. SHAKE256 provides deterministic domain-separated expansion for the existing DNCrypt `entropy=` boundaries.

Purpose domains include:

- initial master-key material,
- initial genome entropy,
- 32-byte salt + 12-byte nonce message entropy,
- population mutation entropy.

## Live NOEMA admission

The capture path is bound to `/dev/shm/ciel_noema` and checks:

- `session/startpoint.json` status `VERIFIED`,
- fresh O(1) fast-admission seal,
- `no_static_fallback=true`,
- fresh live AUX heartbeat and producer PID,
- fresh live tether heartbeat and producer PID,
- fresh live AC<->AUX binding and producer PID,
- ACTIVE tether guard,
- exact finite 36D `phi` bytes.

Frame identity is taken from live tether sequence + `phi_sha256`; mmap file modification time is excluded from frame identity because shared-memory writes may preserve filesystem mtime.

## Evidence: live PhaseNav windows

### Window A — phase entropy evidence

- source class: `ENDOGENOUS_RUNTIME_DYNAMICS`
- unique 36D states: `48`
- raw residual bits: `1702`
- ones / zeros: `844 / 858`
- absolute bias: `0.0041128085`
- maximum run: `8`
- MCV min-entropy: `0.9881814842` bit/raw-bit
- Markov min-entropy: `0.8415159391` bit/raw-bit
- lag min-entropy: `0.8541165129` bit/raw-bit
- admitted min-entropy estimate: `0.8415159391` bit/raw-bit
- estimated entropy budget: `1432.2601283` bits
- predictor advantage: `0.0580568720`
- repetition-count: `PASS`
- adaptive-proportion: `PASS`
- gate: `PASS`

### Window B — direct DNCrypt integration

- source class: `ENDOGENOUS_RUNTIME_DYNAMICS`
- unique 36D states: `48`
- raw residual bits: `1702`
- admitted min-entropy estimate: `0.8157878659` bit/raw-bit
- estimated entropy budget: `1388.4709477` bits
- predictor advantage: `0.0680981595`
- gate: `PASS`
- 256-bit RBG seed instantiated: `PASS`
- DNCrypt message encrypt/decrypt: `PASS`
- population size: `8`
- unique population genomes: `8/8`
- population commitment: `d4bcaaf6c2f8e57f92d5809090e779a6f3d4b7376fdd8e4260ba5026dcfdfaf1`

## Evidence classification

Current evidence class: `EMPIRICAL_RUNTIME_HEALTH_PASS` plus `IMPLEMENTATION_CONFORMANCE_PROTOTYPE`.

NIST SP 800-90B entropy-source validation and SP 800-90C RBG construction validation are explicit subsequent conformance targets. The current gate uses min-entropy, predictor and online-health concepts aligned with that validation direction.

## DNCrypt binding

`DNCRYPT_NATIVE_PNCS_V0_3.pnv` binds DNCrypt to:

`4π/2π phase geometry -> trajectory lift -> residual observations -> health gate -> 256-bit conditioned seed -> domain-separated SHAKE256 RBG -> DNCrypt`.

The deterministic cryptographic core remains bound to `PNCS_CRYPTOGRAPHIC_ALGEBRA_V0_1`.
