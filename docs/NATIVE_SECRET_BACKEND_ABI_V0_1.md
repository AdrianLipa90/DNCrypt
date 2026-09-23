# DNCrypt Native Secret Backend ABI v0.1

Status: candidate interface contract for v0.8.

## Purpose

The Python control plane MUST receive only opaque `SecretHandle` values. Master-key
material is generated, retained and used inside a native/HSM/TPM-backed provider.

The provider MUST NOT serialize raw master keys into Python, logs, receipts,
checkpoint state, PDNA, Genetic IR, exception strings or telemetry.

## Required operations

1. `capabilities() -> SecretBackendCapabilities`
2. `generate_master_key_handle() -> SecretHandle`
3. `encrypt(handle, plaintext, genome, surface, user_aad, parent_receipt) -> DNCryptEnvelope`
4. `decrypt(handle, envelope, genome, surface) -> plaintext`
5. `destroy(handle) -> SecretDestructionReceipt`

The cryptographic semantics of operations 3 and 4 MUST remain compatible with the
frozen DNCrypt v0.2 envelope/AAD contract unless a future protocol version is
explicitly introduced.

## Production admission

The default Python-side admission policy requires:

- implementation class in `native|hsm|tpm|remote-hsm`;
- locked secret memory;
- explicit zeroization support.

Deployments MAY additionally require hardware backing and an independently
reviewed side-channel posture.

The bundled `InMemorySecretBackend` is a conformance fixture only and MUST NOT
be presented as production secret isolation.

## Native implementation requirements

A native provider SHOULD:

- generate keys using the platform CSPRNG or validated hardware RNG;
- keep secret pages non-pageable where the platform permits;
- avoid copies of secret material and wipe transient buffers;
- use constant-time cryptographic implementations supplied by established
  libraries rather than handwritten primitives;
- isolate handles per backend instance and reject cross-backend handles;
- make handle destruction idempotence/failure semantics explicit;
- never expose secret bytes in debug output, panics, crash reports or metrics;
- bind all public metadata exactly to the DNCrypt v0.2 authenticated AAD schema;
- fail closed on malformed envelopes, stale handles, backend mismatch or
  capability-policy mismatch.

## HSM/TPM profile

A hardware-backed provider may map `handle_id` to a non-exportable key object or
sealed object identifier. DNCrypt does not require the handle identifier itself to
be secret; security depends on the backend refusing unauthorized key use/export.

## Evidence boundary

This ABI creates an isolation boundary. It does not by itself prove resistance to
side channels, memory disclosure, malicious firmware, compromised kernels or HSM
implementation defects. Those claims require implementation-specific evidence.
