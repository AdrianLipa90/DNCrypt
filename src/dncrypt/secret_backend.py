"""Opaque secret-backend boundary for DNCrypt v0.8.

The Python orchestration layer receives only opaque handles. A production backend
must generate and retain master-key material outside ordinary Python object
memory and perform DNCrypt v0.2 AEAD operations behind this boundary.

The in-memory backend in this module is a conformance fixture only.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import secrets
from typing import Protocol

from .crypto import DNCryptEnvelope, decrypt, encrypt, generate_master_key
from .genome import CipherGenome
from .surface import CipherSurface
from .util import blake2b256, canonical_json_bytes

SECRET_BACKEND_SCHEMA = "dncrypt.secret-backend/v0.8-candidate"
SECRET_HANDLE_SCHEMA = "dncrypt.secret-handle/v0.8-candidate"
SECRET_DESTRUCTION_SCHEMA = "dncrypt.secret-destruction/v0.8-candidate"
MASTER_KEY_PROFILE = "DNCrypt/v0.2-master-key-256"


@dataclass(frozen=True, slots=True)
class SecretBackendCapabilities:
    backend_id: str
    implementation_class: str
    secret_memory_locked: bool
    zeroization: bool
    hardware_backed: bool
    side_channel_reviewed: bool
    schema: str = SECRET_BACKEND_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SECRET_BACKEND_SCHEMA:
            raise ValueError("unsupported secret-backend capability schema")
        if not self.backend_id.strip() or not self.implementation_class.strip():
            raise ValueError("backend_id/implementation_class must not be empty")

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))


@dataclass(frozen=True, slots=True)
class SecretBackendPolicy:
    require_locked_memory: bool = True
    require_zeroization: bool = True
    require_hardware_backing: bool = False
    require_side_channel_review: bool = False
    allowed_implementation_classes: tuple[str, ...] = (
        "native",
        "hsm",
        "tpm",
        "remote-hsm",
    )

    def admit(self, capabilities: SecretBackendCapabilities) -> bool:
        if capabilities.implementation_class not in self.allowed_implementation_classes:
            raise ValueError("secret backend implementation class is not admitted")
        if self.require_locked_memory and not capabilities.secret_memory_locked:
            raise ValueError("secret backend does not guarantee locked secret memory")
        if self.require_zeroization and not capabilities.zeroization:
            raise ValueError("secret backend does not guarantee zeroization")
        if self.require_hardware_backing and not capabilities.hardware_backed:
            raise ValueError("secret backend is not hardware-backed")
        if self.require_side_channel_review and not capabilities.side_channel_reviewed:
            raise ValueError("secret backend lacks required side-channel review")
        return True


@dataclass(frozen=True, slots=True)
class SecretHandle:
    backend_id: str
    handle_id: str
    key_profile: str = MASTER_KEY_PROFILE
    schema: str = SECRET_HANDLE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SECRET_HANDLE_SCHEMA:
            raise ValueError("unsupported secret-handle schema")
        if not self.backend_id.strip() or not self.handle_id.strip():
            raise ValueError("backend_id/handle_id must not be empty")
        if self.key_profile != MASTER_KEY_PROFILE:
            raise ValueError("unsupported DNCrypt secret key profile")

    @property
    def commitment(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))


@dataclass(frozen=True, slots=True)
class SecretDestructionReceipt:
    backend_id: str
    handle_commitment: str
    destroyed: bool
    schema: str = SECRET_DESTRUCTION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SECRET_DESTRUCTION_SCHEMA:
            raise ValueError("unsupported secret-destruction schema")
        if len(self.handle_commitment) != 64:
            raise ValueError("handle_commitment must be a 32-byte hex digest")
        try:
            int(self.handle_commitment, 16)
        except ValueError as exc:
            raise ValueError("handle_commitment must be hexadecimal") from exc
        if self.destroyed is not True:
            raise ValueError("destruction receipt must confirm destroyed=True")

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))


class SecretBackendPort(Protocol):
    def capabilities(self) -> SecretBackendCapabilities: ...

    def generate_master_key_handle(self) -> SecretHandle:
        """Generate a new master key inside the backend and return only a handle."""
        ...

    def encrypt(
        self,
        handle: SecretHandle,
        plaintext: bytes,
        genome: CipherGenome,
        surface: CipherSurface,
        *,
        user_aad: bytes = b"",
        parent_receipt: str | None = None,
    ) -> DNCryptEnvelope: ...

    def decrypt(
        self,
        handle: SecretHandle,
        envelope: DNCryptEnvelope,
        genome: CipherGenome,
        surface: CipherSurface,
    ) -> bytes: ...

    def destroy(self, handle: SecretHandle) -> SecretDestructionReceipt: ...


def require_secret_backend(
    backend: SecretBackendPort,
    *,
    policy: SecretBackendPolicy = SecretBackendPolicy(),
) -> SecretBackendCapabilities:
    capabilities = backend.capabilities()
    policy.admit(capabilities)
    return capabilities


def _verify_handle_backend(
    backend: SecretBackendPort,
    handle: SecretHandle,
) -> SecretBackendCapabilities:
    capabilities = backend.capabilities()
    if handle.backend_id != capabilities.backend_id:
        raise ValueError("secret handle belongs to a different backend")
    return capabilities


def encrypt_with_secret_handle(
    backend: SecretBackendPort,
    handle: SecretHandle,
    plaintext: bytes,
    genome: CipherGenome,
    surface: CipherSurface,
    *,
    user_aad: bytes = b"",
    parent_receipt: str | None = None,
) -> DNCryptEnvelope:
    _verify_handle_backend(backend, handle)
    envelope = backend.encrypt(
        handle,
        bytes(plaintext),
        genome,
        surface,
        user_aad=bytes(user_aad),
        parent_receipt=parent_receipt,
    )
    if not isinstance(envelope, DNCryptEnvelope) or not envelope.verify_receipt():
        raise ValueError("secret backend returned an invalid DNCrypt envelope")
    return envelope


def decrypt_with_secret_handle(
    backend: SecretBackendPort,
    handle: SecretHandle,
    envelope: DNCryptEnvelope,
    genome: CipherGenome,
    surface: CipherSurface,
) -> bytes:
    _verify_handle_backend(backend, handle)
    return bytes(backend.decrypt(handle, envelope, genome, surface))


class InMemorySecretBackend:
    """Python conformance fixture. Explicitly not production secret isolation."""

    def __init__(self, backend_id: str = "python-test-secret-backend") -> None:
        self._backend_id = backend_id
        self._keys: dict[str, bytearray] = {}

    def capabilities(self) -> SecretBackendCapabilities:
        return SecretBackendCapabilities(
            backend_id=self._backend_id,
            implementation_class="python-test-only",
            secret_memory_locked=False,
            zeroization=False,
            hardware_backed=False,
            side_channel_reviewed=False,
        )

    def _key(self, handle: SecretHandle) -> bytes:
        if handle.backend_id != self._backend_id:
            raise ValueError("secret handle belongs to a different backend")
        try:
            material = self._keys[handle.handle_id]
        except KeyError as exc:
            raise KeyError("secret handle is unknown or destroyed") from exc
        return bytes(material)

    def generate_master_key_handle(self) -> SecretHandle:
        handle_id = secrets.token_hex(24)
        self._keys[handle_id] = bytearray(generate_master_key())
        return SecretHandle(backend_id=self._backend_id, handle_id=handle_id)

    def encrypt(
        self,
        handle: SecretHandle,
        plaintext: bytes,
        genome: CipherGenome,
        surface: CipherSurface,
        *,
        user_aad: bytes = b"",
        parent_receipt: str | None = None,
    ) -> DNCryptEnvelope:
        return encrypt(
            self._key(handle),
            plaintext,
            genome,
            surface,
            user_aad=user_aad,
            parent_receipt=parent_receipt,
        )

    def decrypt(
        self,
        handle: SecretHandle,
        envelope: DNCryptEnvelope,
        genome: CipherGenome,
        surface: CipherSurface,
    ) -> bytes:
        return decrypt(self._key(handle), envelope, genome, surface)

    def destroy(self, handle: SecretHandle) -> SecretDestructionReceipt:
        if handle.backend_id != self._backend_id:
            raise ValueError("secret handle belongs to a different backend")
        try:
            material = self._keys.pop(handle.handle_id)
        except KeyError as exc:
            raise KeyError("secret handle is unknown or already destroyed") from exc
        for index in range(len(material)):
            material[index] = 0
        return SecretDestructionReceipt(
            backend_id=self._backend_id,
            handle_commitment=handle.commitment,
            destroyed=True,
        )


__all__ = [
    "MASTER_KEY_PROFILE",
    "SECRET_BACKEND_SCHEMA",
    "SECRET_DESTRUCTION_SCHEMA",
    "SECRET_HANDLE_SCHEMA",
    "InMemorySecretBackend",
    "SecretBackendCapabilities",
    "SecretBackendPolicy",
    "SecretBackendPort",
    "SecretDestructionReceipt",
    "SecretHandle",
    "decrypt_with_secret_handle",
    "encrypt_with_secret_handle",
    "require_secret_backend",
]
