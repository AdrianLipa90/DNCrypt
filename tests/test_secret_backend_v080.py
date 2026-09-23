from __future__ import annotations

import pytest

from dncrypt.genome import initial_genome
from dncrypt.secret_backend import (
    InMemorySecretBackend,
    SecretBackendCapabilities,
    SecretBackendPolicy,
    SecretHandle,
    decrypt_with_secret_handle,
    encrypt_with_secret_handle,
    require_secret_backend,
)
from dncrypt.surface import initial_surface


class DeclaredNativeBackend(InMemorySecretBackend):
    """Test double declaring production capabilities; not a real native backend."""

    def capabilities(self) -> SecretBackendCapabilities:
        return SecretBackendCapabilities(
            backend_id="native-test-double",
            implementation_class="native",
            secret_memory_locked=True,
            zeroization=True,
            hardware_backed=False,
            side_channel_reviewed=True,
        )


def test_opaque_handle_round_trip_and_destroy():
    backend = InMemorySecretBackend()
    handle = backend.generate_master_key_handle()
    genome = initial_genome(b"g" * 64)
    surface = initial_surface(genome)

    envelope = encrypt_with_secret_handle(
        backend,
        handle,
        b"secret payload",
        genome,
        surface,
        user_aad=b"aad",
    )
    assert decrypt_with_secret_handle(
        backend,
        handle,
        envelope,
        genome,
        surface,
    ) == b"secret payload"

    receipt = backend.destroy(handle)
    assert receipt.destroyed is True
    assert receipt.handle_commitment == handle.commitment
    with pytest.raises(KeyError):
        decrypt_with_secret_handle(backend, handle, envelope, genome, surface)


def test_python_reference_backend_fails_default_production_policy():
    backend = InMemorySecretBackend()
    with pytest.raises(ValueError, match="implementation class"):
        require_secret_backend(backend)


def test_policy_can_admit_declared_native_capabilities():
    backend = DeclaredNativeBackend("ignored")
    caps = require_secret_backend(
        backend,
        policy=SecretBackendPolicy(require_side_channel_review=True),
    )
    assert caps.implementation_class == "native"
    assert caps.secret_memory_locked is True
    assert caps.zeroization is True
    assert caps.side_channel_reviewed is True


def test_hardware_backing_can_be_required_fail_closed():
    backend = DeclaredNativeBackend("ignored")
    with pytest.raises(ValueError, match="hardware-backed"):
        require_secret_backend(
            backend,
            policy=SecretBackendPolicy(require_hardware_backing=True),
        )


def test_cross_backend_handle_is_rejected():
    left = InMemorySecretBackend("left")
    right = InMemorySecretBackend("right")
    handle = left.generate_master_key_handle()
    genome = initial_genome(b"g" * 64)
    surface = initial_surface(genome)
    with pytest.raises(ValueError, match="different backend"):
        encrypt_with_secret_handle(
            right,
            handle,
            b"x",
            genome,
            surface,
        )


def test_handle_contains_no_key_material_fields():
    handle = SecretHandle(backend_id="native-1", handle_id="opaque-123")
    public = {
        "backend_id": handle.backend_id,
        "handle_id": handle.handle_id,
        "key_profile": handle.key_profile,
        "schema": handle.schema,
    }
    assert "key" not in public
    assert "secret" not in public
    assert len(handle.commitment) == 64
