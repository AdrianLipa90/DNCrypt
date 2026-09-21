from __future__ import annotations

from dataclasses import asdict

import pytest

from dncrypt.crypto import DNCryptEnvelope, decrypt, encrypt, encrypt_deterministic_for_test
from dncrypt.genome import initial_genome
from dncrypt.surface import initial_surface
from dncrypt.util import blake2b256, canonical_json_bytes, sha3_256


def _fixture():
    master = bytes(range(32))
    genome = initial_genome(bytes(range(64)))
    surface = initial_surface(genome)
    return master, genome, surface


def _retag(envelope: DNCryptEnvelope, **changes: object) -> DNCryptEnvelope:
    payload = asdict(envelope)
    payload.update(changes)
    payload.pop("receipt_blake2b")
    payload.pop("receipt_sha3_256")
    raw = canonical_json_bytes(payload)
    return DNCryptEnvelope(
        **payload,
        receipt_blake2b=blake2b256(raw),
        receipt_sha3_256=sha3_256(raw),
    )


def test_production_encrypt_rejects_entropy_injection():
    master, genome, surface = _fixture()
    with pytest.raises(TypeError):
        encrypt(master, b"x", genome, surface, entropy=b"x" * 44)


def test_production_encrypt_uses_fresh_entropy():
    master, genome, surface = _fixture()
    first = encrypt(master, b"same", genome, surface)
    second = encrypt(master, b"same", genome, surface)
    assert first.salt_b64 != second.salt_b64 or first.nonce_b64 != second.nonce_b64
    assert first.entropy_commitment_blake2b != second.entropy_commitment_blake2b


def test_explicit_test_helper_is_reproducible():
    master, genome, surface = _fixture()
    entropy = bytes(range(44))
    first = encrypt_deterministic_for_test(
        master, b"same", genome, surface, entropy=entropy, user_aad=b"fixture"
    )
    second = encrypt_deterministic_for_test(
        master, b"same", genome, surface, entropy=entropy, user_aad=b"fixture"
    )
    assert first == second
    assert decrypt(master, first, genome, surface) == b"same"


def test_parent_receipt_retag_cannot_escape_authenticated_aad_binding():
    master, genome, surface = _fixture()
    env = encrypt_deterministic_for_test(
        master,
        b"payload",
        genome,
        surface,
        entropy=bytes(range(44)),
        parent_receipt="parent:a",
        user_aad=b"meta",
    )
    forged = _retag(env, parent_receipt="parent:b")
    assert forged.verify_receipt()
    with pytest.raises(ValueError, match="authenticated AAD binding mismatch: parent_receipt"):
        decrypt(master, forged, genome, surface)


def test_entropy_commitment_retag_fails_closed():
    master, genome, surface = _fixture()
    env = encrypt_deterministic_for_test(
        master, b"payload", genome, surface, entropy=bytes(range(44))
    )
    forged = _retag(env, entropy_commitment_blake2b="0" * 64)
    assert forged.verify_receipt()
    with pytest.raises(ValueError, match="entropy commitment mismatch"):
        decrypt(master, forged, genome, surface)
