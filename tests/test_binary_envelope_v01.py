from __future__ import annotations

import pytest

from dncrypt import decrypt, encrypt, initial_genome, initial_surface
from dncrypt.binary_envelope import MAGIC, binary_envelope_id, pack_envelope, unpack_envelope

MASTER = bytes(range(32))
GENOME_ENTROPY = bytes(range(64))
MESSAGE_ENTROPY = bytes(range(44))
AAD = b'{"object_id":"pnv:test","generation":7,"paux_profile":"PAUX-EXACT"}'


def _envelope(payload: bytes = b"x" * 576, *, parent: str | None = None):
    genome = initial_genome(GENOME_ENTROPY)
    surface = initial_surface(genome)
    env = encrypt(MASTER, payload, genome, surface, user_aad=AAD, parent_receipt=parent, entropy=MESSAGE_ENTROPY)
    return genome, surface, env


def test_binary_roundtrip_preserves_canonical_envelope_bytes_and_receipt():
    genome, surface, env = _envelope()
    raw = pack_envelope(env)
    restored = unpack_envelope(raw)
    assert raw.startswith(MAGIC)
    assert restored == env
    assert restored.to_bytes() == env.to_bytes()
    assert restored.verify_receipt()
    assert decrypt(MASTER, restored, genome, surface) == b"x" * 576


def test_binary_roundtrip_preserves_optional_parent_receipt():
    _, _, env = _envelope(parent="parent:receipt:example")
    restored = unpack_envelope(pack_envelope(env))
    assert restored.parent_receipt == "parent:receipt:example"
    assert restored.to_bytes() == env.to_bytes()


def test_binary_representation_is_smaller_than_canonical_json_for_36d_payload():
    _, _, env = _envelope(b"v" * 288)
    assert len(pack_envelope(env)) < len(env.to_bytes())


def test_binary_envelope_id_is_content_addressed_and_deterministic():
    _, _, env = _envelope()
    raw = pack_envelope(env)
    assert binary_envelope_id(raw) == binary_envelope_id(raw)
    assert binary_envelope_id(env) == binary_envelope_id(raw)
    assert binary_envelope_id(raw).startswith("dncrypt:binary-envelope:sha256:")


def test_tamper_is_rejected_by_reconstructed_receipt():
    _, _, env = _envelope()
    raw = bytearray(pack_envelope(env))
    raw[-1] ^= 1
    with pytest.raises(ValueError, match="invalid provenance receipt"):
        unpack_envelope(raw)


def test_truncation_and_trailing_data_fail_closed():
    _, _, env = _envelope()
    raw = pack_envelope(env)
    with pytest.raises(ValueError):
        unpack_envelope(raw[:-1])
    with pytest.raises(ValueError, match="length mismatch"):
        unpack_envelope(raw + b"x")


def test_wrong_magic_fails_closed():
    _, _, env = _envelope()
    raw = bytearray(pack_envelope(env))
    raw[0:4] = b"NOPE"
    with pytest.raises(ValueError, match="magic"):
        unpack_envelope(raw)
