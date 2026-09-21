from __future__ import annotations

import pytest
from hypothesis import given, settings, strategies as st

from dncrypt.binary_envelope import pack_envelope, unpack_envelope
from dncrypt.checkpoint_port import create_checkpoint
from dncrypt.checkpoint_wire import MAX_WIRE_BYTES, decode_checkpoint, encode_checkpoint
from dncrypt.crypto import encrypt_deterministic_for_test
from dncrypt.genome import initial_genome
from dncrypt.state import DNCryptState
from dncrypt.surface import initial_surface


def _checkpoint_bytes() -> bytes:
    genome = initial_genome(bytes(range(64)))
    state = DNCryptState(genome, initial_surface(genome), "m", "e")
    return encode_checkpoint(create_checkpoint(state, reason="fuzz-fixture"))


def _binary_envelope_bytes() -> bytes:
    genome = initial_genome(bytes(range(64)))
    surface = initial_surface(genome)
    envelope = encrypt_deterministic_for_test(
        bytes(range(32)),
        b"fuzz-fixture-payload",
        genome,
        surface,
        entropy=bytes(range(44)),
        user_aad=b"fuzz-aad",
    )
    return pack_envelope(envelope)


@settings(max_examples=250, deadline=None)
@given(st.binary(max_size=4096))
def test_checkpoint_wire_arbitrary_bytes_fail_only_through_public_error_surface(raw: bytes):
    try:
        checkpoint = decode_checkpoint(raw)
    except (ValueError, TypeError):
        return
    checkpoint.verify()
    assert encode_checkpoint(checkpoint) == raw


@settings(max_examples=250, deadline=None)
@given(st.binary(max_size=4096))
def test_binary_envelope_arbitrary_bytes_fail_only_through_public_error_surface(raw: bytes):
    try:
        envelope = unpack_envelope(raw)
    except (ValueError, TypeError):
        return
    assert envelope.verify_receipt()
    assert pack_envelope(envelope) == raw


@settings(max_examples=150, deadline=None)
@given(
    st.integers(min_value=0, max_value=len(_checkpoint_bytes()) - 1),
    st.integers(min_value=0, max_value=7),
)
def test_single_bit_checkpoint_mutation_never_silently_roundtrips(index: int, bit: int):
    raw = bytearray(_checkpoint_bytes())
    raw[index] ^= 1 << bit
    with pytest.raises((ValueError, TypeError)):
        decode_checkpoint(bytes(raw))


@settings(max_examples=150, deadline=None)
@given(
    st.integers(min_value=0, max_value=len(_binary_envelope_bytes()) - 1),
    st.integers(min_value=0, max_value=7),
)
def test_single_bit_binary_envelope_mutation_never_silently_roundtrips(index: int, bit: int):
    raw = bytearray(_binary_envelope_bytes())
    raw[index] ^= 1 << bit
    with pytest.raises((ValueError, TypeError)):
        unpack_envelope(bytes(raw))


def test_checkpoint_wire_rejects_oversized_input_before_json_decode():
    with pytest.raises(ValueError, match="bounded codec limit"):
        decode_checkpoint(b"x" * (MAX_WIRE_BYTES + 1))
