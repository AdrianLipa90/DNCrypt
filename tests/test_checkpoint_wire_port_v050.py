import json
from pathlib import Path

import pytest

from dncrypt.checkpoint_port import create_checkpoint
from dncrypt.checkpoint_wire_port import (
    InMemoryCheckpointWireStore,
    load_checkpoint_wire,
    persist_checkpoint_wire,
)
from dncrypt.genome import initial_genome
from dncrypt.state import DNCryptState
from dncrypt.surface import initial_surface


def _checkpoint():
    genome = initial_genome(bytes(range(64)))
    state = DNCryptState(genome, initial_surface(genome), "r0", "e0")
    return create_checkpoint(state, reason="wire-port-test")


def test_byte_only_wire_port_roundtrip_and_idempotence():
    checkpoint = _checkpoint()
    store = InMemoryCheckpointWireStore()
    first = persist_checkpoint_wire(store, checkpoint)
    second = persist_checkpoint_wire(store, checkpoint)
    assert first == second
    assert first.readback_verified
    assert first.checkpoint_id == checkpoint.checkpoint_id
    assert load_checkpoint_wire(store, checkpoint.checkpoint_id) == checkpoint


def test_external_port_receives_only_string_key_and_bytes():
    checkpoint = _checkpoint()
    calls = []
    class SpyPort:
        def __init__(self):
            self.payload = None
        def put(self, checkpoint_id, payload):
            assert isinstance(checkpoint_id, str)
            assert isinstance(payload, bytes)
            calls.append((checkpoint_id, payload))
            self.payload = payload
        def get(self, checkpoint_id):
            assert isinstance(checkpoint_id, str)
            return self.payload
    receipt = persist_checkpoint_wire(SpyPort(), checkpoint)
    assert receipt.readback_verified
    assert len(calls) == 1


def test_corrupted_backend_readback_is_rejected():
    checkpoint = _checkpoint()
    class CorruptPort:
        def put(self, checkpoint_id, payload):
            self.payload = payload[:-1] + bytes([payload[-1] ^ 1])
        def get(self, checkpoint_id):
            return self.payload
    with pytest.raises(ValueError, match="invalid checkpoint wire payload|wire"):
        persist_checkpoint_wire(CorruptPort(), checkpoint)


def test_wire_store_rejects_same_key_with_different_bytes():
    checkpoint = _checkpoint()
    store = InMemoryCheckpointWireStore()
    receipt = persist_checkpoint_wire(store, checkpoint)
    with pytest.raises(ValueError, match="key collision"):
        store.put(receipt.checkpoint_id, b"different")


def test_retained_wire_spec_defines_byte_only_storage_port():
    spec_path = Path(__file__).parents[1] / "protocols" / "DNCRYPT_CHECKPOINT_WIRE_V0_1.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    contract = spec["storage_port_contract"]
    assert "payload: bytes" in contract["put"]
    assert contract["get"].endswith("-> bytes")
    assert "no DNCrypt class import required" in contract["backend_dependency"]
