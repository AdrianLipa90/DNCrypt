import json
from pathlib import Path

import pytest

from dncrypt.checkpoint_port import create_checkpoint
from dncrypt.checkpoint_wire import decode_checkpoint, encode_checkpoint, wire_commitment
from dncrypt.genome import initial_genome
from dncrypt.state import DNCryptState
from dncrypt.surface import initial_surface


def _checkpoint():
    genome = initial_genome(bytes(range(64)))
    state = DNCryptState(genome, initial_surface(genome), "r0", "e0")
    return create_checkpoint(state, reason="interop-test-vector")


def test_checkpoint_wire_exact_roundtrip():
    checkpoint = _checkpoint()
    payload = encode_checkpoint(checkpoint)
    restored = decode_checkpoint(payload)
    assert restored == checkpoint
    assert encode_checkpoint(restored) == payload
    assert len(wire_commitment(payload)) == 64


def test_checkpoint_wire_detects_identifier_tampering():
    payload = json.loads(encode_checkpoint(_checkpoint()).decode("utf-8"))
    payload["checkpoint_id"] = "0" * 64
    tampered = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(ValueError, match="id mismatch"):
        decode_checkpoint(tampered)


def test_wire_spec_is_retained_shared_interoperability_asset():
    spec_path = Path(__file__).parents[1] / "protocols" / "DNCRYPT_CHECKPOINT_WIRE_V0_1.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    assert spec["governance"] == "RETAINED_SHARED_INTEROPERABILITY_ASSET"
    assert spec["independent_implementation"] == "ALLOWED_BY_TRANSACTION_REQUIREMENT"
