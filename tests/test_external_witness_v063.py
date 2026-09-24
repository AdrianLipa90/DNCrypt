from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dncrypt.external_witness import (
    InMemorySignedWitnessService,
    RemoteSignedUnifiedAnchorPort,
    SignedWitnessRecord,
    WitnessAdvanceRequest,
)
from dncrypt.unified_checkpoint import UnifiedMonotonicAnchor


def d(ch: str) -> str:
    return ch * 64


def anchor(counter: int, previous: str | None) -> UnifiedMonotonicAnchor:
    digit = format((counter % 15) + 1, "x")
    return UnifiedMonotonicAnchor(
        counter=counter,
        journal_receipt_digest=d(digit),
        event_count=counter + 1,
        head_event_id=d("a"),
        active_checkpoint_id=d("b"),
        active_state_commitment=d("c"),
        active_pdna_id=d("d"),
        previous_anchor_digest=previous,
    )


def make_port():
    private = Ed25519PrivateKey.generate()
    service = InMemorySignedWitnessService(
        private_key=private,
        witness_id="witness-A",
        public_key_id="ed25519-A",
    )
    port = RemoteSignedUnifiedAnchorPort(
        transport=service,
        public_key=private.public_key(),
        witness_id="witness-A",
        public_key_id="ed25519-A",
    )
    return private, service, port


def test_signed_external_witness_advances_exactly_once_and_round_trips():
    _, _, port = make_port()
    a0 = anchor(0, None)
    assert port.read() is None
    assert port.compare_and_advance(expected_previous_digest=None, new_anchor=a0) == a0.digest
    assert port.read() == a0

    a1 = anchor(1, a0.digest)
    assert port.compare_and_advance(expected_previous_digest=a0.digest, new_anchor=a1) == a1.digest
    assert port.read() == a1


def test_external_witness_rejects_stale_anchor_cas():
    _, _, port = make_port()
    a0 = anchor(0, None)
    port.compare_and_advance(expected_previous_digest=None, new_anchor=a0)
    a1 = anchor(1, a0.digest)
    with pytest.raises(ValueError, match="compare-and-swap"):
        port.compare_and_advance(expected_previous_digest=None, new_anchor=a1)


def test_witness_record_signature_is_bound_to_anchor():
    private, service, port = make_port()
    a0 = anchor(0, None)
    port.compare_and_advance(expected_previous_digest=None, new_anchor=a0)
    raw = service.read_record()
    assert raw is not None

    value = json.loads(raw)
    value["anchor"]["event_count"] += 1
    tampered = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(ValueError):
        SignedWitnessRecord.from_bytes(tampered, public_key=private.public_key())


def test_wrong_public_key_is_rejected():
    private, service, port = make_port()
    a0 = anchor(0, None)
    port.compare_and_advance(expected_previous_digest=None, new_anchor=a0)
    raw = service.read_record()
    assert raw is not None
    wrong = Ed25519PrivateKey.generate().public_key()
    with pytest.raises(ValueError, match="signature"):
        SignedWitnessRecord.from_bytes(raw, public_key=wrong)


def test_request_is_canonical_and_committed():
    a0 = anchor(0, None)
    req = WitnessAdvanceRequest(
        witness_id="witness-A",
        public_key_id="ed25519-A",
        expected_previous_witness_digest=None,
        expected_previous_anchor_digest=None,
        new_anchor=a0,
    )
    assert WitnessAdvanceRequest.from_bytes(req.to_bytes()) == req
    value = json.loads(req.to_bytes())
    value["request_id"] = d("f")
    tampered = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(ValueError, match="commitment"):
        WitnessAdvanceRequest.from_bytes(tampered)
