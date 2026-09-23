from __future__ import annotations

from dataclasses import replace
import hashlib

import pytest

from dncrypt.key_establishment import (
    HybridKEMEnvelope,
    X25519KeyEstablishment,
    hybrid_decapsulate,
    hybrid_encapsulate,
)
from dncrypt.util import b64e


class FakeMLKEM:
    """Protocol mock only; deliberately not a cryptographic implementation."""

    algorithm_id = "ML-KEM-768"

    def __init__(self, public_key: bytes) -> None:
        self.public_key = bytes(public_key)

    def encapsulate(self, peer_public_key: bytes) -> tuple[bytes, bytes]:
        peer = bytes(peer_public_key)
        ct = hashlib.sha3_256(b"test-only-ct|" + peer).digest()
        secret = hashlib.sha3_256(b"test-only-ss|" + peer + ct).digest()
        return ct, secret

    def decapsulate(self, ciphertext: bytes) -> bytes:
        ct = bytes(ciphertext)
        return hashlib.sha3_256(
            b"test-only-ss|" + self.public_key + ct
        ).digest()


class UnsupportedPQ(FakeMLKEM):
    algorithm_id = "NOT-ML-KEM"


def test_x25519_key_establishment_round_trip():
    recipient = X25519KeyEstablishment.generate_recipient()
    sender = X25519KeyEstablishment()
    encapsulation, left = sender.encapsulate(recipient.public_key_bytes)
    right = recipient.decapsulate(encapsulation)
    assert len(left) == 32
    assert left == right


def test_hybrid_establishment_combines_classical_and_mlkem_provider():
    classical_recipient = X25519KeyEstablishment.generate_recipient()
    classical_sender = X25519KeyEstablishment()
    pq_public = b"pq-public-key-for-test-only" * 4
    pq_recipient = FakeMLKEM(pq_public)
    pq_sender = FakeMLKEM(b"sender-does-not-use-local-public-key")

    envelope, sender_key, sender_receipt = hybrid_encapsulate(
        classical=classical_sender,
        pq=pq_sender,
        classical_peer_public_key=classical_recipient.public_key_bytes,
        pq_peer_public_key=pq_public,
    )
    recipient_key, recipient_receipt = hybrid_decapsulate(
        classical=classical_recipient,
        pq=pq_recipient,
        envelope=envelope,
    )

    assert len(sender_key) == 32
    assert sender_key == recipient_key
    assert sender_receipt == recipient_receipt
    assert sender_receipt.to_dict()["authority"]["changes_frozen_aead"] is False
    assert sender_receipt.to_dict()["authority"]["master_key_not_serialized"] is True


def test_hybrid_transcript_tamper_is_rejected():
    classical_recipient = X25519KeyEstablishment.generate_recipient()
    pq_public = b"p" * 64
    envelope, _, _ = hybrid_encapsulate(
        classical=X25519KeyEstablishment(),
        pq=FakeMLKEM(b"sender"),
        classical_peer_public_key=classical_recipient.public_key_bytes,
        pq_peer_public_key=pq_public,
    )
    tampered = replace(envelope, pq_ciphertext_b64=b64e(b"tampered"))
    with pytest.raises(ValueError, match="transcript"):
        hybrid_decapsulate(
            classical=classical_recipient,
            pq=FakeMLKEM(pq_public),
            envelope=tampered,
        )


def test_non_mlkem_provider_is_rejected():
    classical_recipient = X25519KeyEstablishment.generate_recipient()
    with pytest.raises(ValueError, match="ML-KEM"):
        hybrid_encapsulate(
            classical=X25519KeyEstablishment(),
            pq=UnsupportedPQ(b"p" * 64),
            classical_peer_public_key=classical_recipient.public_key_bytes,
            pq_peer_public_key=b"p" * 64,
        )


def test_hybrid_envelope_rejects_unapproved_pq_identifier():
    with pytest.raises(ValueError, match="approved ML-KEM"):
        HybridKEMEnvelope(
            classical_algorithm_id="X25519-HKDF-SHA3-512",
            pq_algorithm_id="Kyber768",
            classical_ciphertext_b64=b64e(b"a"),
            pq_ciphertext_b64=b64e(b"b"),
            transcript_commitment="0" * 64,
        )
