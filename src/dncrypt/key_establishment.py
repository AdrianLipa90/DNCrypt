"""Crypto-agility and hybrid key-establishment boundary for DNCrypt v0.7.

The frozen DNCrypt v0.2 data-encryption protocol remains unchanged. This module
only establishes a 32-byte master key for that protocol. It deliberately avoids
re-implementing ML-KEM: post-quantum providers must come from a separately
validated implementation exposing the KEMProvider boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .util import b64d, b64e, blake2b256, canonical_json_bytes

KEY_ESTABLISHMENT_SCHEMA = "dncrypt.key-establishment/v0.7-candidate"
HYBRID_KEM_SCHEMA = "dncrypt.hybrid-kem-envelope/v0.7-candidate"
APPROVED_MLKEM_IDS = frozenset({"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})


class KEMProvider(Protocol):
    """Provider boundary for a KEM or KEM-like key-establishment primitive."""

    algorithm_id: str

    def encapsulate(self, peer_public_key: bytes) -> tuple[bytes, bytes]:
        """Return (ciphertext_or_encapsulation, shared_secret)."""
        ...

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """Return the shared secret for a received encapsulation."""
        ...


class X25519KeyEstablishment:
    """Classical ephemeral-static X25519 adapter.

    This is a key-establishment adapter, not a claim that X25519 is ML-KEM.
    """

    algorithm_id = "X25519-HKDF-SHA3-512"

    def __init__(self, private_key: X25519PrivateKey | None = None) -> None:
        self._private_key = private_key

    @classmethod
    def generate_recipient(cls) -> "X25519KeyEstablishment":
        return cls(X25519PrivateKey.generate())

    @property
    def public_key_bytes(self) -> bytes:
        if self._private_key is None:
            raise ValueError("recipient private key is not configured")
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    @staticmethod
    def _derive(shared: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA3_512(),
            length=32,
            salt=None,
            info=b"DNCrypt/v0.7/X25519-key-establishment",
        ).derive(shared)

    def encapsulate(self, peer_public_key: bytes) -> tuple[bytes, bytes]:
        try:
            peer = X25519PublicKey.from_public_bytes(bytes(peer_public_key))
        except ValueError as exc:
            raise ValueError("invalid X25519 peer public key") from exc
        ephemeral = X25519PrivateKey.generate()
        shared = ephemeral.exchange(peer)
        encapsulation = ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return encapsulation, self._derive(shared)

    def decapsulate(self, ciphertext: bytes) -> bytes:
        if self._private_key is None:
            raise ValueError("recipient private key is not configured")
        try:
            ephemeral_public = X25519PublicKey.from_public_bytes(bytes(ciphertext))
        except ValueError as exc:
            raise ValueError("invalid X25519 encapsulation") from exc
        return self._derive(self._private_key.exchange(ephemeral_public))


@dataclass(frozen=True, slots=True)
class HybridKEMEnvelope:
    classical_algorithm_id: str
    pq_algorithm_id: str
    classical_ciphertext_b64: str
    pq_ciphertext_b64: str
    transcript_commitment: str
    schema: str = HYBRID_KEM_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != HYBRID_KEM_SCHEMA:
            raise ValueError("unsupported hybrid KEM schema")
        if not self.classical_algorithm_id.strip() or not self.pq_algorithm_id.strip():
            raise ValueError("algorithm ids must not be empty")
        if self.pq_algorithm_id not in APPROVED_MLKEM_IDS:
            raise ValueError("post-quantum provider must identify an approved ML-KEM parameter set")
        if len(self.transcript_commitment) != 64:
            raise ValueError("transcript_commitment must be a 32-byte hex digest")
        try:
            int(self.transcript_commitment, 16)
            b64d(self.classical_ciphertext_b64)
            b64d(self.pq_ciphertext_b64)
        except Exception as exc:
            raise ValueError("hybrid KEM envelope encoding is invalid") from exc

    def public_payload(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "classical_algorithm_id": self.classical_algorithm_id,
            "pq_algorithm_id": self.pq_algorithm_id,
            "classical_ciphertext_b64": self.classical_ciphertext_b64,
            "pq_ciphertext_b64": self.pq_ciphertext_b64,
        }

    def verify_transcript(self) -> bool:
        expected = blake2b256(canonical_json_bytes(self.public_payload()))
        if expected != self.transcript_commitment:
            raise ValueError("hybrid KEM transcript commitment mismatch")
        return True


@dataclass(frozen=True, slots=True)
class KeyEstablishmentReceipt:
    classical_algorithm_id: str
    pq_algorithm_id: str
    envelope_commitment: str
    master_key_commitment: str
    schema: str = KEY_ESTABLISHMENT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != KEY_ESTABLISHMENT_SCHEMA:
            raise ValueError("unsupported key-establishment receipt schema")
        for name, value in (
            ("envelope_commitment", self.envelope_commitment),
            ("master_key_commitment", self.master_key_commitment),
        ):
            if len(value) != 64:
                raise ValueError(name + " must be a 32-byte hex digest")
            try:
                int(value, 16)
            except ValueError as exc:
                raise ValueError(name + " must be hexadecimal") from exc

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "classical_algorithm_id": self.classical_algorithm_id,
            "pq_algorithm_id": self.pq_algorithm_id,
            "envelope_commitment": self.envelope_commitment,
            "master_key_commitment": self.master_key_commitment,
            "authority": {
                "changes_frozen_aead": False,
                "master_key_not_serialized": True,
                "pqc_provider_external": True,
            },
        }


def _validate_provider_pair(classical: KEMProvider, pq: KEMProvider) -> None:
    if not classical.algorithm_id.strip() or not pq.algorithm_id.strip():
        raise ValueError("KEM provider algorithm ids must not be empty")
    if pq.algorithm_id not in APPROVED_MLKEM_IDS:
        raise ValueError("post-quantum provider must identify ML-KEM-512/768/1024")
    if classical.algorithm_id == pq.algorithm_id:
        raise ValueError("hybrid KEM components must use distinct algorithm ids")


def _combine_hybrid_secrets(
    *,
    classical_secret: bytes,
    pq_secret: bytes,
    envelope: HybridKEMEnvelope,
) -> bytes:
    c = bytes(classical_secret)
    p = bytes(pq_secret)
    if len(c) < 16 or len(p) < 16:
        raise ValueError("KEM shared secrets are unexpectedly short")
    envelope.verify_transcript()
    info = canonical_json_bytes(
        {
            "domain": "DNCrypt/v0.7/hybrid-master-key",
            "classical_algorithm_id": envelope.classical_algorithm_id,
            "pq_algorithm_id": envelope.pq_algorithm_id,
            "transcript_commitment": envelope.transcript_commitment,
        }
    )
    return HKDF(
        algorithm=hashes.SHA3_512(),
        length=32,
        salt=bytes.fromhex(envelope.transcript_commitment),
        info=info,
    ).derive(c + p)


def hybrid_encapsulate(
    *,
    classical: KEMProvider,
    pq: KEMProvider,
    classical_peer_public_key: bytes,
    pq_peer_public_key: bytes,
) -> tuple[HybridKEMEnvelope, bytes, KeyEstablishmentReceipt]:
    """Establish one DNCrypt master key using classical + ML-KEM components."""

    _validate_provider_pair(classical, pq)
    classical_ct, classical_secret = classical.encapsulate(classical_peer_public_key)
    pq_ct, pq_secret = pq.encapsulate(pq_peer_public_key)
    payload = {
        "schema": HYBRID_KEM_SCHEMA,
        "classical_algorithm_id": classical.algorithm_id,
        "pq_algorithm_id": pq.algorithm_id,
        "classical_ciphertext_b64": b64e(bytes(classical_ct)),
        "pq_ciphertext_b64": b64e(bytes(pq_ct)),
    }
    envelope = HybridKEMEnvelope(
        **payload,
        transcript_commitment=blake2b256(canonical_json_bytes(payload)),
    )
    master_key = _combine_hybrid_secrets(
        classical_secret=classical_secret,
        pq_secret=pq_secret,
        envelope=envelope,
    )
    receipt = KeyEstablishmentReceipt(
        classical_algorithm_id=classical.algorithm_id,
        pq_algorithm_id=pq.algorithm_id,
        envelope_commitment=blake2b256(canonical_json_bytes(envelope.public_payload())),
        master_key_commitment=blake2b256(master_key),
    )
    return envelope, master_key, receipt


def hybrid_decapsulate(
    *,
    classical: KEMProvider,
    pq: KEMProvider,
    envelope: HybridKEMEnvelope,
) -> tuple[bytes, KeyEstablishmentReceipt]:
    _validate_provider_pair(classical, pq)
    envelope.verify_transcript()
    if envelope.classical_algorithm_id != classical.algorithm_id:
        raise ValueError("classical KEM algorithm mismatch")
    if envelope.pq_algorithm_id != pq.algorithm_id:
        raise ValueError("post-quantum KEM algorithm mismatch")
    classical_secret = classical.decapsulate(b64d(envelope.classical_ciphertext_b64))
    pq_secret = pq.decapsulate(b64d(envelope.pq_ciphertext_b64))
    master_key = _combine_hybrid_secrets(
        classical_secret=classical_secret,
        pq_secret=pq_secret,
        envelope=envelope,
    )
    receipt = KeyEstablishmentReceipt(
        classical_algorithm_id=classical.algorithm_id,
        pq_algorithm_id=pq.algorithm_id,
        envelope_commitment=blake2b256(canonical_json_bytes(envelope.public_payload())),
        master_key_commitment=blake2b256(master_key),
    )
    return master_key, receipt


__all__ = [
    "APPROVED_MLKEM_IDS",
    "HYBRID_KEM_SCHEMA",
    "KEY_ESTABLISHMENT_SCHEMA",
    "HybridKEMEnvelope",
    "KEMProvider",
    "KeyEstablishmentReceipt",
    "X25519KeyEstablishment",
    "hybrid_decapsulate",
    "hybrid_encapsulate",
]
