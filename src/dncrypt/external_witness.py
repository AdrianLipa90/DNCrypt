"""Signed external monotonic witness boundary for DNCrypt v0.6.3.

This module provides a production-oriented protocol boundary for an anti-rollback
authority that lives outside rollbackable DNCrypt process state. It does not
pretend that local files are monotonic hardware. A deployment may back the
transport with an HSM/TPM-mediated service or a remote append-only witness.

The bundled in-memory service is test-only.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Any, Mapping, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .unified_checkpoint import (
    ANCHOR_SCHEMA,
    UnifiedMonotonicAnchor,
    UnifiedMonotonicAnchorPort,
)
from .util import blake2b256, canonical_json_bytes

WITNESS_RECORD_SCHEMA = "dncrypt.signed-unified-anchor-witness/v0.6.3-candidate"
WITNESS_REQUEST_SCHEMA = "dncrypt.signed-unified-anchor-request/v0.6.3-candidate"


def _validate_digest(value: str | None, name: str, *, optional: bool = False) -> None:
    if value is None and optional:
        return
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(name + " must be a 64-character hex digest")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(name + " must be hexadecimal") from exc


def _anchor_from_mapping(value: Mapping[str, Any]) -> UnifiedMonotonicAnchor:
    expected = {
        "counter",
        "journal_receipt_digest",
        "event_count",
        "head_event_id",
        "active_checkpoint_id",
        "active_state_commitment",
        "active_pdna_id",
        "previous_anchor_digest",
        "schema",
    }
    if set(value) != expected:
        raise ValueError("external witness anchor schema mismatch")
    anchor = UnifiedMonotonicAnchor(**dict(value))
    anchor.verify()
    if anchor.schema != ANCHOR_SCHEMA:
        raise ValueError("external witness carried unsupported anchor schema")
    return anchor


@dataclass(frozen=True, slots=True)
class WitnessAdvanceRequest:
    witness_id: str
    public_key_id: str
    expected_previous_witness_digest: str | None
    expected_previous_anchor_digest: str | None
    new_anchor: UnifiedMonotonicAnchor
    schema: str = WITNESS_REQUEST_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != WITNESS_REQUEST_SCHEMA:
            raise ValueError("unsupported witness request schema")
        if not self.witness_id.strip() or not self.public_key_id.strip():
            raise ValueError("witness_id/public_key_id must not be empty")
        _validate_digest(
            self.expected_previous_witness_digest,
            "expected_previous_witness_digest",
            optional=True,
        )
        _validate_digest(
            self.expected_previous_anchor_digest,
            "expected_previous_anchor_digest",
            optional=True,
        )
        self.new_anchor.verify()

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "witness_id": self.witness_id,
            "public_key_id": self.public_key_id,
            "expected_previous_witness_digest": self.expected_previous_witness_digest,
            "expected_previous_anchor_digest": self.expected_previous_anchor_digest,
            "new_anchor": asdict(self.new_anchor),
        }

    @property
    def request_id(self) -> str:
        return blake2b256(canonical_json_bytes(self.to_dict()))

    def to_bytes(self) -> bytes:
        return canonical_json_bytes({**self.to_dict(), "request_id": self.request_id})

    @classmethod
    def from_bytes(cls, raw: bytes) -> "WitnessAdvanceRequest":
        try:
            value = json.loads(bytes(raw).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("witness request is not valid UTF-8 JSON") from exc
        if not isinstance(value, dict):
            raise ValueError("witness request root must be an object")
        expected = {
            "schema",
            "witness_id",
            "public_key_id",
            "expected_previous_witness_digest",
            "expected_previous_anchor_digest",
            "new_anchor",
            "request_id",
        }
        if set(value) != expected:
            raise ValueError("witness request schema mismatch")
        if canonical_json_bytes(value) != bytes(raw):
            raise ValueError("witness request encoding is not canonical")
        anchor_value = value.get("new_anchor")
        if not isinstance(anchor_value, Mapping):
            raise ValueError("witness request new_anchor must be an object")
        request = cls(
            witness_id=str(value["witness_id"]),
            public_key_id=str(value["public_key_id"]),
            expected_previous_witness_digest=value["expected_previous_witness_digest"],
            expected_previous_anchor_digest=value["expected_previous_anchor_digest"],
            new_anchor=_anchor_from_mapping(anchor_value),
            schema=str(value["schema"]),
        )
        if value.get("request_id") != request.request_id:
            raise ValueError("witness request commitment mismatch")
        return request


@dataclass(frozen=True, slots=True)
class SignedWitnessRecord:
    witness_id: str
    public_key_id: str
    sequence: int
    anchor: UnifiedMonotonicAnchor
    previous_witness_digest: str | None
    signature_hex: str
    schema: str = WITNESS_RECORD_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != WITNESS_RECORD_SCHEMA:
            raise ValueError("unsupported witness record schema")
        if not self.witness_id.strip() or not self.public_key_id.strip():
            raise ValueError("witness_id/public_key_id must not be empty")
        if self.sequence < 0:
            raise ValueError("witness sequence must be non-negative")
        _validate_digest(
            self.previous_witness_digest,
            "previous_witness_digest",
            optional=True,
        )
        self.anchor.verify()
        try:
            sig = bytes.fromhex(self.signature_hex)
        except ValueError as exc:
            raise ValueError("signature_hex must be hexadecimal") from exc
        if len(sig) != 64:
            raise ValueError("Ed25519 signature must contain 64 bytes")

    def signing_payload(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "witness_id": self.witness_id,
            "public_key_id": self.public_key_id,
            "sequence": self.sequence,
            "anchor": asdict(self.anchor),
            "anchor_digest": self.anchor.digest,
            "previous_witness_digest": self.previous_witness_digest,
        }

    def verify_signature(self, public_key: Ed25519PublicKey) -> bool:
        self.__post_init__()
        try:
            public_key.verify(
                bytes.fromhex(self.signature_hex),
                canonical_json_bytes(self.signing_payload()),
            )
        except Exception as exc:
            raise ValueError("external witness signature verification failed") from exc
        return True

    @property
    def digest(self) -> str:
        return blake2b256(
            canonical_json_bytes(
                {**self.signing_payload(), "signature_hex": self.signature_hex}
            )
        )

    def to_bytes(self) -> bytes:
        return canonical_json_bytes(
            {**self.signing_payload(), "signature_hex": self.signature_hex}
        )

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        *,
        public_key: Ed25519PublicKey,
    ) -> "SignedWitnessRecord":
        try:
            value = json.loads(bytes(raw).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("witness record is not valid UTF-8 JSON") from exc
        if not isinstance(value, dict):
            raise ValueError("witness record root must be an object")
        expected = {
            "schema",
            "witness_id",
            "public_key_id",
            "sequence",
            "anchor",
            "anchor_digest",
            "previous_witness_digest",
            "signature_hex",
        }
        if set(value) != expected:
            raise ValueError("witness record schema mismatch")
        if canonical_json_bytes(value) != bytes(raw):
            raise ValueError("witness record encoding is not canonical")
        anchor_value = value.get("anchor")
        if not isinstance(anchor_value, Mapping):
            raise ValueError("witness record anchor must be an object")
        anchor = _anchor_from_mapping(anchor_value)
        if value.get("anchor_digest") != anchor.digest:
            raise ValueError("witness anchor digest mismatch")
        record = cls(
            witness_id=str(value["witness_id"]),
            public_key_id=str(value["public_key_id"]),
            sequence=int(value["sequence"]),
            anchor=anchor,
            previous_witness_digest=value["previous_witness_digest"],
            signature_hex=str(value["signature_hex"]),
            schema=str(value["schema"]),
        )
        record.verify_signature(public_key)
        return record


class SignedWitnessTransport(Protocol):
    """Opaque transport boundary to an external append-only witness service."""

    def read_record(self) -> bytes | None: ...

    def compare_and_advance(self, request: bytes) -> bytes: ...


class RemoteSignedUnifiedAnchorPort(UnifiedMonotonicAnchorPort):
    """Verified client-side adapter for a signed external monotonic witness."""

    def __init__(
        self,
        *,
        transport: SignedWitnessTransport,
        public_key: Ed25519PublicKey,
        witness_id: str,
        public_key_id: str,
    ) -> None:
        if not witness_id.strip() or not public_key_id.strip():
            raise ValueError("witness_id/public_key_id must not be empty")
        self._transport = transport
        self._public_key = public_key
        self._witness_id = witness_id
        self._public_key_id = public_key_id

    def _read_verified_record(self) -> SignedWitnessRecord | None:
        raw = self._transport.read_record()
        if raw is None:
            return None
        record = SignedWitnessRecord.from_bytes(raw, public_key=self._public_key)
        if record.witness_id != self._witness_id:
            raise ValueError("external witness id mismatch")
        if record.public_key_id != self._public_key_id:
            raise ValueError("external witness public-key id mismatch")
        return record

    def read(self) -> UnifiedMonotonicAnchor | None:
        record = self._read_verified_record()
        return None if record is None else record.anchor

    def compare_and_advance(
        self,
        *,
        expected_previous_digest: str | None,
        new_anchor: UnifiedMonotonicAnchor,
    ) -> str:
        new_anchor.verify()
        current = self._read_verified_record()
        current_anchor_digest = None if current is None else current.anchor.digest
        if expected_previous_digest != current_anchor_digest:
            raise ValueError("external witness anchor compare-and-swap mismatch")

        request = WitnessAdvanceRequest(
            witness_id=self._witness_id,
            public_key_id=self._public_key_id,
            expected_previous_witness_digest=None if current is None else current.digest,
            expected_previous_anchor_digest=current_anchor_digest,
            new_anchor=new_anchor,
        )
        response = SignedWitnessRecord.from_bytes(
            self._transport.compare_and_advance(request.to_bytes()),
            public_key=self._public_key,
        )
        if response.witness_id != self._witness_id:
            raise ValueError("external witness id mismatch")
        if response.public_key_id != self._public_key_id:
            raise ValueError("external witness public-key id mismatch")
        expected_sequence = 0 if current is None else current.sequence + 1
        if response.sequence != expected_sequence:
            raise ValueError("external witness sequence did not advance exactly once")
        if response.previous_witness_digest != (
            None if current is None else current.digest
        ):
            raise ValueError("external witness chain mismatch")
        if response.anchor != new_anchor:
            raise ValueError("external witness signed a different anchor")
        return new_anchor.digest


class InMemorySignedWitnessService(SignedWitnessTransport):
    """Test-only reference service. Not a durable anti-rollback authority."""

    def __init__(
        self,
        *,
        private_key: Ed25519PrivateKey,
        witness_id: str,
        public_key_id: str,
    ) -> None:
        self._private_key = private_key
        self._witness_id = witness_id
        self._public_key_id = public_key_id
        self._current: SignedWitnessRecord | None = None

    def read_record(self) -> bytes | None:
        return None if self._current is None else self._current.to_bytes()

    def compare_and_advance(self, request: bytes) -> bytes:
        req = WitnessAdvanceRequest.from_bytes(request)
        if req.witness_id != self._witness_id:
            raise ValueError("witness service id mismatch")
        if req.public_key_id != self._public_key_id:
            raise ValueError("witness service public-key id mismatch")

        actual_witness_digest = None if self._current is None else self._current.digest
        actual_anchor_digest = (
            None if self._current is None else self._current.anchor.digest
        )
        if req.expected_previous_witness_digest != actual_witness_digest:
            raise ValueError("witness service CAS mismatch")
        if req.expected_previous_anchor_digest != actual_anchor_digest:
            raise ValueError("witness service anchor CAS mismatch")

        sequence = 0 if self._current is None else self._current.sequence + 1
        payload = {
            "schema": WITNESS_RECORD_SCHEMA,
            "witness_id": self._witness_id,
            "public_key_id": self._public_key_id,
            "sequence": sequence,
            "anchor": asdict(req.new_anchor),
            "anchor_digest": req.new_anchor.digest,
            "previous_witness_digest": actual_witness_digest,
        }
        signature = self._private_key.sign(canonical_json_bytes(payload)).hex()
        record = SignedWitnessRecord(
            witness_id=self._witness_id,
            public_key_id=self._public_key_id,
            sequence=sequence,
            anchor=req.new_anchor,
            previous_witness_digest=actual_witness_digest,
            signature_hex=signature,
        )
        self._current = record
        return record.to_bytes()


__all__ = [
    "WITNESS_RECORD_SCHEMA",
    "WITNESS_REQUEST_SCHEMA",
    "InMemorySignedWitnessService",
    "RemoteSignedUnifiedAnchorPort",
    "SignedWitnessRecord",
    "SignedWitnessTransport",
    "WitnessAdvanceRequest",
]
