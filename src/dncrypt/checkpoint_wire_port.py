from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Protocol

from .checkpoint_port import DNCryptCheckpoint
from .checkpoint_wire import decode_checkpoint, encode_checkpoint, wire_commitment
from .util import blake2b256, canonical_json_bytes

WIRE_PORT_RECEIPT_SCHEMA = "dncrypt.checkpoint-wire-port-receipt/v0.5-candidate"


class CheckpointWirePort(Protocol):
    """Byte-only persistence boundary.

    External implementations receive only a content-addressed string key and opaque
    bytes. They do not need to import DNCrypt classes or any retained project code.
    """

    def put(self, checkpoint_id: str, payload: bytes) -> None: ...
    def get(self, checkpoint_id: str) -> bytes: ...


@dataclass(frozen=True, slots=True)
class CheckpointWirePortReceipt:
    schema: str
    checkpoint_id: str
    wire_commitment: str
    payload_size: int
    readback_verified: bool

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))


class InMemoryCheckpointWireStore:
    """Opaque-byte reference backend for conformance tests only."""

    def __init__(self) -> None:
        self._items: dict[str, bytes] = {}

    def put(self, checkpoint_id: str, payload: bytes) -> None:
        _validate_digest(checkpoint_id, "checkpoint_id")
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("checkpoint wire payload must be bytes")
        value = bytes(payload)
        existing = self._items.get(checkpoint_id)
        if existing is not None and existing != value:
            raise ValueError("checkpoint wire key collision")
        self._items[checkpoint_id] = value

    def get(self, checkpoint_id: str) -> bytes:
        _validate_digest(checkpoint_id, "checkpoint_id")
        try:
            return self._items[checkpoint_id]
        except KeyError as exc:
            raise KeyError("checkpoint wire payload not found") from exc


def persist_checkpoint_wire(
    port: CheckpointWirePort,
    checkpoint: DNCryptCheckpoint,
    *,
    verify_readback: bool = True,
) -> CheckpointWirePortReceipt:
    checkpoint.verify()
    checkpoint_id = checkpoint.checkpoint_id
    payload = encode_checkpoint(checkpoint)
    port.put(checkpoint_id, payload)

    readback_verified = False
    if verify_readback:
        readback = port.get(checkpoint_id)
        restored = decode_checkpoint(readback)
        if restored.checkpoint_id != checkpoint_id or restored != checkpoint:
            raise ValueError("checkpoint wire readback mismatch")
        if bytes(readback) != payload:
            raise ValueError("checkpoint wire bytes changed during persistence")
        readback_verified = True

    return CheckpointWirePortReceipt(
        schema=WIRE_PORT_RECEIPT_SCHEMA,
        checkpoint_id=checkpoint_id,
        wire_commitment=wire_commitment(payload),
        payload_size=len(payload),
        readback_verified=readback_verified,
    )


def load_checkpoint_wire(port: CheckpointWirePort, checkpoint_id: str) -> DNCryptCheckpoint:
    _validate_digest(checkpoint_id, "checkpoint_id")
    payload = port.get(checkpoint_id)
    checkpoint = decode_checkpoint(payload)
    if checkpoint.checkpoint_id != checkpoint_id:
        raise ValueError("checkpoint wire storage key mismatch")
    return checkpoint


def _validate_digest(value: str, name: str) -> None:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{name} must be a 64-character hex digest")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{name} must be hexadecimal") from exc
