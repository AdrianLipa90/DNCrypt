from __future__ import annotations

from dataclasses import asdict
import json
from typing import Any

from .checkpoint_port import DNCryptCheckpoint
from .util import blake2b256, canonical_json_bytes

WIRE_SCHEMA = "dncrypt.checkpoint-wire/v0.1"


def encode_checkpoint(checkpoint: DNCryptCheckpoint) -> bytes:
    checkpoint.verify()
    envelope = {
        "schema": WIRE_SCHEMA,
        "checkpoint_id": checkpoint.checkpoint_id,
        "checkpoint": asdict(checkpoint),
    }
    return canonical_json_bytes(envelope)


def decode_checkpoint(data: bytes) -> DNCryptCheckpoint:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("checkpoint wire payload must be bytes")
    try:
        value: Any = json.loads(bytes(data).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid checkpoint wire payload") from exc
    if not isinstance(value, dict) or set(value) != {"schema", "checkpoint_id", "checkpoint"}:
        raise ValueError("invalid checkpoint wire envelope")
    if value["schema"] != WIRE_SCHEMA:
        raise ValueError("unsupported checkpoint wire schema")
    raw_checkpoint = value["checkpoint"]
    if not isinstance(raw_checkpoint, dict):
        raise ValueError("checkpoint wire body must be a mapping")
    raw_checkpoint = dict(raw_checkpoint)
    state_payload = raw_checkpoint.get("state_payload")
    if not isinstance(state_payload, dict):
        raise ValueError("checkpoint wire state payload must be a mapping")
    state_payload = dict(state_payload)
    genome = state_payload.get("genome")
    surface = state_payload.get("surface")
    if not isinstance(genome, dict) or not isinstance(surface, dict):
        raise ValueError("checkpoint wire state payload is incomplete")
    genome = dict(genome)
    surface = dict(surface)
    genome["operator_vector"] = tuple(genome["operator_vector"])
    genome["route"] = tuple(genome["route"])
    surface["phi"] = tuple(surface["phi"])
    surface["omega"] = tuple(surface["omega"])
    state_payload["genome"] = genome
    state_payload["surface"] = surface
    raw_checkpoint["state_payload"] = state_payload
    try:
        checkpoint = DNCryptCheckpoint(**raw_checkpoint)
    except TypeError as exc:
        raise ValueError("invalid checkpoint wire body") from exc
    checkpoint.verify()
    if value["checkpoint_id"] != checkpoint.checkpoint_id:
        raise ValueError("checkpoint wire id mismatch")
    return checkpoint


def wire_commitment(data: bytes) -> str:
    return blake2b256(bytes(data))
