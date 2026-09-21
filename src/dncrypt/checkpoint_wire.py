from __future__ import annotations

from dataclasses import asdict
import json
from typing import Any

from .checkpoint_port import DNCryptCheckpoint
from .util import blake2b256, canonical_json_bytes

WIRE_SCHEMA = "dncrypt.checkpoint-wire/v0.1"
MAX_WIRE_BYTES = 2 * 1024 * 1024

_CHECKPOINT_FIELDS = {
    "schema",
    "state_payload",
    "state_commitment",
    "parent_checkpoint_id",
    "reason",
}
_STATE_FIELDS = {
    "genome",
    "surface",
    "last_receipt",
    "last_evolution_receipt",
}
_GENOME_FIELDS = {
    "version",
    "generation",
    "parent_id",
    "operator_vector",
    "route",
    "phase_seed_hex",
    "mutation_nonce_hex",
}
_SURFACE_FIELDS = {"tick", "phi", "omega"}


def encode_checkpoint(checkpoint: DNCryptCheckpoint) -> bytes:
    checkpoint.verify()
    envelope = {
        "schema": WIRE_SCHEMA,
        "checkpoint_id": checkpoint.checkpoint_id,
        "checkpoint": asdict(checkpoint),
    }
    payload = canonical_json_bytes(envelope)
    if len(payload) > MAX_WIRE_BYTES:
        raise ValueError("checkpoint wire payload exceeds bounded codec limit")
    return payload


def _exact_fields(value: dict[str, Any], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise ValueError(f"{name} fields mismatch")


def decode_checkpoint(data: bytes) -> DNCryptCheckpoint:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("checkpoint wire payload must be bytes")
    raw = bytes(data)
    if len(raw) > MAX_WIRE_BYTES:
        raise ValueError("checkpoint wire payload exceeds bounded codec limit")
    try:
        value: Any = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid checkpoint wire payload") from exc
    if not isinstance(value, dict):
        raise ValueError("invalid checkpoint wire envelope")
    _exact_fields(value, {"schema", "checkpoint_id", "checkpoint"}, "checkpoint wire envelope")
    if value["schema"] != WIRE_SCHEMA:
        raise ValueError("unsupported checkpoint wire schema")
    if canonical_json_bytes(value) != raw:
        raise ValueError("checkpoint wire payload is not canonical")

    raw_checkpoint = value["checkpoint"]
    if not isinstance(raw_checkpoint, dict):
        raise ValueError("checkpoint wire body must be a mapping")
    raw_checkpoint = dict(raw_checkpoint)
    _exact_fields(raw_checkpoint, _CHECKPOINT_FIELDS, "checkpoint wire body")

    state_payload = raw_checkpoint.get("state_payload")
    if not isinstance(state_payload, dict):
        raise ValueError("checkpoint wire state payload must be a mapping")
    state_payload = dict(state_payload)
    _exact_fields(state_payload, _STATE_FIELDS, "checkpoint wire state payload")

    genome = state_payload.get("genome")
    surface = state_payload.get("surface")
    if not isinstance(genome, dict) or not isinstance(surface, dict):
        raise ValueError("checkpoint wire state payload is incomplete")
    genome = dict(genome)
    surface = dict(surface)
    _exact_fields(genome, _GENOME_FIELDS, "checkpoint wire genome")
    _exact_fields(surface, _SURFACE_FIELDS, "checkpoint wire surface")

    operator_vector = genome.get("operator_vector")
    route = genome.get("route")
    phi = surface.get("phi")
    omega = surface.get("omega")
    if not isinstance(operator_vector, list) or not isinstance(route, list):
        raise ValueError("checkpoint wire genome vectors must be arrays")
    if not isinstance(phi, list) or not isinstance(omega, list):
        raise ValueError("checkpoint wire surface vectors must be arrays")

    genome["operator_vector"] = tuple(operator_vector)
    genome["route"] = tuple(route)
    surface["phi"] = tuple(phi)
    surface["omega"] = tuple(omega)
    state_payload["genome"] = genome
    state_payload["surface"] = surface
    raw_checkpoint["state_payload"] = state_payload

    try:
        checkpoint = DNCryptCheckpoint(**raw_checkpoint)
        checkpoint.verify()
    except (TypeError, ValueError, KeyError, OverflowError) as exc:
        raise ValueError("invalid checkpoint wire body") from exc
    if value["checkpoint_id"] != checkpoint.checkpoint_id:
        raise ValueError("checkpoint wire id mismatch")
    return checkpoint


def wire_commitment(data: bytes) -> str:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("checkpoint wire payload must be bytes")
    return blake2b256(bytes(data))
