from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Protocol

from .genome import CipherGenome
from .state import DNCryptState
from .surface import CipherSurface
from .util import blake2b256, canonical_json_bytes

CHECKPOINT_SCHEMA = "dncrypt.checkpoint/v0.5-candidate"
ROLLBACK_SCHEMA = "dncrypt.rollback-receipt/v0.5-candidate"


def _state_payload(state: DNCryptState) -> dict[str, object]:
    return {
        "genome": asdict(state.genome),
        "surface": asdict(state.surface),
        "last_receipt": state.last_receipt,
        "last_evolution_receipt": state.last_evolution_receipt,
    }


def state_commitment(state: DNCryptState) -> str:
    return blake2b256(canonical_json_bytes(_state_payload(state)))


@dataclass(frozen=True, slots=True)
class DNCryptCheckpoint:
    schema: str
    state_payload: dict[str, object]
    state_commitment: str
    parent_checkpoint_id: str | None
    reason: str

    @property
    def checkpoint_id(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))

    def verify(self) -> None:
        if self.schema != CHECKPOINT_SCHEMA:
            raise ValueError("unsupported checkpoint schema")
        restored = _state_from_payload(self.state_payload)
        if state_commitment(restored) != self.state_commitment:
            raise ValueError("checkpoint state commitment mismatch")
        if self.parent_checkpoint_id is not None:
            _validate_digest(self.parent_checkpoint_id, "parent_checkpoint_id")
        if not self.reason.strip():
            raise ValueError("checkpoint reason must not be empty")


@dataclass(frozen=True, slots=True)
class RollbackReceipt:
    schema: str
    from_state_commitment: str
    checkpoint_id: str
    restored_state_commitment: str
    restored_genome_id: str
    restored_surface_commitment: str
    restored_tick: int

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))


class CheckpointPort(Protocol):
    """Minimal persistence boundary for external checkpoint backends.

    Implementations may live in DNCrypt-specific storage or in an adjacent
    project through an adapter. The port intentionally imports no external
    project namespace.
    """

    def put(self, checkpoint: DNCryptCheckpoint) -> str: ...
    def get(self, checkpoint_id: str) -> DNCryptCheckpoint: ...


class InMemoryCheckpointStore:
    """Reference store for tests and local execution; not the v0.6 persistence layer."""

    def __init__(self) -> None:
        self._items: dict[str, DNCryptCheckpoint] = {}

    def put(self, checkpoint: DNCryptCheckpoint) -> str:
        checkpoint.verify()
        checkpoint_id = checkpoint.checkpoint_id
        existing = self._items.get(checkpoint_id)
        if existing is not None and existing != checkpoint:
            raise ValueError("checkpoint id collision")
        self._items[checkpoint_id] = checkpoint
        return checkpoint_id

    def get(self, checkpoint_id: str) -> DNCryptCheckpoint:
        _validate_digest(checkpoint_id, "checkpoint_id")
        try:
            checkpoint = self._items[checkpoint_id]
        except KeyError as exc:
            raise KeyError("checkpoint not found") from exc
        checkpoint.verify()
        return checkpoint


def create_checkpoint(
    state: DNCryptState,
    *,
    parent_checkpoint_id: str | None = None,
    reason: str = "state-transition-boundary",
) -> DNCryptCheckpoint:
    if parent_checkpoint_id is not None:
        _validate_digest(parent_checkpoint_id, "parent_checkpoint_id")
    if not reason.strip():
        raise ValueError("checkpoint reason must not be empty")
    checkpoint = DNCryptCheckpoint(
        schema=CHECKPOINT_SCHEMA,
        state_payload=_state_payload(state),
        state_commitment=state_commitment(state),
        parent_checkpoint_id=parent_checkpoint_id,
        reason=reason,
    )
    checkpoint.verify()
    return checkpoint


def restore_checkpoint(checkpoint: DNCryptCheckpoint) -> DNCryptState:
    checkpoint.verify()
    restored = _state_from_payload(checkpoint.state_payload)
    if state_commitment(restored) != checkpoint.state_commitment:
        raise ValueError("restored state commitment mismatch")
    return restored


def rollback_to_checkpoint(
    current_state: DNCryptState,
    checkpoint: DNCryptCheckpoint,
    *,
    expected_current_state_commitment: str | None = None,
) -> tuple[DNCryptState, RollbackReceipt]:
    current_commitment = state_commitment(current_state)
    if expected_current_state_commitment is not None:
        _validate_digest(expected_current_state_commitment, "expected_current_state_commitment")
        if current_commitment != expected_current_state_commitment:
            raise ValueError("current state changed before rollback")
    restored = restore_checkpoint(checkpoint)
    receipt = RollbackReceipt(
        schema=ROLLBACK_SCHEMA,
        from_state_commitment=current_commitment,
        checkpoint_id=checkpoint.checkpoint_id,
        restored_state_commitment=state_commitment(restored),
        restored_genome_id=restored.genome.genome_id,
        restored_surface_commitment=restored.surface.commitment,
        restored_tick=restored.surface.tick,
    )
    return restored, receipt


def _state_from_payload(payload: dict[str, object]) -> DNCryptState:
    if not isinstance(payload, dict):
        raise ValueError("checkpoint state payload must be a mapping")
    try:
        g = dict(payload["genome"])  # type: ignore[arg-type]
        s = dict(payload["surface"])  # type: ignore[arg-type]
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("invalid checkpoint state payload") from exc
    g["operator_vector"] = tuple(g["operator_vector"])
    g["route"] = tuple(g["route"])
    s["phi"] = tuple(s["phi"])
    s["omega"] = tuple(s["omega"])
    return DNCryptState(
        CipherGenome(**g),
        CipherSurface(**s),
        payload.get("last_receipt"),  # type: ignore[arg-type]
        payload.get("last_evolution_receipt"),  # type: ignore[arg-type]
    )


def _validate_digest(value: str, name: str) -> None:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(name + " must be a 64-character hex digest")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(name + " must be hexadecimal") from exc
