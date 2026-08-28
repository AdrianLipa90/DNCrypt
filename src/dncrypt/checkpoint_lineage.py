from __future__ import annotations

from dataclasses import asdict, dataclass

from .checkpoint_port import (
    CheckpointPort,
    DNCryptCheckpoint,
    RollbackReceipt,
    rollback_to_checkpoint,
    state_commitment,
)
from .state import DNCryptState
from .util import blake2b256, canonical_json_bytes

LINEAGE_SCHEMA = "dncrypt.checkpoint-lineage-receipt/v0.5-candidate"
DEFAULT_MAX_DEPTH = 4096


@dataclass(frozen=True, slots=True)
class CheckpointLineageReceipt:
    schema: str
    head_checkpoint_id: str
    target_checkpoint_id: str
    path_head_to_target: tuple[str, ...]
    ancestry_depth: int
    head_state_commitment: str
    target_state_commitment: str
    pass_ancestry: bool

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))


def verify_checkpoint_ancestry(
    store: CheckpointPort,
    head_checkpoint_id: str,
    target_checkpoint_id: str,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> CheckpointLineageReceipt:
    if max_depth <= 0:
        raise ValueError("max_depth must be positive")
    _validate_digest(head_checkpoint_id, "head_checkpoint_id")
    _validate_digest(target_checkpoint_id, "target_checkpoint_id")

    seen: set[str] = set()
    path: list[str] = []
    current_id = head_checkpoint_id
    head_checkpoint: DNCryptCheckpoint | None = None

    for _ in range(max_depth):
        if current_id in seen:
            raise ValueError("checkpoint lineage cycle detected")
        seen.add(current_id)
        try:
            checkpoint = store.get(current_id)
        except KeyError as exc:
            raise ValueError(f"checkpoint lineage missing node: {current_id}") from exc
        checkpoint.verify()
        if checkpoint.checkpoint_id != current_id:
            raise ValueError("checkpoint store returned mismatched checkpoint id")
        if head_checkpoint is None:
            head_checkpoint = checkpoint
        path.append(current_id)

        if current_id == target_checkpoint_id:
            assert head_checkpoint is not None
            receipt = CheckpointLineageReceipt(
                schema=LINEAGE_SCHEMA,
                head_checkpoint_id=head_checkpoint_id,
                target_checkpoint_id=target_checkpoint_id,
                path_head_to_target=tuple(path),
                ancestry_depth=len(path) - 1,
                head_state_commitment=head_checkpoint.state_commitment,
                target_state_commitment=checkpoint.state_commitment,
                pass_ancestry=True,
            )
            return receipt

        parent_id = checkpoint.parent_checkpoint_id
        if parent_id is None:
            raise ValueError("target checkpoint is not an ancestor of head checkpoint")
        _validate_digest(parent_id, "parent_checkpoint_id")
        current_id = parent_id

    raise ValueError("checkpoint lineage maximum depth exceeded")


def rollback_to_ancestor(
    current_state: DNCryptState,
    store: CheckpointPort,
    current_checkpoint_id: str,
    target_checkpoint_id: str,
    *,
    expected_current_state_commitment: str | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> tuple[DNCryptState, RollbackReceipt, CheckpointLineageReceipt]:
    lineage = verify_checkpoint_ancestry(
        store,
        current_checkpoint_id,
        target_checkpoint_id,
        max_depth=max_depth,
    )
    actual_current_commitment = state_commitment(current_state)
    if actual_current_commitment != lineage.head_state_commitment:
        raise ValueError("current state does not match current checkpoint")
    if expected_current_state_commitment is not None:
        _validate_digest(expected_current_state_commitment, "expected_current_state_commitment")
        if actual_current_commitment != expected_current_state_commitment:
            raise ValueError("current state changed before ancestry rollback")
    target = store.get(target_checkpoint_id)
    restored, rollback_receipt = rollback_to_checkpoint(
        current_state,
        target,
        expected_current_state_commitment=actual_current_commitment,
    )
    return restored, rollback_receipt, lineage


def _validate_digest(value: str, name: str) -> None:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{name} must be a 64-character hex digest")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{name} must be hexadecimal") from exc
