"""Checkpoint, journal and anti-rollback closure for UnifiedDNCryptState v0.6.1.

This candidate layer binds rollback authority to the same logical state that binds
CipherGenome, CipherSurface, Genetic IR and PDNA.  The in-memory stores are
reference implementations only; durable production authority must live outside
rollbackable process state.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping, Protocol

from .unified_state import UnifiedDNCryptState
from .util import blake2b256, canonical_json_bytes

CHECKPOINT_SCHEMA = "dncrypt.unified-checkpoint/v0.6.1-candidate"
ROLLBACK_SCHEMA = "dncrypt.unified-rollback-receipt/v0.6.1-candidate"
EVENT_SCHEMA = "dncrypt.unified-state-memory-event/v0.6.1-candidate"
JOURNAL_SCHEMA = "dncrypt.unified-state-memory-journal/v0.6.1-candidate"
ANCHOR_SCHEMA = "dncrypt.unified-monotonic-anchor/v0.6.1-candidate"


def _validate_digest(value: str | None, name: str, *, optional: bool = False) -> None:
    if value is None and optional:
        return
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(name + " must be a 64-character hex digest")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(name + " must be hexadecimal") from exc


@dataclass(frozen=True, slots=True)
class UnifiedCheckpoint:
    state_payload: Mapping[str, Any]
    state_commitment: str
    parent_checkpoint_id: str | None = None
    reason: str = "unified-state-transition-boundary"
    schema: str = CHECKPOINT_SCHEMA

    def verify(self) -> bool:
        if self.schema != CHECKPOINT_SCHEMA:
            raise ValueError("unsupported unified checkpoint schema")
        _validate_digest(self.state_commitment, "state_commitment")
        _validate_digest(self.parent_checkpoint_id, "parent_checkpoint_id", optional=True)
        if not self.reason.strip():
            raise ValueError("checkpoint reason must not be empty")
        restored = UnifiedDNCryptState.from_mapping(self.state_payload)
        if restored.commitment != self.state_commitment:
            raise ValueError("unified checkpoint state commitment mismatch")
        return True

    @property
    def checkpoint_id(self) -> str:
        self.verify()
        return blake2b256(
            canonical_json_bytes(
                {
                    "schema": self.schema,
                    "state_payload": dict(self.state_payload),
                    "state_commitment": self.state_commitment,
                    "parent_checkpoint_id": self.parent_checkpoint_id,
                    "reason": self.reason,
                }
            )
        )


@dataclass(frozen=True, slots=True)
class UnifiedRollbackReceipt:
    from_state_commitment: str
    checkpoint_id: str
    restored_state_commitment: str
    restored_genome_id: str
    restored_surface_commitment: str
    restored_genetic_ir_id: str
    restored_pdna_id: str
    schema: str = ROLLBACK_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != ROLLBACK_SCHEMA:
            raise ValueError("unsupported unified rollback schema")
        for name, value in (
            ("from_state_commitment", self.from_state_commitment),
            ("checkpoint_id", self.checkpoint_id),
            ("restored_state_commitment", self.restored_state_commitment),
            ("restored_genome_id", self.restored_genome_id),
            ("restored_surface_commitment", self.restored_surface_commitment),
            ("restored_genetic_ir_id", self.restored_genetic_ir_id),
            ("restored_pdna_id", self.restored_pdna_id),
        ):
            _validate_digest(value, name)

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))


class UnifiedCheckpointPort(Protocol):
    def put(self, checkpoint: UnifiedCheckpoint) -> str: ...
    def get(self, checkpoint_id: str) -> UnifiedCheckpoint: ...


class InMemoryUnifiedCheckpointStore:
    def __init__(self) -> None:
        self._items: dict[str, UnifiedCheckpoint] = {}

    def put(self, checkpoint: UnifiedCheckpoint) -> str:
        checkpoint.verify()
        checkpoint_id = checkpoint.checkpoint_id
        existing = self._items.get(checkpoint_id)
        if existing is not None and existing != checkpoint:
            raise ValueError("unified checkpoint id collision")
        self._items[checkpoint_id] = checkpoint
        return checkpoint_id

    def get(self, checkpoint_id: str) -> UnifiedCheckpoint:
        _validate_digest(checkpoint_id, "checkpoint_id")
        try:
            checkpoint = self._items[checkpoint_id]
        except KeyError as exc:
            raise KeyError("unified checkpoint not found") from exc
        checkpoint.verify()
        return checkpoint


def create_unified_checkpoint(
    state: UnifiedDNCryptState,
    *,
    parent_checkpoint_id: str | None = None,
    reason: str = "unified-state-transition-boundary",
) -> UnifiedCheckpoint:
    checkpoint = UnifiedCheckpoint(
        state_payload=state.to_dict(),
        state_commitment=state.commitment,
        parent_checkpoint_id=parent_checkpoint_id,
        reason=reason,
    )
    checkpoint.verify()
    return checkpoint


def restore_unified_checkpoint(checkpoint: UnifiedCheckpoint) -> UnifiedDNCryptState:
    checkpoint.verify()
    state = UnifiedDNCryptState.from_mapping(checkpoint.state_payload)
    if state.commitment != checkpoint.state_commitment:
        raise ValueError("restored unified state commitment mismatch")
    return state


def rollback_unified_state(
    current_state: UnifiedDNCryptState,
    checkpoint: UnifiedCheckpoint,
    *,
    expected_current_state_commitment: str | None = None,
) -> tuple[UnifiedDNCryptState, UnifiedRollbackReceipt]:
    current_commitment = current_state.commitment
    if expected_current_state_commitment is not None:
        _validate_digest(expected_current_state_commitment, "expected_current_state_commitment")
        if current_commitment != expected_current_state_commitment:
            raise ValueError("unified state changed before rollback")

    restored = restore_unified_checkpoint(checkpoint)
    receipt = UnifiedRollbackReceipt(
        from_state_commitment=current_commitment,
        checkpoint_id=checkpoint.checkpoint_id,
        restored_state_commitment=restored.commitment,
        restored_genome_id=restored.genome.genome_id,
        restored_surface_commitment=restored.surface.commitment,
        restored_genetic_ir_id=restored.genetic_ir_id,
        restored_pdna_id=restored.pdna_id,
    )
    return restored, receipt


@dataclass(frozen=True, slots=True)
class UnifiedStateMemoryEvent:
    sequence: int
    event_type: str
    checkpoint_id: str
    state_commitment: str
    pdna_id: str
    previous_event_id: str | None
    rollback_receipt_digest: str | None = None
    schema: str = EVENT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != EVENT_SCHEMA:
            raise ValueError("unsupported unified state-memory event schema")
        if self.sequence < 0:
            raise ValueError("event sequence must be non-negative")
        if self.event_type not in {"CHECKPOINT", "ROLLBACK"}:
            raise ValueError("unsupported unified state-memory event type")
        _validate_digest(self.checkpoint_id, "checkpoint_id")
        _validate_digest(self.state_commitment, "state_commitment")
        _validate_digest(self.pdna_id, "pdna_id")
        _validate_digest(self.previous_event_id, "previous_event_id", optional=True)
        _validate_digest(
            self.rollback_receipt_digest,
            "rollback_receipt_digest",
            optional=self.event_type == "CHECKPOINT",
        )
        if self.event_type == "CHECKPOINT" and self.rollback_receipt_digest is not None:
            raise ValueError("checkpoint event cannot carry rollback receipt")
        if self.event_type == "ROLLBACK" and self.rollback_receipt_digest is None:
            raise ValueError("rollback event requires rollback receipt")

    @property
    def event_id(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))


@dataclass(frozen=True, slots=True)
class UnifiedJournalReceipt:
    event_count: int
    head_event_id: str
    active_checkpoint_id: str
    active_state_commitment: str
    active_pdna_id: str
    event_chain_commitment: str
    schema: str = JOURNAL_SCHEMA

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))


class UnifiedStateMemoryJournal:
    def __init__(self) -> None:
        self._events: list[UnifiedStateMemoryEvent] = []
        self._checkpoint_parents: dict[str, str | None] = {}
        self._checkpoint_pdna: dict[str, str] = {}
        self._checkpoint_state: dict[str, str] = {}

    @property
    def events(self) -> tuple[UnifiedStateMemoryEvent, ...]:
        return tuple(self._events)

    @property
    def active_checkpoint_id(self) -> str | None:
        return None if not self._events else self._events[-1].checkpoint_id

    @property
    def active_state_commitment(self) -> str | None:
        return None if not self._events else self._events[-1].state_commitment

    @property
    def active_pdna_id(self) -> str | None:
        return None if not self._events else self._events[-1].pdna_id

    def append_checkpoint(self, checkpoint: UnifiedCheckpoint) -> UnifiedStateMemoryEvent:
        checkpoint.verify()
        checkpoint_id = checkpoint.checkpoint_id
        if checkpoint_id in self._checkpoint_parents:
            raise ValueError("unified checkpoint already recorded")
        if checkpoint.parent_checkpoint_id != self.active_checkpoint_id:
            raise ValueError("unified checkpoint parent does not match active journal checkpoint")
        state = restore_unified_checkpoint(checkpoint)
        event = self._append_event(
            event_type="CHECKPOINT",
            checkpoint_id=checkpoint_id,
            state_commitment=state.commitment,
            pdna_id=state.pdna_id,
            rollback_receipt_digest=None,
        )
        self._checkpoint_parents[checkpoint_id] = checkpoint.parent_checkpoint_id
        self._checkpoint_pdna[checkpoint_id] = state.pdna_id
        self._checkpoint_state[checkpoint_id] = state.commitment
        return event

    def append_rollback(
        self,
        receipt: UnifiedRollbackReceipt,
    ) -> UnifiedStateMemoryEvent:
        if not self._events:
            raise ValueError("cannot record unified rollback before a checkpoint")
        if receipt.from_state_commitment != self.active_state_commitment:
            raise ValueError("rollback source state does not match active unified state")
        if receipt.checkpoint_id not in self._checkpoint_parents:
            raise ValueError("rollback target checkpoint is not recorded in unified journal")
        expected_pdna = self._checkpoint_pdna[receipt.checkpoint_id]
        expected_state = self._checkpoint_state[receipt.checkpoint_id]
        if receipt.restored_pdna_id != expected_pdna:
            raise ValueError("rollback restored PDNA does not match checkpoint lineage")
        if receipt.restored_state_commitment != expected_state:
            raise ValueError("rollback restored state does not match checkpoint lineage")
        return self._append_event(
            event_type="ROLLBACK",
            checkpoint_id=receipt.checkpoint_id,
            state_commitment=receipt.restored_state_commitment,
            pdna_id=receipt.restored_pdna_id,
            rollback_receipt_digest=receipt.digest,
        )

    def _append_event(
        self,
        *,
        event_type: str,
        checkpoint_id: str,
        state_commitment: str,
        pdna_id: str,
        rollback_receipt_digest: str | None,
    ) -> UnifiedStateMemoryEvent:
        event = UnifiedStateMemoryEvent(
            sequence=len(self._events),
            event_type=event_type,
            checkpoint_id=checkpoint_id,
            state_commitment=state_commitment,
            pdna_id=pdna_id,
            previous_event_id=None if not self._events else self._events[-1].event_id,
            rollback_receipt_digest=rollback_receipt_digest,
        )
        self._events.append(event)
        return event

    def receipt(self) -> UnifiedJournalReceipt:
        if not self._events:
            raise ValueError("empty unified state-memory journal has no receipt")
        event_ids = [event.event_id for event in self._events]
        return UnifiedJournalReceipt(
            event_count=len(self._events),
            head_event_id=event_ids[-1],
            active_checkpoint_id=self._events[-1].checkpoint_id,
            active_state_commitment=self._events[-1].state_commitment,
            active_pdna_id=self._events[-1].pdna_id,
            event_chain_commitment=blake2b256(canonical_json_bytes(event_ids)),
        )

    def verify(self) -> UnifiedJournalReceipt | None:
        if not self._events:
            if self._checkpoint_parents or self._checkpoint_pdna or self._checkpoint_state:
                raise ValueError("empty unified journal has checkpoint index state")
            return None
        previous: str | None = None
        known: set[str] = set()
        for index, event in enumerate(self._events):
            if event.sequence != index:
                raise ValueError("unified event sequence mismatch")
            if event.previous_event_id != previous:
                raise ValueError("unified event hash chain mismatch")
            if event.event_type == "CHECKPOINT":
                if event.checkpoint_id in known:
                    raise ValueError("duplicate unified checkpoint event")
                known.add(event.checkpoint_id)
            elif event.checkpoint_id not in known:
                raise ValueError("unified rollback targets unknown checkpoint")
            previous = event.event_id
        if known != set(self._checkpoint_parents):
            raise ValueError("unified checkpoint index diverges from journal")
        if known != set(self._checkpoint_pdna) or known != set(self._checkpoint_state):
            raise ValueError("unified checkpoint binding indexes diverge from journal")
        return self.receipt()


@dataclass(frozen=True, slots=True)
class UnifiedMonotonicAnchor:
    counter: int
    journal_receipt_digest: str
    event_count: int
    head_event_id: str
    active_checkpoint_id: str
    active_state_commitment: str
    active_pdna_id: str
    previous_anchor_digest: str | None
    schema: str = ANCHOR_SCHEMA

    def verify(self) -> bool:
        if self.schema != ANCHOR_SCHEMA:
            raise ValueError("unsupported unified monotonic anchor schema")
        if self.counter < 0 or self.event_count <= 0:
            raise ValueError("invalid unified monotonic counter/event_count")
        for name, value in (
            ("journal_receipt_digest", self.journal_receipt_digest),
            ("head_event_id", self.head_event_id),
            ("active_checkpoint_id", self.active_checkpoint_id),
            ("active_state_commitment", self.active_state_commitment),
            ("active_pdna_id", self.active_pdna_id),
        ):
            _validate_digest(value, name)
        _validate_digest(self.previous_anchor_digest, "previous_anchor_digest", optional=True)
        return True

    @property
    def digest(self) -> str:
        self.verify()
        return blake2b256(canonical_json_bytes(asdict(self)))


class UnifiedMonotonicAnchorPort(Protocol):
    def read(self) -> UnifiedMonotonicAnchor | None: ...
    def compare_and_advance(
        self,
        *,
        expected_previous_digest: str | None,
        new_anchor: UnifiedMonotonicAnchor,
    ) -> str: ...


class InMemoryUnifiedMonotonicAnchor:
    """Reference CAS witness for tests; not durable production authority."""

    def __init__(self) -> None:
        self._current: UnifiedMonotonicAnchor | None = None

    def read(self) -> UnifiedMonotonicAnchor | None:
        return self._current

    def compare_and_advance(
        self,
        *,
        expected_previous_digest: str | None,
        new_anchor: UnifiedMonotonicAnchor,
    ) -> str:
        new_anchor.verify()
        current = self._current
        actual_previous = current.digest if current is not None else None
        if expected_previous_digest != actual_previous:
            raise ValueError("unified monotonic anchor compare-and-swap mismatch")
        expected_counter = 0 if current is None else current.counter + 1
        if new_anchor.counter != expected_counter:
            raise ValueError("unified monotonic anchor counter must advance exactly once")
        if new_anchor.previous_anchor_digest != actual_previous:
            raise ValueError("unified monotonic anchor previous digest mismatch")
        if current is not None and new_anchor.event_count <= current.event_count:
            raise ValueError("unified monotonic event_count must strictly increase")
        self._current = new_anchor
        return new_anchor.digest


def advance_unified_journal_anchor(
    journal: UnifiedStateMemoryJournal,
    port: UnifiedMonotonicAnchorPort,
) -> UnifiedMonotonicAnchor:
    receipt = journal.receipt()
    current = port.read()
    previous_digest = current.digest if current is not None else None
    anchor = UnifiedMonotonicAnchor(
        counter=0 if current is None else current.counter + 1,
        journal_receipt_digest=receipt.digest,
        event_count=receipt.event_count,
        head_event_id=receipt.head_event_id,
        active_checkpoint_id=receipt.active_checkpoint_id,
        active_state_commitment=receipt.active_state_commitment,
        active_pdna_id=receipt.active_pdna_id,
        previous_anchor_digest=previous_digest,
    )
    port.compare_and_advance(
        expected_previous_digest=previous_digest,
        new_anchor=anchor,
    )
    return anchor


def verify_unified_journal_against_anchor(
    journal: UnifiedStateMemoryJournal,
    port: UnifiedMonotonicAnchorPort,
) -> UnifiedMonotonicAnchor:
    current = port.read()
    if current is None:
        raise ValueError("unified monotonic anchor is uninitialized")
    current.verify()
    receipt = journal.receipt()
    checks = (
        (receipt.digest == current.journal_receipt_digest, "unified journal receipt diverged from monotonic anchor"),
        (receipt.event_count == current.event_count, "unified journal event_count mismatch"),
        (receipt.head_event_id == current.head_event_id, "unified journal head mismatch"),
        (receipt.active_checkpoint_id == current.active_checkpoint_id, "unified active checkpoint mismatch"),
        (receipt.active_state_commitment == current.active_state_commitment, "unified active state mismatch"),
        (receipt.active_pdna_id == current.active_pdna_id, "unified active PDNA mismatch"),
    )
    failed = next((reason for ok, reason in checks if not ok), None)
    if failed is not None:
        raise ValueError(failed)
    return current


__all__ = [
    "ANCHOR_SCHEMA",
    "CHECKPOINT_SCHEMA",
    "EVENT_SCHEMA",
    "JOURNAL_SCHEMA",
    "ROLLBACK_SCHEMA",
    "InMemoryUnifiedCheckpointStore",
    "InMemoryUnifiedMonotonicAnchor",
    "UnifiedCheckpoint",
    "UnifiedCheckpointPort",
    "UnifiedJournalReceipt",
    "UnifiedMonotonicAnchor",
    "UnifiedMonotonicAnchorPort",
    "UnifiedRollbackReceipt",
    "UnifiedStateMemoryEvent",
    "UnifiedStateMemoryJournal",
    "advance_unified_journal_anchor",
    "create_unified_checkpoint",
    "restore_unified_checkpoint",
    "rollback_unified_state",
    "verify_unified_journal_against_anchor",
]
