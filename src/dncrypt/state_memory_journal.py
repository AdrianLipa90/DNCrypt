from __future__ import annotations

from dataclasses import asdict, dataclass

from .checkpoint_lineage import CheckpointLineageReceipt
from .checkpoint_port import DNCryptCheckpoint, RollbackReceipt
from .util import blake2b256, canonical_json_bytes

EVENT_SCHEMA = "dncrypt.state-memory-event/v0.5-candidate"
JOURNAL_SCHEMA = "dncrypt.state-memory-journal-receipt/v0.5-candidate"
_EVENT_TYPES = frozenset({"CHECKPOINT", "ROLLBACK"})


@dataclass(frozen=True, slots=True)
class StateMemoryEvent:
    schema: str
    sequence: int
    previous_event_id: str | None
    event_type: str
    checkpoint_id: str
    state_commitment: str
    rollback_receipt_digest: str | None
    lineage_receipt_digest: str | None

    @property
    def event_id(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))

    def verify(self) -> None:
        if self.schema != EVENT_SCHEMA:
            raise ValueError("unsupported state-memory event schema")
        if self.sequence < 0:
            raise ValueError("event sequence must be non-negative")
        if self.previous_event_id is not None:
            _validate_digest(self.previous_event_id, "previous_event_id")
        if self.event_type not in _EVENT_TYPES:
            raise ValueError("unsupported state-memory event type")
        _validate_digest(self.checkpoint_id, "checkpoint_id")
        _validate_digest(self.state_commitment, "state_commitment")
        if self.event_type == "CHECKPOINT":
            if self.rollback_receipt_digest is not None or self.lineage_receipt_digest is not None:
                raise ValueError("checkpoint event must not carry rollback receipts")
        else:
            if self.rollback_receipt_digest is None or self.lineage_receipt_digest is None:
                raise ValueError("rollback event requires rollback and lineage receipts")
            _validate_digest(self.rollback_receipt_digest, "rollback_receipt_digest")
            _validate_digest(self.lineage_receipt_digest, "lineage_receipt_digest")


@dataclass(frozen=True, slots=True)
class StateMemoryJournalReceipt:
    schema: str
    event_count: int
    root_event_id: str
    head_event_id: str
    active_checkpoint_id: str
    active_state_commitment: str
    event_chain_commitment: str

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))


class StateMemoryJournal:
    """Append-only logical memory for v0.5.

    The journal owns DNCrypt-specific checkpoint/rollback lineage only. Durable storage
    and PNFS/PNH5 integration remain behind external adapters in v0.6.
    """

    def __init__(self) -> None:
        self._events: list[StateMemoryEvent] = []
        self._checkpoint_parents: dict[str, str | None] = {}

    @property
    def events(self) -> tuple[StateMemoryEvent, ...]:
        return tuple(self._events)

    @property
    def active_checkpoint_id(self) -> str | None:
        if not self._events:
            return None
        return self._events[-1].checkpoint_id

    @property
    def active_state_commitment(self) -> str | None:
        if not self._events:
            return None
        return self._events[-1].state_commitment

    def append_checkpoint(self, checkpoint: DNCryptCheckpoint) -> StateMemoryEvent:
        checkpoint.verify()
        checkpoint_id = checkpoint.checkpoint_id
        if checkpoint_id in self._checkpoint_parents:
            raise ValueError("checkpoint already recorded in state-memory journal")
        expected_parent = self.active_checkpoint_id
        if checkpoint.parent_checkpoint_id != expected_parent:
            raise ValueError("checkpoint parent does not match active journal checkpoint")
        event = self._new_event(
            event_type="CHECKPOINT",
            checkpoint_id=checkpoint_id,
            state_commitment=checkpoint.state_commitment,
            rollback_receipt_digest=None,
            lineage_receipt_digest=None,
        )
        self._events.append(event)
        self._checkpoint_parents[checkpoint_id] = checkpoint.parent_checkpoint_id
        self.verify()
        return event

    def append_rollback(
        self,
        rollback_receipt: RollbackReceipt,
        lineage_receipt: CheckpointLineageReceipt,
    ) -> StateMemoryEvent:
        if not self._events:
            raise ValueError("cannot record rollback before a checkpoint")
        if lineage_receipt.schema != "dncrypt.checkpoint-lineage-receipt/v0.5-candidate":
            raise ValueError("unsupported lineage receipt schema")
        if not lineage_receipt.pass_ancestry:
            raise ValueError("rollback lineage did not pass ancestry")
        if lineage_receipt.head_checkpoint_id != self.active_checkpoint_id:
            raise ValueError("rollback lineage head does not match active checkpoint")
        if rollback_receipt.checkpoint_id != lineage_receipt.target_checkpoint_id:
            raise ValueError("rollback target does not match lineage target")
        if rollback_receipt.from_state_commitment != self.active_state_commitment:
            raise ValueError("rollback source state does not match active state")
        if rollback_receipt.restored_state_commitment != lineage_receipt.target_state_commitment:
            raise ValueError("rollback restored state does not match lineage target state")
        if rollback_receipt.checkpoint_id not in self._checkpoint_parents:
            raise ValueError("rollback target checkpoint is not recorded in journal")
        event = self._new_event(
            event_type="ROLLBACK",
            checkpoint_id=rollback_receipt.checkpoint_id,
            state_commitment=rollback_receipt.restored_state_commitment,
            rollback_receipt_digest=rollback_receipt.digest,
            lineage_receipt_digest=lineage_receipt.digest,
        )
        self._events.append(event)
        self.verify()
        return event

    def verify(self, *, expected_receipt_digest: str | None = None) -> StateMemoryJournalReceipt | None:
        if expected_receipt_digest is not None:
            _validate_digest(expected_receipt_digest, "expected_receipt_digest")
        if not self._events:
            if self._checkpoint_parents:
                raise ValueError("empty journal has checkpoint index state")
            if expected_receipt_digest is not None:
                raise ValueError("empty journal cannot match expected receipt")
            return None

        previous_id: str | None = None
        active_checkpoint: str | None = None
        active_state: str | None = None
        known: dict[str, str | None] = {}
        event_ids: list[str] = []

        for sequence, event in enumerate(self._events):
            event.verify()
            if event.sequence != sequence:
                raise ValueError("state-memory event sequence mismatch")
            if event.previous_event_id != previous_id:
                raise ValueError("state-memory hash chain mismatch")

            if event.event_type == "CHECKPOINT":
                if event.checkpoint_id in known:
                    raise ValueError("duplicate checkpoint event")
                expected_parent = active_checkpoint
                sentinel = object()
                indexed_parent = self._checkpoint_parents.get(event.checkpoint_id, sentinel)
                if indexed_parent is sentinel:
                    raise ValueError("checkpoint index missing journal checkpoint")
                if indexed_parent != expected_parent:
                    raise ValueError("checkpoint parent/index mismatch")
                known[event.checkpoint_id] = indexed_parent  # type: ignore[assignment]
            else:
                if event.checkpoint_id not in known:
                    raise ValueError("rollback targets unknown checkpoint")

            active_checkpoint = event.checkpoint_id
            active_state = event.state_commitment
            previous_id = event.event_id
            event_ids.append(previous_id)

        if known != self._checkpoint_parents:
            raise ValueError("checkpoint index diverges from journal")
        assert active_checkpoint is not None and active_state is not None
        receipt = StateMemoryJournalReceipt(
            schema=JOURNAL_SCHEMA,
            event_count=len(self._events),
            root_event_id=event_ids[0],
            head_event_id=event_ids[-1],
            active_checkpoint_id=active_checkpoint,
            active_state_commitment=active_state,
            event_chain_commitment=blake2b256(canonical_json_bytes(event_ids)),
        )
        if expected_receipt_digest is not None and receipt.digest != expected_receipt_digest:
            raise ValueError("state-memory journal receipt mismatch")
        return receipt

    def receipt(self) -> StateMemoryJournalReceipt:
        receipt = self.verify()
        if receipt is None:
            raise ValueError("empty state-memory journal has no receipt")
        return receipt

    def _new_event(
        self,
        *,
        event_type: str,
        checkpoint_id: str,
        state_commitment: str,
        rollback_receipt_digest: str | None,
        lineage_receipt_digest: str | None,
    ) -> StateMemoryEvent:
        event = StateMemoryEvent(
            schema=EVENT_SCHEMA,
            sequence=len(self._events),
            previous_event_id=self._events[-1].event_id if self._events else None,
            event_type=event_type,
            checkpoint_id=checkpoint_id,
            state_commitment=state_commitment,
            rollback_receipt_digest=rollback_receipt_digest,
            lineage_receipt_digest=lineage_receipt_digest,
        )
        event.verify()
        return event


def _validate_digest(value: str, name: str) -> None:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{name} must be a 64-character hex digest")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{name} must be hexadecimal") from exc
