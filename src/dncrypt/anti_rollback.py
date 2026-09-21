from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Protocol

from .state_memory_journal import StateMemoryJournal
from .util import blake2b256, canonical_json_bytes

ANCHOR_SCHEMA = "dncrypt.monotonic-journal-anchor/v0.5.2"


def _validate_digest(value: str, name: str) -> None:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{name} must be a 64-character hex digest")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{name} must be hexadecimal") from exc


@dataclass(frozen=True, slots=True)
class MonotonicJournalAnchor:
    schema: str
    counter: int
    journal_receipt_digest: str
    event_count: int
    head_event_id: str
    active_checkpoint_id: str
    active_state_commitment: str
    previous_anchor_digest: str | None

    def verify(self) -> None:
        if self.schema != ANCHOR_SCHEMA:
            raise ValueError("unsupported monotonic anchor schema")
        if self.counter < 0 or self.event_count <= 0:
            raise ValueError("invalid monotonic anchor counter/event_count")
        _validate_digest(self.journal_receipt_digest, "journal_receipt_digest")
        _validate_digest(self.head_event_id, "head_event_id")
        _validate_digest(self.active_checkpoint_id, "active_checkpoint_id")
        _validate_digest(self.active_state_commitment, "active_state_commitment")
        if self.previous_anchor_digest is not None:
            _validate_digest(self.previous_anchor_digest, "previous_anchor_digest")

    @property
    def digest(self) -> str:
        self.verify()
        return blake2b256(canonical_json_bytes(asdict(self)))


class MonotonicAnchorPort(Protocol):
    """External monotonic witness boundary.

    A production implementation should live outside the rollbackable DNCrypt state
    (for example TPM/HSM-backed storage or a remote append-only service).
    """

    def read(self) -> MonotonicJournalAnchor | None: ...
    def compare_and_advance(
        self,
        *,
        expected_previous_digest: str | None,
        new_anchor: MonotonicJournalAnchor,
    ) -> str: ...


class InMemoryMonotonicAnchor:
    """Reference CAS anchor for tests. Not a durable anti-rollback authority."""

    def __init__(self) -> None:
        self._current: MonotonicJournalAnchor | None = None

    def read(self) -> MonotonicJournalAnchor | None:
        return self._current

    def compare_and_advance(
        self,
        *,
        expected_previous_digest: str | None,
        new_anchor: MonotonicJournalAnchor,
    ) -> str:
        new_anchor.verify()
        current = self._current
        actual_previous = current.digest if current is not None else None
        if expected_previous_digest != actual_previous:
            raise ValueError("monotonic anchor compare-and-swap mismatch")
        expected_counter = 0 if current is None else current.counter + 1
        if new_anchor.counter != expected_counter:
            raise ValueError("monotonic anchor counter must advance exactly once")
        if new_anchor.previous_anchor_digest != actual_previous:
            raise ValueError("monotonic anchor previous digest mismatch")
        if current is not None and new_anchor.event_count <= current.event_count:
            raise ValueError("monotonic anchor event_count must strictly increase")
        self._current = new_anchor
        return new_anchor.digest


def _anchor_from_journal(
    journal: StateMemoryJournal,
    *,
    counter: int,
    previous_anchor_digest: str | None,
) -> MonotonicJournalAnchor:
    receipt = journal.receipt()
    anchor = MonotonicJournalAnchor(
        schema=ANCHOR_SCHEMA,
        counter=counter,
        journal_receipt_digest=receipt.digest,
        event_count=receipt.event_count,
        head_event_id=receipt.head_event_id,
        active_checkpoint_id=receipt.active_checkpoint_id,
        active_state_commitment=receipt.active_state_commitment,
        previous_anchor_digest=previous_anchor_digest,
    )
    anchor.verify()
    return anchor


def advance_journal_anchor(
    journal: StateMemoryJournal,
    port: MonotonicAnchorPort,
) -> MonotonicJournalAnchor:
    current = port.read()
    previous_digest = current.digest if current is not None else None
    counter = 0 if current is None else current.counter + 1
    candidate = _anchor_from_journal(
        journal,
        counter=counter,
        previous_anchor_digest=previous_digest,
    )
    port.compare_and_advance(
        expected_previous_digest=previous_digest,
        new_anchor=candidate,
    )
    return candidate


def verify_journal_against_anchor(
    journal: StateMemoryJournal,
    port: MonotonicAnchorPort,
) -> MonotonicJournalAnchor:
    current = port.read()
    if current is None:
        raise ValueError("monotonic anchor is uninitialized")
    current.verify()
    receipt = journal.receipt()
    checks = (
        (receipt.digest == current.journal_receipt_digest, "journal receipt is older or diverged from monotonic anchor"),
        (receipt.event_count == current.event_count, "journal event_count mismatch against monotonic anchor"),
        (receipt.head_event_id == current.head_event_id, "journal head mismatch against monotonic anchor"),
        (receipt.active_checkpoint_id == current.active_checkpoint_id, "active checkpoint mismatch against monotonic anchor"),
        (receipt.active_state_commitment == current.active_state_commitment, "active state mismatch against monotonic anchor"),
    )
    failed = next((reason for ok, reason in checks if not ok), None)
    if failed is not None:
        raise ValueError(failed)
    return current
