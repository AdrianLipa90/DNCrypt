from __future__ import annotations

import pytest

from dncrypt.anti_rollback import (
    InMemoryMonotonicAnchor,
    advance_journal_anchor,
    verify_journal_against_anchor,
)
from dncrypt.checkpoint_port import InMemoryCheckpointStore, create_checkpoint
from dncrypt.genome import initial_genome, mutate_genome
from dncrypt.state import DNCryptState
from dncrypt.state_memory_journal import StateMemoryJournal
from dncrypt.surface import evolve_surface, initial_surface


def _states_and_checkpoints():
    store = InMemoryCheckpointStore()
    g0 = initial_genome(bytes(range(64)))
    s0 = DNCryptState(g0, initial_surface(g0), "m0", "e0")
    c0 = create_checkpoint(s0, reason="root")
    id0 = store.put(c0)

    g1 = mutate_genome(g0, bytes([17]) * 64)
    s1 = DNCryptState(g1, evolve_surface(s0.surface, g1, steps=2), "m1", "e1")
    c1 = create_checkpoint(s1, parent_checkpoint_id=id0, reason="generation-1")
    store.put(c1)
    return c0, c1


def test_external_anchor_detects_full_local_journal_replay():
    c0, c1 = _states_and_checkpoints()
    anchor = InMemoryMonotonicAnchor()

    current = StateMemoryJournal()
    current.append_checkpoint(c0)
    first = advance_journal_anchor(current, anchor)
    assert first.counter == 0

    old_snapshot = StateMemoryJournal()
    old_snapshot.append_checkpoint(c0)

    current.append_checkpoint(c1)
    second = advance_journal_anchor(current, anchor)
    assert second.counter == 1
    assert second.previous_anchor_digest == first.digest
    assert verify_journal_against_anchor(current, anchor) == second

    with pytest.raises(ValueError, match="older or diverged|event_count mismatch|head mismatch"):
        verify_journal_against_anchor(old_snapshot, anchor)


def test_anchor_compare_and_swap_rejects_stale_writer():
    c0, c1 = _states_and_checkpoints()
    anchor = InMemoryMonotonicAnchor()
    journal = StateMemoryJournal()
    journal.append_checkpoint(c0)
    first = advance_journal_anchor(journal, anchor)
    journal.append_checkpoint(c1)
    second = advance_journal_anchor(journal, anchor)

    with pytest.raises(ValueError, match="compare-and-swap mismatch"):
        anchor.compare_and_advance(
            expected_previous_digest=first.digest,
            new_anchor=second,
        )


def test_anchor_requires_strictly_increasing_journal_history():
    c0, _ = _states_and_checkpoints()
    anchor = InMemoryMonotonicAnchor()
    journal = StateMemoryJournal()
    journal.append_checkpoint(c0)
    advance_journal_anchor(journal, anchor)

    with pytest.raises(ValueError, match="strictly increase"):
        advance_journal_anchor(journal, anchor)


def test_uninitialized_anchor_fails_closed():
    c0, _ = _states_and_checkpoints()
    journal = StateMemoryJournal()
    journal.append_checkpoint(c0)
    with pytest.raises(ValueError, match="uninitialized"):
        verify_journal_against_anchor(journal, InMemoryMonotonicAnchor())
