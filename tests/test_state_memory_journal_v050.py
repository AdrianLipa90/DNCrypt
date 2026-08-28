from dataclasses import replace

import pytest

from dncrypt.checkpoint_lineage import rollback_to_ancestor
from dncrypt.checkpoint_port import InMemoryCheckpointStore, create_checkpoint, state_commitment
from dncrypt.genome import initial_genome, mutate_genome
from dncrypt.state import DNCryptState
from dncrypt.state_memory_journal import StateMemoryJournal
from dncrypt.surface import evolve_surface, initial_surface


def _recorded_chain():
    store = InMemoryCheckpointStore()
    journal = StateMemoryJournal()

    g0 = initial_genome(bytes(range(64)))
    s0 = DNCryptState(g0, initial_surface(g0), "m0", "e0")
    c0 = create_checkpoint(s0, reason="root")
    id0 = store.put(c0)
    journal.append_checkpoint(c0)

    g1 = mutate_genome(g0, bytes([17]) * 64)
    s1 = DNCryptState(g1, evolve_surface(s0.surface, g1, steps=2), "m1", "e1")
    c1 = create_checkpoint(s1, parent_checkpoint_id=id0, reason="generation-1")
    id1 = store.put(c1)
    journal.append_checkpoint(c1)

    g2 = mutate_genome(g1, bytes([29]) * 64)
    s2 = DNCryptState(g2, evolve_surface(s1.surface, g2, steps=3), "m2", "e2")
    c2 = create_checkpoint(s2, parent_checkpoint_id=id1, reason="generation-2")
    id2 = store.put(c2)
    journal.append_checkpoint(c2)
    return store, journal, (s0, s1, s2), (id0, id1, id2)


def test_append_only_journal_records_rollback_and_reopens_branch():
    store, journal, states, ids = _recorded_chain()
    restored, rollback, lineage = rollback_to_ancestor(
        states[2], store, ids[2], ids[0],
        expected_current_state_commitment=state_commitment(states[2]),
    )
    event = journal.append_rollback(rollback, lineage)
    assert event.event_type == "ROLLBACK"
    assert journal.active_checkpoint_id == ids[0]
    assert journal.active_state_commitment == state_commitment(restored)

    branch_g = mutate_genome(restored.genome, bytes([61]) * 64)
    branch_s = DNCryptState(branch_g, evolve_surface(restored.surface, branch_g, steps=1), "mb", "eb")
    branch_c = create_checkpoint(branch_s, parent_checkpoint_id=ids[0], reason="post-rollback-branch")
    branch_id = store.put(branch_c)
    journal.append_checkpoint(branch_c)

    receipt = journal.receipt()
    assert receipt.event_count == 5
    assert receipt.active_checkpoint_id == branch_id
    assert receipt.active_state_commitment == state_commitment(branch_s)
    assert len(receipt.event_chain_commitment) == 64
    assert len(receipt.digest) == 64


def test_journal_hash_chain_detects_event_tampering():
    _, journal, _, _ = _recorded_chain()
    event = journal._events[1]
    journal._events[1] = replace(event, state_commitment="0" * 64)
    with pytest.raises(ValueError, match="hash chain mismatch"):
        journal.verify()


def test_journal_detects_checkpoint_index_tampering():
    _, journal, _, ids = _recorded_chain()
    del journal._checkpoint_parents[ids[1]]
    with pytest.raises(ValueError, match="index missing|diverges"):
        journal.verify()


def test_checkpoint_parent_must_follow_active_state_after_rollback():
    store, journal, states, ids = _recorded_chain()
    _, rollback, lineage = rollback_to_ancestor(states[2], store, ids[2], ids[0])
    journal.append_rollback(rollback, lineage)
    g = mutate_genome(states[1].genome, bytes([83]) * 64)
    s = DNCryptState(g, evolve_surface(states[1].surface, g, steps=1))
    wrong_parent = create_checkpoint(s, parent_checkpoint_id=ids[1], reason="wrong-branch")
    with pytest.raises(ValueError, match="parent does not match active"):
        journal.append_checkpoint(wrong_parent)


def test_rollback_receipts_must_bind_active_head_and_target():
    store, journal, states, ids = _recorded_chain()
    _, rollback, lineage = rollback_to_ancestor(states[2], store, ids[2], ids[0])
    bad = replace(rollback, from_state_commitment="f" * 64)
    with pytest.raises(ValueError, match="source state"):
        journal.append_rollback(bad, lineage)


def test_frozen_journal_receipt_detects_tail_tampering():
    _, journal, _, _ = _recorded_chain()
    frozen = journal.receipt().digest
    tail = journal._events[-1]
    journal._events[-1] = replace(tail, state_commitment="1" * 64)
    with pytest.raises(ValueError, match="journal receipt mismatch"):
        journal.verify(expected_receipt_digest=frozen)
