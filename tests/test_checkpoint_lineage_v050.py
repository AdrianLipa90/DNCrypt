import pytest

from dncrypt.checkpoint_lineage import rollback_to_ancestor, verify_checkpoint_ancestry
from dncrypt.checkpoint_port import InMemoryCheckpointStore, create_checkpoint, state_commitment
from dncrypt.genome import initial_genome, mutate_genome
from dncrypt.state import DNCryptState
from dncrypt.surface import evolve_surface, initial_surface


def _chain():
    store = InMemoryCheckpointStore()
    g0 = initial_genome(bytes(range(64)))
    s0 = DNCryptState(g0, initial_surface(g0), "m0", "e0")
    c0 = create_checkpoint(s0, reason="root")
    id0 = store.put(c0)

    g1 = mutate_genome(g0, bytes([17]) * 64)
    s1 = DNCryptState(g1, evolve_surface(s0.surface, g1, steps=2), "m1", "e1")
    c1 = create_checkpoint(s1, parent_checkpoint_id=id0, reason="generation-1")
    id1 = store.put(c1)

    g2 = mutate_genome(g1, bytes([29]) * 64)
    s2 = DNCryptState(g2, evolve_surface(s1.surface, g2, steps=3), "m2", "e2")
    c2 = create_checkpoint(s2, parent_checkpoint_id=id1, reason="generation-2")
    id2 = store.put(c2)
    return store, (s0, s1, s2), (id0, id1, id2)


def test_ancestry_receipt_and_exact_rollback_to_root():
    store, states, ids = _chain()
    receipt = verify_checkpoint_ancestry(store, ids[2], ids[0])
    assert receipt.pass_ancestry
    assert receipt.path_head_to_target == (ids[2], ids[1], ids[0])
    assert receipt.ancestry_depth == 2
    restored, rollback, lineage = rollback_to_ancestor(
        states[2], store, ids[2], ids[0],
        expected_current_state_commitment=state_commitment(states[2]),
    )
    assert restored == states[0]
    assert rollback.checkpoint_id == ids[0]
    assert lineage.digest == receipt.digest


def test_unrelated_checkpoint_is_rejected():
    store, states, ids = _chain()
    other_g = initial_genome(bytes([91]) * 64)
    other_s = DNCryptState(other_g, initial_surface(other_g))
    other_id = store.put(create_checkpoint(other_s, reason="unrelated-root"))
    with pytest.raises(ValueError, match="not an ancestor"):
        rollback_to_ancestor(states[2], store, ids[2], other_id)


def test_missing_parent_is_rejected_fail_closed():
    store, _, ids = _chain()
    head = store.get(ids[2])
    from dataclasses import replace
    missing = "a" * 64
    broken = replace(head, parent_checkpoint_id=missing)
    store._items[broken.checkpoint_id] = broken
    with pytest.raises(ValueError, match="missing node"):
        verify_checkpoint_ancestry(store, broken.checkpoint_id, ids[0])


def test_cycle_is_rejected_fail_closed():
    class FakeCheckpoint:
        def __init__(self, checkpoint_id, parent_checkpoint_id):
            self._checkpoint_id = checkpoint_id
            self.parent_checkpoint_id = parent_checkpoint_id
            self.state_commitment = "d" * 64
        @property
        def checkpoint_id(self):
            return self._checkpoint_id
        def verify(self):
            return None

    a, b, target = "a" * 64, "b" * 64, "c" * 64
    class CycleStore:
        def get(self, checkpoint_id):
            if checkpoint_id == a:
                return FakeCheckpoint(a, b)
            if checkpoint_id == b:
                return FakeCheckpoint(b, a)
            raise KeyError(checkpoint_id)

    with pytest.raises(ValueError, match="cycle detected"):
        verify_checkpoint_ancestry(CycleStore(), a, target)


def test_current_state_must_match_head_checkpoint():
    store, states, ids = _chain()
    with pytest.raises(ValueError, match="does not match current checkpoint"):
        rollback_to_ancestor(states[1], store, ids[2], ids[0])
