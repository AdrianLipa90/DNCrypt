from dataclasses import replace

import pytest

from dncrypt.checkpoint_port import (
    DNCryptCheckpoint,
    InMemoryCheckpointStore,
    create_checkpoint,
    rollback_to_checkpoint,
    state_commitment,
)
from dncrypt.genome import initial_genome, mutate_genome
from dncrypt.state import DNCryptState
from dncrypt.surface import evolve_surface, initial_surface


def _state0() -> DNCryptState:
    genome = initial_genome(bytes(range(64)))
    surface = initial_surface(genome)
    return DNCryptState(genome, surface, "msg-receipt-0", "evolution-receipt-0")


def test_exact_rollback_restores_full_dncrypt_state():
    original = _state0()
    checkpoint = create_checkpoint(original, reason="before-candidate-promotion")
    store = InMemoryCheckpointStore()
    checkpoint_id = store.put(checkpoint)

    child = mutate_genome(original.genome, bytes(reversed(range(64))))
    advanced = DNCryptState(
        child,
        evolve_surface(original.surface, child, steps=7),
        "msg-receipt-1",
        "evolution-receipt-1",
    )
    restored, receipt = rollback_to_checkpoint(
        advanced,
        store.get(checkpoint_id),
        expected_current_state_commitment=state_commitment(advanced),
    )

    assert restored == original
    assert receipt.from_state_commitment == state_commitment(advanced)
    assert receipt.restored_state_commitment == state_commitment(original)
    assert receipt.restored_genome_id == original.genome.genome_id
    assert receipt.restored_surface_commitment == original.surface.commitment
    assert receipt.restored_tick == original.surface.tick


def test_checkpoint_detects_payload_tampering():
    original = _state0()
    checkpoint = create_checkpoint(original)
    payload = dict(checkpoint.state_payload)
    surface = dict(payload["surface"])
    surface["tick"] = 9
    payload["surface"] = surface
    tampered = replace(checkpoint, state_payload=payload)
    with pytest.raises(ValueError, match="commitment mismatch"):
        tampered.verify()


def test_rollback_fails_if_current_state_changed_after_authorization():
    original = _state0()
    checkpoint = create_checkpoint(original)
    child = mutate_genome(original.genome, bytes([3]) * 64)
    advanced = DNCryptState(child, evolve_surface(original.surface, child, steps=1))
    with pytest.raises(ValueError, match="changed before rollback"):
        rollback_to_checkpoint(
            advanced,
            checkpoint,
            expected_current_state_commitment=state_commitment(original),
        )
