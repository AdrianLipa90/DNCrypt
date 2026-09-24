from __future__ import annotations

from dataclasses import replace

import pytest

from dncrypt.genetic_compiler import compile_genetic_program
from dncrypt.genetic_ir import GeneticIRNode, GeneticLevel, rewrite_payload
from dncrypt.genome import initial_genome, mutate_genome
from dncrypt.state import DNCryptState
from dncrypt.surface import initial_surface, transition_surface
from dncrypt.unified_checkpoint import (
    InMemoryUnifiedCheckpointStore,
    InMemoryUnifiedMonotonicAnchor,
    UnifiedStateMemoryJournal,
    advance_unified_journal_anchor,
    create_unified_checkpoint,
    rollback_unified_state,
    verify_unified_journal_against_anchor,
)
from dncrypt.unified_state import (
    UnifiedDNCryptState,
    bind_unified_state,
    transition_unified_state,
)


def sample_program() -> GeneticIRNode:
    k = GeneticIRNode("k1", GeneticLevel.KAKU, {"symbol": "A"})
    r = GeneticIRNode("r1", GeneticLevel.RADICAL, {"motif": "m"}, (k,))
    c = GeneticIRNode("c1", GeneticLevel.CONCEPT, {}, (r,))
    return GeneticIRNode("s1", GeneticLevel.SENTENCE, {"record": "x"}, (c,))


def state0() -> UnifiedDNCryptState:
    genome = initial_genome(bytes(range(64)))
    core = DNCryptState(genome, initial_surface(genome), "msg-0", "evo-0")
    return bind_unified_state(
        core,
        sample_program(),
        evidence_commitment="1" * 64,
    )


def test_unified_state_closes_genome_surface_genetics_and_pdna():
    state = state0()
    assert state.genetic_ir_id == state.program.semantic_id
    assert state.compiler_commitment == compile_genetic_program(state.program).commitment
    assert state.verify_pdna()
    assert state.pdna.metadata["surface_commitment"] == state.surface.commitment
    assert state.pdna.metadata["closure_commitment"] == state.closure_commitment
    assert len(state.commitment) == 64

    recovered = UnifiedDNCryptState.from_mapping(state.to_dict())
    assert recovered.commitment == state.commitment
    assert recovered.pdna_id == state.pdna_id


def test_unified_state_rejects_cross_plane_pdna_or_program_mismatch():
    state = state0()
    changed_program, _ = rewrite_payload(state.program, "r1", {"motif": "other"})
    changed = bind_unified_state(
        state.core_state,
        changed_program,
        evidence_commitment=state.evidence_commitment,
    )

    with pytest.raises(ValueError, match="Genetic IR"):
        state.verify_pdna(changed.pdna)

    value = state.to_dict()
    value["pdna_id"] = "0" * 64
    with pytest.raises(ValueError, match="PDNA commitment mismatch"):
        UnifiedDNCryptState.from_mapping(value)


def test_transition_advances_pdna_lineage_and_checkpoint_restores_all_planes():
    original = state0()
    cp0 = create_unified_checkpoint(original, reason="before-genetic-promotion")
    store = InMemoryUnifiedCheckpointStore()
    cp0_id = store.put(cp0)

    child_genome = mutate_genome(original.genome, b"z" * 64)
    child_surface = transition_surface(original.surface, child_genome, steps=3)
    changed_program, _ = rewrite_payload(original.program, "r1", {"motif": "next"})
    child_core = DNCryptState(child_genome, child_surface, "msg-1", "evo-1")
    advanced = transition_unified_state(
        original,
        core_state=child_core,
        program=changed_program,
        evidence_commitment="2" * 64,
    )
    assert advanced.parent_pdna_id == original.pdna_id
    assert advanced.pdna_id != original.pdna_id

    restored, receipt = rollback_unified_state(
        advanced,
        store.get(cp0_id),
        expected_current_state_commitment=advanced.commitment,
    )
    assert restored.commitment == original.commitment
    assert restored.genetic_ir_id == original.genetic_ir_id
    assert restored.pdna_id == original.pdna_id
    assert receipt.restored_genetic_ir_id == original.genetic_ir_id
    assert receipt.restored_pdna_id == original.pdna_id


def test_unified_journal_and_external_anchor_bind_pdna_head():
    original = state0()
    cp0 = create_unified_checkpoint(original)
    journal = UnifiedStateMemoryJournal()
    journal.append_checkpoint(cp0)

    port = InMemoryUnifiedMonotonicAnchor()
    anchor0 = advance_unified_journal_anchor(journal, port)
    assert anchor0.active_pdna_id == original.pdna_id
    assert verify_unified_journal_against_anchor(journal, port) == anchor0

    child_genome = mutate_genome(original.genome, b"k" * 64)
    child_core = DNCryptState(
        child_genome,
        transition_surface(original.surface, child_genome, steps=1),
    )
    child = transition_unified_state(original, core_state=child_core)
    cp1 = create_unified_checkpoint(child, parent_checkpoint_id=cp0.checkpoint_id)
    journal.append_checkpoint(cp1)
    anchor1 = advance_unified_journal_anchor(journal, port)
    assert anchor1.counter == anchor0.counter + 1
    assert anchor1.active_pdna_id == child.pdna_id

    restored, rollback_receipt = rollback_unified_state(child, cp0)
    assert restored.pdna_id == original.pdna_id
    journal.append_rollback(rollback_receipt)
    anchor2 = advance_unified_journal_anchor(journal, port)
    assert anchor2.active_pdna_id == original.pdna_id
    assert verify_unified_journal_against_anchor(journal, port) == anchor2


def test_unified_rollback_fails_on_state_drift():
    original = state0()
    checkpoint = create_unified_checkpoint(original)
    with pytest.raises(ValueError, match="changed before rollback"):
        rollback_unified_state(
            original,
            checkpoint,
            expected_current_state_commitment="f" * 64,
        )
