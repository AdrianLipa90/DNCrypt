from __future__ import annotations

from dataclasses import replace

import pytest

from dncrypt.genetic_ir import GeneticIRNode, GeneticLevel, GeneticRelation, rewrite_payload
from dncrypt.genetic_operators import (
    duplicate_child,
    invert_children,
    recombine_children,
    translocate_child,
)
from dncrypt.genetic_policy import compile_genetic_security_policy


def sample_program() -> GeneticIRNode:
    k1 = GeneticIRNode("k1", GeneticLevel.KAKU, {"symbol": "A"})
    k2 = GeneticIRNode("k2", GeneticLevel.KAKU, {"symbol": "C"})
    k3 = GeneticIRNode("k3", GeneticLevel.KAKU, {"symbol": "G"})
    r1 = GeneticIRNode("r1", GeneticLevel.RADICAL, {"motif": "m1"}, (k1,))
    r2 = GeneticIRNode("r2", GeneticLevel.RADICAL, {"motif": "m2"}, (k2,))
    r3 = GeneticIRNode("r3", GeneticLevel.RADICAL, {"motif": "m3"}, (k3,))
    rel12 = GeneticRelation("r1", "r2", 2.0, 0.5)
    rel23 = GeneticRelation("r2", "r3", 3.0, 0.75)
    return GeneticIRNode("c1", GeneticLevel.CONCEPT, {}, (r1, r2, r3), (rel12, rel23))


def test_duplicate_is_namespaced_candidate_only_and_preserves_valid_ir():
    program = sample_program()
    child, receipt = duplicate_child(program, "c1", 0, tag="t1")
    assert len(child.children) == 4
    assert child.children[1].unit_id == "r1__dup_t1"
    assert child.children[1].children[0].unit_id == "k1__dup_t1"
    assert receipt.parent_semantic_id == program.semantic_id
    assert receipt.child_semantic_id == child.semantic_id
    assert receipt.to_dict()["authority"]["candidate_only"] is True
    assert receipt.to_dict()["authority"]["security_admission"] is False


def test_inversion_and_translocation_change_order_without_changing_relation_endpoints():
    program = sample_program()
    inverted, inv_receipt = invert_children(program, "c1", 0, 3)
    assert [x.unit_id for x in inverted.children] == ["r3", "r2", "r1"]
    assert {(r.source_id, r.target_id) for r in inverted.relations} == {
        ("r1", "r2"),
        ("r2", "r3"),
    }
    assert inv_receipt.operation == "INVERT_CHILDREN"

    moved, move_receipt = translocate_child(program, "c1", 0, 2)
    assert [x.unit_id for x in moved.children] == ["r2", "r3", "r1"]
    assert move_receipt.operation == "TRANSLOCATE_CHILD"


def test_recombination_preserves_only_surviving_side_relations_and_namespaces_donor():
    left = sample_program()
    right, _ = rewrite_payload(sample_program(), "r3", {"motif": "donor"})
    child, receipt = recombine_children(
        left,
        right,
        "c1",
        left_cut=1,
        right_cut=1,
        tag="x1",
    )
    ids = [x.unit_id for x in child.children]
    assert ids == ["r1", "r2__xo_x1", "r3__xo_x1"]
    endpoints = {(r.source_id, r.target_id) for r in child.relations}
    assert endpoints == {("r2__xo_x1", "r3__xo_x1")}
    assert receipt.operation == "RECOMBINE_CHILDREN"
    assert receipt.to_dict()["authority"]["changes_frozen_aead"] is False


def test_operator_targets_must_be_unique_and_operations_must_be_effective():
    program = sample_program()
    with pytest.raises(ValueError, match="must change"):
        translocate_child(program, "c1", 1, 1)
    with pytest.raises(IndexError):
        invert_children(program, "c1", 0, 1)


def test_policy_compiler_is_deterministic_bounded_fail_closed_and_candidate_only():
    program = sample_program()
    a = compile_genetic_security_policy(program)
    b = compile_genetic_security_policy(program)
    assert a == b
    assert a.genetic_ir_id == program.semantic_id
    assert 256 <= a.policy.message_budget <= 4096
    assert 1_048_576 <= a.policy.byte_budget <= 8_388_608
    assert 0.01 <= a.policy.attack_risk_threshold <= 0.10
    assert 4 <= a.policy.risk_window <= 16
    assert a.policy.nonce_domain_tracking is True
    assert a.policy.quarantine_on_integrity_failure is True
    assert a.policy.quarantine_on_decrypt_failure is True
    authority = a.to_dict()["authority"]
    assert authority["candidate_only"] is True
    assert authority["security_admission"] is False
    assert authority["cryptographic_entropy"] is False
    assert authority["fail_closed_invariants_locked"] is True


def test_policy_candidate_changes_when_genetic_ir_changes():
    program = sample_program()
    changed, _ = rewrite_payload(program, "r1", {"motif": "changed"})
    assert compile_genetic_security_policy(changed).candidate_id != compile_genetic_security_policy(program).candidate_id
