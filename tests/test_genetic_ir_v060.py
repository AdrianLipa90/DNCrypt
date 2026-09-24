from __future__ import annotations

import math

import pytest

from dncrypt.genetic_ir import (
    CIELINGO_SCHEMA,
    GeneticIRNode,
    GeneticLevel,
    GeneticRelation,
    compile_ir_to_phase36,
    delete_child,
    import_cielingo_genomic_unit,
    rewrite_payload,
    source_binding,
    swap_adjacent_children,
)


def sample_program() -> GeneticIRNode:
    k1 = GeneticIRNode("k1", GeneticLevel.KAKU, {"symbol": "A", "position_bp": 1})
    k2 = GeneticIRNode("k2", GeneticLevel.KAKU, {"symbol": "C", "position_bp": 2})
    k3 = GeneticIRNode("k3", GeneticLevel.KAKU, {"symbol": "G", "position_bp": 8})
    k4 = GeneticIRNode("k4", GeneticLevel.KAKU, {"symbol": "T", "position_bp": 9})
    r1 = GeneticIRNode("r1", GeneticLevel.RADICAL, {"motif_id": "m1"}, (k1, k2))
    r2 = GeneticIRNode("r2", GeneticLevel.RADICAL, {"motif_id": "m2"}, (k3, k4))
    relation = GeneticRelation("r1", "r2", 7.0, 1.25, "co_forward")
    concept = GeneticIRNode(
        "c1",
        GeneticLevel.CONCEPT,
        {"component_size": 2},
        (r1, r2),
        (relation,),
    )
    return GeneticIRNode(
        "sentence:test",
        GeneticLevel.SENTENCE,
        {"record_id": "test"},
        (concept,),
    )


def as_cielingo(node: GeneticIRNode) -> dict[str, object]:
    out = {
        "schema": CIELINGO_SCHEMA,
        "unit_id": node.unit_id,
        "level": node.level.name,
        "payload": dict(node.payload),
        "children": [as_cielingo(child) for child in node.children],
        "relations": [
            {
                "source_id": rel.source_id,
                "target_id": rel.target_id,
                "distance_bp": rel.distance_bp,
                "relative_phase_rad": rel.relative_phase_rad,
                "orientation": rel.orientation,
                "chromatin_context": None,
            }
            for rel in node.relations
        ],
        "epistemic_status": "COMPUTATIONAL_HYPOTHESIS",
        "biological_equivalence_claim": False,
    }
    return out


def test_cielingo_import_is_canonical_and_pinned():
    imported = import_cielingo_genomic_unit(as_cielingo(sample_program()))
    assert imported.level is GeneticLevel.SENTENCE
    assert imported.children[0].level is GeneticLevel.CONCEPT
    assert len(imported.semantic_id) == 64

    binding = source_binding()
    assert binding["commit"] == "59297d21fba563e17c7a656e0cb3139a5a302ee5"
    assert binding["canon_claim"] is False


def test_hierarchy_and_relation_endpoints_fail_closed():
    kaku = GeneticIRNode("k", GeneticLevel.KAKU, {"symbol": "A"})
    with pytest.raises(ValueError, match="children must be KAKU"):
        GeneticIRNode("bad", GeneticLevel.RADICAL, {}, (
            GeneticIRNode("r", GeneticLevel.RADICAL, {}, (kaku,)),
        ))

    r1 = GeneticIRNode("r1", GeneticLevel.RADICAL, {}, (kaku,))
    with pytest.raises(ValueError, match="immediate children"):
        GeneticIRNode(
            "c",
            GeneticLevel.CONCEPT,
            {},
            (r1,),
            (GeneticRelation("r1", "missing", 1.0, 0.1),),
        )


def test_phase36_projection_is_deterministic_finite_and_sensitive():
    program = sample_program()
    a = compile_ir_to_phase36(program)
    b = compile_ir_to_phase36(program)
    assert a == b
    assert len(a) == 36
    assert all(math.isfinite(x) and 0.0 <= x <= 2.0 * math.pi for x in a)

    changed, _ = rewrite_payload(program, "r1", {"motif_id": "m1b"})
    assert compile_ir_to_phase36(changed) != a


def test_grammar_constrained_mutations_preserve_typed_tree():
    program = sample_program()

    rewritten, receipt = rewrite_payload(program, "r1", {"weight": 0.5})
    assert receipt.parent_semantic_id == program.semantic_id
    assert receipt.child_semantic_id == rewritten.semantic_id
    assert receipt.security_admission is False

    concept_id = "c1"
    swapped, swap_receipt = swap_adjacent_children(rewritten, concept_id, 0)
    assert swap_receipt.operation == "SWAP_ADJACENT_CHILDREN"
    assert [child.unit_id for child in swapped.children[0].children] == ["r2", "r1"]

    reduced, delete_receipt = delete_child(swapped, concept_id, 0)
    concept = reduced.children[0]
    assert len(concept.children) == 1
    assert concept.relations == ()
    assert delete_receipt.operation == "DELETE_CHILD"


def test_import_rejects_biological_promotion_and_unknown_fields():
    value = as_cielingo(sample_program())
    value["biological_equivalence_claim"] = True
    with pytest.raises(ValueError, match="biological-equivalence"):
        import_cielingo_genomic_unit(value)

    value = as_cielingo(sample_program())
    value["surprise"] = 1
    with pytest.raises(ValueError, match="unknown Genetic IR fields"):
        import_cielingo_genomic_unit(value)
