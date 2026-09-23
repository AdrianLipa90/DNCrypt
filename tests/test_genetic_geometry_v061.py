from __future__ import annotations

import math

import pytest

from dncrypt.genetic_geometry import (
    GeneticResourceLimits,
    bounded_genetic_ir_from_mapping,
    genetic_phase_tree,
    level_phase_coherence,
    parent_child_phase_distance,
)
from dncrypt.genetic_ir import GeneticIRNode, GeneticLevel


def sample_program() -> GeneticIRNode:
    k1 = GeneticIRNode("k1", GeneticLevel.KAKU, {"symbol": "A"})
    k2 = GeneticIRNode("k2", GeneticLevel.KAKU, {"symbol": "C"})
    r1 = GeneticIRNode("r1", GeneticLevel.RADICAL, {}, (k1, k2))
    c1 = GeneticIRNode("c1", GeneticLevel.CONCEPT, {}, (r1,))
    return GeneticIRNode("s1", GeneticLevel.SENTENCE, {}, (c1,))


def test_phase_tree_preserves_hierarchy_instead_of_only_global_projection():
    program = sample_program()
    records = genetic_phase_tree(program)
    assert len(records) == 5
    assert records[0].path == ("s1",)
    assert all(len(record.phase36) == 36 for record in records)
    assert all(
        math.isfinite(value)
        for record in records
        for value in record.phase36
    )

    coherence = level_phase_coherence(program)
    assert set(coherence) == {"KAKU", "RADICAL", "CONCEPT", "SENTENCE"}
    assert all(0.0 <= value <= 1.0 for value in coherence.values())

    distances = parent_child_phase_distance(program)
    assert len(distances) == 4
    assert all(value >= 0.0 for value in distances.values())


def test_bounded_loader_rejects_depth_bomb_before_recursive_parser():
    leaf = {
        "schema": "DNCRYPT_GENETIC_IR_V0_6",
        "source_schema": "CIELINGO_GENOMIC_GRAMMAR_V0_1",
        "unit_id": "leaf",
        "level": "KAKU",
        "payload": {},
        "children": [],
        "relations": [],
    }
    value = leaf
    for index in range(12):
        value = {
            "schema": "DNCRYPT_GENETIC_IR_V0_6",
            "source_schema": "CIELINGO_GENOMIC_GRAMMAR_V0_1",
            "unit_id": f"n{index}",
            "level": "BOOK",
            "payload": {},
            "children": [value],
            "relations": [],
        }

    with pytest.raises(ValueError, match="depth budget"):
        bounded_genetic_ir_from_mapping(
            value,
            limits=GeneticResourceLimits(max_depth=5),
        )


def test_bounded_loader_rejects_node_and_payload_budgets():
    program = sample_program().to_dict()

    with pytest.raises(ValueError, match="node budget"):
        bounded_genetic_ir_from_mapping(
            program,
            limits=GeneticResourceLimits(max_nodes=3),
        )

    with pytest.raises(ValueError, match="payload budget"):
        bounded_genetic_ir_from_mapping(
            program,
            limits=GeneticResourceLimits(max_payload_bytes=1),
        )
