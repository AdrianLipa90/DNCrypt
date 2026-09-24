from __future__ import annotations

from dataclasses import replace

import pytest

from dncrypt.genetic_compiler import (
    compile_genetic_program,
    genetic_dictionary_v1,
    mutate_genome_with_program,
    vectorized_genetic_population,
)
from dncrypt.genetic_ir import GeneticIRNode, GeneticLevel, GeneticRelation, rewrite_payload
from dncrypt.genome import initial_genome


def sample_program() -> GeneticIRNode:
    k1 = GeneticIRNode("k1", GeneticLevel.KAKU, {"symbol": "A"})
    k2 = GeneticIRNode("k2", GeneticLevel.KAKU, {"symbol": "C"})
    r1 = GeneticIRNode("r1", GeneticLevel.RADICAL, {"motif_id": "m1"}, (k1,))
    r2 = GeneticIRNode("r2", GeneticLevel.RADICAL, {"motif_id": "m2"}, (k2,))
    rel = GeneticRelation("r1", "r2", 2.0, 0.5)
    return GeneticIRNode("c1", GeneticLevel.CONCEPT, {}, (r1, r2), (rel,))


def test_dictionary_and_compiler_are_diagnostic_only_and_deterministic():
    program = sample_program()
    dictionary = genetic_dictionary_v1()
    assert dictionary["authority"]["cryptographic_entropy"] is False
    assert dictionary["authority"]["security_admission"] is False

    a = compile_genetic_program(program)
    b = compile_genetic_program(program)
    assert a == b
    assert a.genetic_ir_id == program.semantic_id
    assert 1 <= a.mutation_budget <= len(a.allowed_loci) <= 36
    assert a.to_dict()["authority"]["cryptographic_entropy"] is False

    changed, _ = rewrite_payload(program, "r1", {"motif_id": "changed"})
    assert compile_genetic_program(changed).commitment != a.commitment


def test_program_shaped_mutation_requires_fresh_entropy_and_stays_in_scope():
    parent = initial_genome(bytes(range(64)))
    program = sample_program()
    phenotype = compile_genetic_program(program)

    with pytest.raises(ValueError, match="fresh mutation entropy"):
        mutate_genome_with_program(parent, program, entropy=b"short")

    child, binding = mutate_genome_with_program(parent, program, entropy=b"x" * 64)
    assert child.parent_id == parent.genome_id
    assert child.generation == parent.generation + 1
    assert binding.genetic_ir_id == program.semantic_id
    assert binding.phenotype_commitment == phenotype.commitment
    assert 1 <= len(binding.changed_loci) <= phenotype.mutation_budget
    assert set(binding.changed_loci).issubset(set(phenotype.allowed_loci))
    assert binding.to_dict()["authority"]["changes_frozen_aead"] is False


def test_program_mutation_is_reproducible_but_fresh_entropy_changes_candidate():
    parent = initial_genome(b"p" * 64)
    program = sample_program()

    a, ra = mutate_genome_with_program(parent, program, entropy=b"a" * 64)
    b, rb = mutate_genome_with_program(parent, program, entropy=b"a" * 64)
    c, rc = mutate_genome_with_program(parent, program, entropy=b"b" * 64)

    assert a == b
    assert ra == rb
    assert c.genome_id != a.genome_id
    assert rc.fresh_entropy_commitment != ra.fresh_entropy_commitment


def test_genetic_population_is_unique_and_bound_to_one_program():
    parent = initial_genome(b"g" * 64)
    program = sample_program()
    population, bindings, commitment = vectorized_genetic_population(
        parent,
        program,
        12,
        entropy=b"e" * 64,
    )
    assert len(population) == 12
    assert len({item.genome_id for item in population}) == 12
    assert len(bindings) == 12
    assert len(commitment) == 64
    assert all(item.genetic_ir_id == program.semantic_id for item in bindings)
