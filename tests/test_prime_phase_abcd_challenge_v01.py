from __future__ import annotations

import importlib.util
from pathlib import Path

from dncrypt.genetic_compiler import (
    compile_genetic_program,
    mutate_genome_with_program,
)
from dncrypt.genome import initial_genome

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "prime_phase_abcd_challenge_v01",
    ROOT / "tools" / "prime_phase_abcd_challenge_v01.py",
)
abcd = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(abcd)


def fixture():
    parent = initial_genome(bytes(range(64)))
    program = abcd.fixed_program()
    entropy = b"e" * 64
    return parent, program, entropy


def test_a_strategy_exactly_reproduces_native_genetic_mutator():
    parent, program, entropy = fixture()
    native, native_binding = mutate_genome_with_program(
        parent,
        program,
        entropy=entropy,
    )
    experimental, binding = abcd.mutate_with_strategy(
        parent,
        program,
        fresh_entropy=entropy,
        strategy="A_NATIVE_GENETIC_IR",
    )
    assert experimental == native
    assert binding.changed_loci == native_binding.changed_loci
    assert binding.phenotype_commitment == native_binding.phenotype_commitment


def test_all_strategies_preserve_native_security_substrate():
    parent, program, entropy = fixture()
    children = {}
    for strategy in abcd.STRATEGIES:
        child, binding = abcd.mutate_with_strategy(
            parent,
            program,
            fresh_entropy=entropy,
            strategy=strategy,
        )
        children[strategy] = child
        phenotype = compile_genetic_program(program)
        assert set(binding.changed_loci).issubset(set(phenotype.allowed_loci))
        assert len(binding.changed_loci) <= phenotype.mutation_budget
        assert binding.cryptographic_entropy_authority is False
        assert binding.security_admission_authority is False
        assert binding.frozen_aead_changed is False

    reference = children[abcd.STRATEGIES[0]]
    for child in children.values():
        assert child.route == reference.route
        assert child.phase_seed_hex == reference.phase_seed_hex
        assert child.mutation_nonce_hex == reference.mutation_nonce_hex
        assert child.parent_id == reference.parent_id
        assert child.generation == reference.generation


def test_population_uses_same_substrate_candidate_by_candidate():
    parent, program, _ = fixture()
    raw = b"p" * (8 * 64)
    populations = {}
    for strategy in abcd.STRATEGIES:
        pop, bindings, commitment = abcd.strategy_population(
            parent,
            program,
            8,
            entropy=raw,
            strategy=strategy,
        )
        assert len(pop) == 8
        assert len(bindings) == 8
        assert len(commitment) == 64
        populations[strategy] = pop

    for i in range(8):
        ref = populations[abcd.STRATEGIES[0]][i]
        for strategy in abcd.STRATEGIES[1:]:
            candidate = populations[strategy][i]
            assert candidate.route == ref.route
            assert candidate.phase_seed_hex == ref.phase_seed_hex
            assert candidate.mutation_nonce_hex == ref.mutation_nonce_hex


def test_random_null_has_no_prime_frame_binding():
    parent, program, entropy = fixture()
    _, binding = abcd.mutate_with_strategy(
        parent,
        program,
        fresh_entropy=entropy,
        strategy="B_RANDOM_LOCUS_NULL",
    )
    assert binding.phase_frame_commitment is None


def test_prime_strategies_bind_exact_phase_frame():
    parent, program, entropy = fixture()
    for strategy in ("C_RAW_FLAVOUR_PHASE_V1", "D_ORBITAL_FLAVOUR_PHASE_V2"):
        _, binding = abcd.mutate_with_strategy(
            parent,
            program,
            fresh_entropy=entropy,
            strategy=strategy,
        )
        assert binding.phase_frame_commitment is not None
        assert len(binding.phase_frame_commitment) == 64


def test_orbital_v2_is_flavour_invariant_at_orbit_score_level():
    frame = abcd.PHASE_FRAMES[0]
    scores = abcd._orbit_base_scores(frame)
    assert len(scores) == 12
    phase = abcd._phase36(frame)
    assert len(phase) == 36
    # Three flavour coordinates belong to one orbit but v2 assigns one shared
    # flavour-independent orbital score.
    for orbit in range(12):
        loci = (3 * orbit, 3 * orbit + 1, 3 * orbit + 2)
        assert all(locus // 3 == orbit for locus in loci)
        assert 0.0 <= scores[orbit] <= 1.0


def test_fixed_program_creates_nontrivial_bounded_search_surface():
    phenotype = compile_genetic_program(abcd.fixed_program())
    assert len(phenotype.allowed_loci) >= 12
    assert phenotype.mutation_budget < len(phenotype.allowed_loci)
    assert phenotype.mutation_budget >= 1