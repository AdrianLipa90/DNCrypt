from __future__ import annotations

import pytest

from dncrypt.fitness import FitnessRecord, PopulationFitnessReport
from dncrypt.generalization import GeneralizationPolicy, select_generation_multifold
from dncrypt.genome import initial_genome, vectorized_mutation_population
from dncrypt.surface import initial_surface
from dncrypt.util import blake2b256


def record(genome, structural: float, throughput: float = 100.0) -> FitnessRecord:
    return FitnessRecord(
        genome_id=genome.genome_id,
        generation=genome.generation,
        structural_leakage=structural,
        predictability=0.0,
        delta_bits=0.0,
        delta_alpha=0.0,
        avalanche_bias=0.0,
        throughput=throughput,
        decrypt_failures=0,
        integrity_failures=0,
        p_value=1.0,
        source="generalization-unit-test",
    )


def make_fixture():
    parent = initial_genome(bytes(range(64)))
    surface = initial_surface(parent)
    population = vectorized_mutation_population(parent, 2, bytes(range(128)))
    parents = tuple(record(parent, 0.20) for _ in range(3))
    request_digest = blake2b256(b"generalization-test-request")
    return parent, surface, population, parents, request_digest


def test_multifold_rejects_overfit_candidate_and_promotes_stable_candidate():
    parent, surface, population, parents, request_digest = make_fixture()
    candidate_structural = (
        (0.10, 0.15),
        (0.10, 0.15),
        (0.35, 0.15),
    )
    reports = tuple(
        PopulationFitnessReport(
            "dncrypt.external-evaluation/v0.2",
            request_digest,
            tuple(record(genome, values[i]) for i, genome in enumerate(population)),
        )
        for values in candidate_structural
    )
    policy = GeneralizationPolicy(
        minimum_folds=3,
        minimum_winning_fraction=2 / 3,
        maximum_worst_fold_regression=0.0,
        maximum_delta_stddev=0.20,
        minimum_throughput_ratio=0.5,
    )
    child, child_surface, receipt, scores = select_generation_multifold(
        parent,
        surface,
        parents,
        population,
        reports,
        policy,
        sealed_holdout_commitment=blake2b256(b"sealed-holdout"),
    )
    assert not scores[0].gate_pass
    assert scores[0].reason == "worst_fold_regression_exceeded"
    assert scores[1].gate_pass
    assert receipt.promoted
    assert receipt.holdout_used_for_selection is False
    assert child.genome_id == population[1].genome_id
    assert child_surface.tick > surface.tick


def test_multifold_fails_closed_when_every_candidate_has_fold_regression():
    parent, surface, population, parents, request_digest = make_fixture()
    candidate_structural = (
        (0.10, 0.10),
        (0.10, 0.10),
        (0.30, 0.25),
    )
    reports = tuple(
        PopulationFitnessReport(
            "dncrypt.external-evaluation/v0.2",
            request_digest,
            tuple(record(genome, values[i]) for i, genome in enumerate(population)),
        )
        for values in candidate_structural
    )
    policy = GeneralizationPolicy(
        minimum_folds=3,
        minimum_winning_fraction=2 / 3,
        maximum_worst_fold_regression=0.0,
        maximum_delta_stddev=0.20,
    )
    child, child_surface, receipt, scores = select_generation_multifold(
        parent,
        surface,
        parents,
        population,
        reports,
        policy,
        sealed_holdout_commitment=blake2b256(b"sealed-holdout"),
    )
    assert not receipt.promoted
    assert receipt.reason == "no_candidate_passed_multifold_generalization_gate"
    assert child.genome_id == parent.genome_id
    assert child_surface.commitment == surface.commitment
    assert all(not score.gate_pass for score in scores)


def test_multifold_rejects_invalid_or_missing_holdout_commitment():
    parent, surface, population, parents, request_digest = make_fixture()
    reports = tuple(
        PopulationFitnessReport(
            "dncrypt.external-evaluation/v0.2",
            request_digest,
            tuple(record(genome, 0.10) for genome in population),
        )
        for _ in range(3)
    )
    with pytest.raises(ValueError, match="sealed_holdout_commitment"):
        select_generation_multifold(
            parent,
            surface,
            parents,
            population,
            reports,
            GeneralizationPolicy(minimum_folds=3),
            sealed_holdout_commitment="not-a-digest",
        )


def test_multifold_requires_policy_minimum_fold_count():
    parent, surface, population, parents, request_digest = make_fixture()
    reports = tuple(
        PopulationFitnessReport(
            "dncrypt.external-evaluation/v0.2",
            request_digest,
            tuple(record(genome, 0.10) for genome in population),
        )
        for _ in range(2)
    )
    with pytest.raises(ValueError, match="insufficient independent folds"):
        select_generation_multifold(
            parent,
            surface,
            parents[:2],
            population,
            reports,
            GeneralizationPolicy(minimum_folds=3),
            sealed_holdout_commitment=blake2b256(b"sealed-holdout"),
        )
