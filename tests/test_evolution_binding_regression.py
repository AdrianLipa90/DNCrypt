import pytest

from dncrypt import (
    EvolutionPolicy,
    FitnessRecord,
    PopulationFitnessReport,
    initial_genome,
    initial_surface,
    make_evaluation_request,
    propose_generation,
    select_generation,
    vectorized_mutation_population,
)


def _fitness(genome, *, risk: float = 0.01) -> FitnessRecord:
    return FitnessRecord(
        genome.genome_id,
        genome.generation,
        risk,
        risk,
        0.0,
        0.0,
        risk,
        100.0,
        0,
        0,
        0.9,
        "binding-regression",
    )


def test_selection_rejects_report_for_different_request() -> None:
    parent = initial_genome(bytes(range(64)))
    surface = initial_surface(parent)
    policy = EvolutionPolicy(population_size=2, mutation_risk_threshold=0.0)
    parent_report = _fitness(parent, risk=0.1)
    population, _ = propose_generation(parent, parent_report, policy, entropy=b"a" * 128)
    records = tuple(_fitness(g, risk=0.01) for g in population)
    report = PopulationFitnessReport("dncrypt.external-evaluation/v0.2", "0" * 64, records)

    with pytest.raises(ValueError, match="request_id mismatch"):
        select_generation(parent, surface, parent_report, population, report, policy)


def test_selection_rejects_population_with_wrong_parent_lineage() -> None:
    parent = initial_genome(bytes(range(64)))
    other_parent = initial_genome(bytes(reversed(range(64))))
    surface = initial_surface(parent)
    policy = EvolutionPolicy(population_size=2, mutation_risk_threshold=0.0)
    parent_report = _fitness(parent, risk=0.1)
    foreign_population = vectorized_mutation_population(other_parent, 2, b"b" * 128)
    request = make_evaluation_request(other_parent, foreign_population)
    report = PopulationFitnessReport(
        "dncrypt.external-evaluation/v0.2",
        request.request_id,
        tuple(_fitness(g, risk=0.01) for g in foreign_population),
    )

    with pytest.raises(ValueError, match="population lineage mismatch"):
        select_generation(parent, surface, parent_report, foreign_population, report, policy)
