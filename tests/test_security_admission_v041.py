from __future__ import annotations

from dncrypt.fitness import FitnessRecord, PopulationFitnessReport
from dncrypt.generalization import GeneralizationPolicy
from dncrypt.genome import initial_genome, vectorized_mutation_population
from dncrypt.security_admission import select_generation_multifold_security_only
from dncrypt.surface import initial_surface
from dncrypt.util import blake2b256


def record(genome, structural: float, throughput: float) -> FitnessRecord:
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
        source="security-admission-v041-test",
    )


def test_security_only_selection_is_invariant_to_wallclock_throughput_swap():
    parent = initial_genome(bytes(range(64)))
    surface = initial_surface(parent)
    population = vectorized_mutation_population(parent, 2, bytes(range(128)))
    parents_a = tuple(record(parent, 0.20, 100.0) for _ in range(3))
    parents_b = tuple(record(parent, 0.20, 1_000_000.0) for _ in range(3))

    def reports(first: float, second: float):
        return tuple(
            PopulationFitnessReport(
                "dncrypt.external-evaluation/v0.2",
                blake2b256(f"request-{fold}".encode()),
                (
                    record(population[0], 0.10, first),
                    record(population[1], 0.10, second),
                ),
            )
            for fold in range(3)
        )

    policy = GeneralizationPolicy(minimum_folds=3, maximum_delta_stddev=0.20)
    chosen_a, _, _, _, binding_a = select_generation_multifold_security_only(
        parent, surface, parents_a, population, reports(10.0, 200.0), policy,
        sealed_holdout_commitment=blake2b256(b"sealed-holdout"),
    )
    chosen_b, _, _, _, binding_b = select_generation_multifold_security_only(
        parent, surface, parents_b, population, reports(200.0, 10.0), policy,
        sealed_holdout_commitment=blake2b256(b"sealed-holdout"),
    )
    expected = min(population, key=lambda genome: genome.genome_id)
    assert chosen_a.genome_id == expected.genome_id
    assert chosen_b.genome_id == expected.genome_id
    assert binding_a.digest == binding_b.digest
    assert binding_a.performance_mode == "observe_only"
