from __future__ import annotations

from dncrypt.causality import frozen_v02_causality_registry, select_generation_multifold_causal
from dncrypt.fitness import FitnessRecord, PopulationFitnessReport
from dncrypt.generalization import GeneralizationPolicy
from dncrypt.genome import initial_genome, vectorized_mutation_population
from dncrypt.surface import initial_surface
from dncrypt.util import blake2b256


def rec(genome, structural, predictability, avalanche, throughput=100.0):
    return FitnessRecord(
        genome_id=genome.genome_id,
        generation=genome.generation,
        structural_leakage=structural,
        predictability=predictability,
        delta_bits=0.0,
        delta_alpha=0.0,
        avalanche_bias=avalanche,
        throughput=throughput,
        decrypt_failures=0,
        integrity_failures=0,
        p_value=1.0,
        source="causality-firewall-v042-test",
    )


def test_frozen_v02_diagnostic_ciphertext_metrics_cannot_promote():
    parent = initial_genome(bytes(range(64)))
    surface = initial_surface(parent)
    population = vectorized_mutation_population(parent, 2, bytes(range(128)))
    parent_folds = tuple(rec(parent, 0.9, 0.9, 0.9) for _ in range(3))
    reports = tuple(
        PopulationFitnessReport(
            "dncrypt.external-evaluation/v0.2",
            blake2b256(f"fold-{fold}".encode()),
            (
                rec(population[0], 0.0, 0.0, 0.0),
                rec(population[1], 0.1, 0.1, 0.1),
            ),
        )
        for fold in range(3)
    )
    child, child_surface, promotion, scores, _security, firewall = select_generation_multifold_causal(
        parent,
        surface,
        parent_folds,
        population,
        reports,
        GeneralizationPolicy(minimum_folds=3, maximum_delta_stddev=0.2),
        sealed_holdout_commitment=blake2b256(b"sealed"),
    )
    assert child.genome_id == parent.genome_id
    assert child_surface == surface
    assert promotion.promoted is False
    assert promotion.reason == "no_candidate_passed_multifold_generalization_gate"
    assert firewall.admission_fields == ()
    assert set(firewall.diagnostic_fields) == {"avalanche_bias", "delta_alpha", "delta_bits", "predictability", "structural_leakage"}
    assert all(score.median_risk_delta == 0.0 for score in scores)


def test_frozen_registry_is_content_addressed_and_complete():
    registry = frozen_v02_causality_registry()
    assert len(registry.digest) == 64
    assert registry.admission_fields == ()
    assert registry.role_for("decrypt_failures") == "HARD_INVARIANT"
    assert registry.role_for("throughput") == "PERFORMANCE_OBSERVATION"
