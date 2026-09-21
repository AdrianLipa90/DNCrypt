from __future__ import annotations

import pytest

from dncrypt.generalization import CandidateGeneralizationScore
from dncrypt.statistical_gate import (
    StatisticalAdmissionPolicy,
    benjamini_hochberg_qvalues,
    exact_one_sided_sign_test,
    population_statistical_gate,
)


def _score(genome_id: str, deltas: tuple[float, ...], *, gate_pass: bool = True):
    wins = sum(d < 0 for d in deltas)
    return CandidateGeneralizationScore(
        genome_id=genome_id,
        generation=1,
        fold_count=len(deltas),
        fold_risk_deltas=deltas,
        fold_throughput_ratios=(1.0,) * len(deltas),
        mean_risk_delta=sum(deltas) / len(deltas),
        median_risk_delta=sorted(deltas)[len(deltas) // 2],
        worst_fold_risk_delta=max(deltas),
        delta_stddev=0.0,
        winning_folds=wins,
        required_winning_folds=1,
        minimum_observed_throughput_ratio=1.0,
        invariants_pass=True,
        gate_pass=gate_pass,
        reason="fixture",
    )


def test_exact_sign_test_requires_repeated_directional_evidence():
    assert exact_one_sided_sign_test(6, 0) == pytest.approx(1 / 64)
    assert exact_one_sided_sign_test(5, 1) == pytest.approx(7 / 64)
    assert exact_one_sided_sign_test(3, 3) == 1.0


def test_bh_qvalues_are_monotone_and_control_population_search():
    q = benjamini_hochberg_qvalues((0.01, 0.02, 0.20, 0.90))
    assert q[0] <= q[1] <= q[2] <= q[3]
    assert q[0] == pytest.approx(0.04)
    assert q[1] == pytest.approx(0.04)


def test_population_gate_rejects_weak_candidate_after_multiple_testing():
    scores = (
        _score("a" * 64, (-0.04,) * 6),
        _score("b" * 64, (-0.02,) * 5 + (0.01,)),
        _score("c" * 64, (-0.001,) * 3 + (0.001,) * 3),
    )
    evidence = population_statistical_gate(
        scores,
        StatisticalAdmissionPolicy(
            fdr_alpha=0.05,
            minimum_effect_improvement=0.01,
            minimum_non_tie_folds=6,
        ),
    )
    assert evidence[0].gate_pass
    assert evidence[0].fdr_q_value <= 0.05
    assert not evidence[1].gate_pass
    assert evidence[1].reason == "fdr_q_value_above_threshold"
    assert not evidence[2].gate_pass


def test_population_gate_never_resurrects_failed_generalization_candidate():
    score = _score("d" * 64, (-1.0,) * 8, gate_pass=False)
    evidence = population_statistical_gate(
        (score,),
        StatisticalAdmissionPolicy(minimum_non_tie_folds=5),
    )
    assert not evidence[0].gate_pass
    assert evidence[0].reason == "multifold_generalization_gate_failed"
