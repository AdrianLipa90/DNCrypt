from __future__ import annotations

from dataclasses import asdict, dataclass
import math
import statistics
from typing import Iterable

from .fitness import FitnessRecord, PopulationFitnessReport
from .genome import CipherGenome, population_commitment
from .surface import CipherSurface, transition_surface
from .util import blake2b256, canonical_json_bytes


@dataclass(frozen=True, slots=True)
class GeneralizationPolicy:
    minimum_folds: int = 3
    significance_alpha: float = 0.05
    minimum_winning_fraction: float = 0.60
    minimum_median_risk_improvement: float = 0.0
    maximum_worst_fold_regression: float = 0.0
    maximum_delta_stddev: float = 0.05
    minimum_throughput_ratio: float = 0.50
    surface_transition_steps: int = 1

    def __post_init__(self) -> None:
        if self.minimum_folds < 2:
            raise ValueError("minimum_folds must be at least 2")
        if not 0 < self.significance_alpha <= 1:
            raise ValueError("invalid significance_alpha")
        if not 0 < self.minimum_winning_fraction <= 1:
            raise ValueError("minimum_winning_fraction must be in (0,1]")
        if self.minimum_median_risk_improvement < 0:
            raise ValueError("minimum_median_risk_improvement must be non-negative")
        if self.maximum_worst_fold_regression < 0:
            raise ValueError("maximum_worst_fold_regression must be non-negative")
        if self.maximum_delta_stddev < 0:
            raise ValueError("maximum_delta_stddev must be non-negative")
        if not 0 < self.minimum_throughput_ratio <= 1:
            raise ValueError("minimum_throughput_ratio must be in (0,1]")
        if self.surface_transition_steps <= 0:
            raise ValueError("surface_transition_steps must be positive")

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))


@dataclass(frozen=True, slots=True)
class CandidateGeneralizationScore:
    genome_id: str
    generation: int
    fold_count: int
    fold_risk_deltas: tuple[float, ...]
    fold_throughput_ratios: tuple[float, ...]
    mean_risk_delta: float
    median_risk_delta: float
    worst_fold_risk_delta: float
    delta_stddev: float
    winning_folds: int
    required_winning_folds: int
    minimum_observed_throughput_ratio: float
    invariants_pass: bool
    gate_pass: bool
    reason: str

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))


@dataclass(frozen=True, slots=True)
class GeneralizationPromotionReceipt:
    schema: str
    parent_genome_id: str
    parent_surface_commitment: str
    parent_tick: int
    population_commitment: str
    parent_fold_report_digests: tuple[str, ...]
    candidate_fold_report_digests: tuple[str, ...]
    policy_digest: str
    sealed_holdout_commitment: str
    holdout_used_for_selection: bool
    selected_genome_id: str | None
    selected_score_digest: str | None
    selected_fold_risk_deltas: tuple[float, ...] | None
    selected_median_risk_delta: float | None
    selected_worst_fold_risk_delta: float | None
    selected_delta_stddev: float | None
    selected_minimum_throughput_ratio: float | None
    selected_surface_commitment: str | None
    selected_tick: int | None
    promoted: bool
    reason: str

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))


def _fitness_digest(report: FitnessRecord) -> str:
    return blake2b256(canonical_json_bytes(asdict(report)))


def _validate_hex_commitment(value: str, name: str) -> None:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{name} must be a 64-character hex digest")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{name} must be hexadecimal") from exc


def _dominates(a: CandidateGeneralizationScore, b: CandidateGeneralizationScore) -> bool:
    av = (
        a.median_risk_delta,
        a.worst_fold_risk_delta,
        a.delta_stddev,
        -a.minimum_observed_throughput_ratio,
    )
    bv = (
        b.median_risk_delta,
        b.worst_fold_risk_delta,
        b.delta_stddev,
        -b.minimum_observed_throughput_ratio,
    )
    return all(x <= y for x, y in zip(av, bv)) and any(x < y for x, y in zip(av, bv))


def robust_pareto_survivor_indices(scores: Iterable[CandidateGeneralizationScore]) -> tuple[int, ...]:
    seq = tuple(scores)
    return tuple(
        i for i, score in enumerate(seq)
        if not any(j != i and _dominates(other, score) for j, other in enumerate(seq))
    )


def _score_candidate(
    candidate_records: tuple[FitnessRecord, ...],
    parent_records: tuple[FitnessRecord, ...],
    policy: GeneralizationPolicy,
) -> CandidateGeneralizationScore:
    if len(candidate_records) != len(parent_records):
        raise ValueError("candidate and parent fold counts differ")
    if not candidate_records:
        raise ValueError("fold records must not be empty")
    genome_id = candidate_records[0].genome_id
    generation = candidate_records[0].generation
    if any(r.genome_id != genome_id or r.generation != generation for r in candidate_records):
        raise ValueError("candidate fold identity mismatch")

    deltas = tuple(
        child.adversarial_risk(policy.significance_alpha)
        - parent.adversarial_risk(policy.significance_alpha)
        for child, parent in zip(candidate_records, parent_records)
    )
    throughput_ratios = tuple(
        child.throughput / max(parent.throughput, 1e-12)
        for child, parent in zip(candidate_records, parent_records)
    )
    fold_count = len(deltas)
    required_wins = math.ceil(policy.minimum_winning_fraction * fold_count)
    winning_folds = sum(delta < 0.0 for delta in deltas)
    median_delta = float(statistics.median(deltas))
    mean_delta = float(statistics.fmean(deltas))
    worst_delta = float(max(deltas))
    delta_stddev = float(statistics.pstdev(deltas)) if fold_count > 1 else 0.0
    min_throughput_ratio = float(min(throughput_ratios))
    invariants_pass = all(r.invariant_pass for r in candidate_records)

    checks = (
        (invariants_pass, "candidate_failed_frozen_decrypt_integrity_invariant"),
        (winning_folds >= required_wins, "insufficient_winning_folds"),
        (
            median_delta < -policy.minimum_median_risk_improvement,
            "median_risk_improvement_below_threshold",
        ),
        (
            worst_delta <= policy.maximum_worst_fold_regression,
            "worst_fold_regression_exceeded",
        ),
        (delta_stddev <= policy.maximum_delta_stddev, "fold_delta_variance_exceeded"),
        (
            min_throughput_ratio >= policy.minimum_throughput_ratio,
            "minimum_fold_throughput_ratio_failed",
        ),
    )
    failed = next((reason for ok, reason in checks if not ok), None)
    return CandidateGeneralizationScore(
        genome_id=genome_id,
        generation=generation,
        fold_count=fold_count,
        fold_risk_deltas=deltas,
        fold_throughput_ratios=throughput_ratios,
        mean_risk_delta=mean_delta,
        median_risk_delta=median_delta,
        worst_fold_risk_delta=worst_delta,
        delta_stddev=delta_stddev,
        winning_folds=winning_folds,
        required_winning_folds=required_wins,
        minimum_observed_throughput_ratio=min_throughput_ratio,
        invariants_pass=invariants_pass,
        gate_pass=failed is None,
        reason="multifold_generalization_gate_pass" if failed is None else failed,
    )


def select_generation_multifold(
    parent: CipherGenome,
    parent_surface: CipherSurface,
    parent_fold_reports: tuple[FitnessRecord, ...],
    population: tuple[CipherGenome, ...],
    candidate_fold_reports: tuple[PopulationFitnessReport, ...],
    policy: GeneralizationPolicy,
    *,
    sealed_holdout_commitment: str,
) -> tuple[CipherGenome, CipherSurface, GeneralizationPromotionReceipt, tuple[CandidateGeneralizationScore, ...]]:
    """Select one child using only multifold evidence.

    The sealed holdout enters this function only as a pre-committed digest. Holdout
    measurements are intentionally absent from the selection API and therefore cannot
    affect candidate ranking or promotion.
    """
    if not population:
        raise ValueError("population must not be empty")
    _validate_hex_commitment(sealed_holdout_commitment, "sealed_holdout_commitment")
    if len(parent_fold_reports) != len(candidate_fold_reports):
        raise ValueError("parent/candidate fold report count mismatch")
    if len(parent_fold_reports) < policy.minimum_folds:
        raise ValueError("insufficient independent folds for generalization admission")
    for report in parent_fold_reports:
        if report.genome_id != parent.genome_id or report.generation != parent.generation:
            raise ValueError("parent fold report binding mismatch")
        if not report.invariant_pass:
            raise ValueError("parent fold invariant report is not clean")
    ordered_folds: list[tuple[FitnessRecord, ...]] = []
    for report in candidate_fold_reports:
        report.validate_population(population)
        ordered_folds.append(report.ordered_for(population))

    scores = tuple(
        _score_candidate(
            tuple(fold[i] for fold in ordered_folds),
            parent_fold_reports,
            policy,
        )
        for i in range(len(population))
    )
    passing_indices = tuple(i for i, score in enumerate(scores) if score.gate_pass)
    pop_commit = population_commitment(population)
    parent_digests = tuple(_fitness_digest(report) for report in parent_fold_reports)
    candidate_digests = tuple(report.digest for report in candidate_fold_reports)

    if not passing_indices:
        receipt = GeneralizationPromotionReceipt(
            schema="dncrypt.generalization-promotion-receipt/v0.4",
            parent_genome_id=parent.genome_id,
            parent_surface_commitment=parent_surface.commitment,
            parent_tick=parent_surface.tick,
            population_commitment=pop_commit,
            parent_fold_report_digests=parent_digests,
            candidate_fold_report_digests=candidate_digests,
            policy_digest=policy.digest,
            sealed_holdout_commitment=sealed_holdout_commitment,
            holdout_used_for_selection=False,
            selected_genome_id=None,
            selected_score_digest=None,
            selected_fold_risk_deltas=None,
            selected_median_risk_delta=None,
            selected_worst_fold_risk_delta=None,
            selected_delta_stddev=None,
            selected_minimum_throughput_ratio=None,
            selected_surface_commitment=None,
            selected_tick=None,
            promoted=False,
            reason="no_candidate_passed_multifold_generalization_gate",
        )
        return parent, parent_surface, receipt, scores

    passing_scores = tuple(scores[i] for i in passing_indices)
    local_survivors = robust_pareto_survivor_indices(passing_scores)
    survivor_indices = tuple(passing_indices[i] for i in local_survivors)

    def rank(i: int) -> tuple[float, float, float, float, str]:
        score = scores[i]
        return (
            score.median_risk_delta,
            score.worst_fold_risk_delta,
            score.delta_stddev,
            -score.minimum_observed_throughput_ratio,
            score.genome_id,
        )

    chosen_index = min(survivor_indices, key=rank)
    chosen = population[chosen_index]
    chosen_score = scores[chosen_index]
    child_surface = transition_surface(parent_surface, chosen, steps=policy.surface_transition_steps)
    receipt = GeneralizationPromotionReceipt(
        schema="dncrypt.generalization-promotion-receipt/v0.4",
        parent_genome_id=parent.genome_id,
        parent_surface_commitment=parent_surface.commitment,
        parent_tick=parent_surface.tick,
        population_commitment=pop_commit,
        parent_fold_report_digests=parent_digests,
        candidate_fold_report_digests=candidate_digests,
        policy_digest=policy.digest,
        sealed_holdout_commitment=sealed_holdout_commitment,
        holdout_used_for_selection=False,
        selected_genome_id=chosen.genome_id,
        selected_score_digest=chosen_score.digest,
        selected_fold_risk_deltas=chosen_score.fold_risk_deltas,
        selected_median_risk_delta=chosen_score.median_risk_delta,
        selected_worst_fold_risk_delta=chosen_score.worst_fold_risk_delta,
        selected_delta_stddev=chosen_score.delta_stddev,
        selected_minimum_throughput_ratio=chosen_score.minimum_observed_throughput_ratio,
        selected_surface_commitment=child_surface.commitment,
        selected_tick=child_surface.tick,
        promoted=True,
        reason="robust_pareto_survivor_passed_multifold_generalization_gate",
    )
    return chosen, child_surface, receipt, scores
