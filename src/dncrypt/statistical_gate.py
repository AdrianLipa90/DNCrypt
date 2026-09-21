from __future__ import annotations

from dataclasses import asdict, dataclass
import math
import statistics
from typing import Sequence

from .generalization import CandidateGeneralizationScore
from .util import blake2b256, canonical_json_bytes


@dataclass(frozen=True, slots=True)
class StatisticalAdmissionPolicy:
    fdr_alpha: float = 0.05
    minimum_effect_improvement: float = 0.0
    minimum_non_tie_folds: int = 5

    def __post_init__(self) -> None:
        if not 0 < self.fdr_alpha <= 1:
            raise ValueError("fdr_alpha must be in (0,1]")
        if self.minimum_effect_improvement < 0:
            raise ValueError("minimum_effect_improvement must be non-negative")
        if self.minimum_non_tie_folds < 1:
            raise ValueError("minimum_non_tie_folds must be positive")

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))


@dataclass(frozen=True, slots=True)
class StatisticalCandidateEvidence:
    genome_id: str
    wins: int
    losses: int
    ties: int
    non_tie_folds: int
    sign_test_p_value: float
    fdr_q_value: float
    median_effect_improvement: float
    gate_pass: bool
    reason: str

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))


def exact_one_sided_sign_test(wins: int, losses: int) -> float:
    if wins < 0 or losses < 0:
        raise ValueError("wins/losses must be non-negative")
    n = wins + losses
    if n == 0:
        return 1.0
    if wins <= n // 2:
        return 1.0
    return min(
        1.0,
        sum(math.comb(n, k) for k in range(wins, n + 1)) / (2 ** n),
    )


def benjamini_hochberg_qvalues(p_values: Sequence[float]) -> tuple[float, ...]:
    values = tuple(float(p) for p in p_values)
    if any(not math.isfinite(p) or p < 0.0 or p > 1.0 for p in values):
        raise ValueError("p-values must be finite and in [0,1]")
    m = len(values)
    if m == 0:
        return tuple()
    order = sorted(range(m), key=lambda i: (values[i], i))
    adjusted = [1.0] * m
    running = 1.0
    for rank_from_end in range(m - 1, -1, -1):
        i = order[rank_from_end]
        rank = rank_from_end + 1
        candidate = min(1.0, values[i] * m / rank)
        running = min(running, candidate)
        adjusted[i] = running
    return tuple(adjusted)


def population_statistical_gate(
    scores: Sequence[CandidateGeneralizationScore],
    policy: StatisticalAdmissionPolicy,
) -> tuple[StatisticalCandidateEvidence, ...]:
    seq = tuple(scores)
    p_values: list[float] = []
    raw: list[tuple[int, int, int, int, float]] = []
    for score in seq:
        wins = sum(delta < 0.0 for delta in score.fold_risk_deltas)
        losses = sum(delta > 0.0 for delta in score.fold_risk_deltas)
        ties = len(score.fold_risk_deltas) - wins - losses
        non_tie = wins + losses
        p = exact_one_sided_sign_test(wins, losses)
        effect = -float(statistics.median(score.fold_risk_deltas))
        p_values.append(p)
        raw.append((wins, losses, ties, non_tie, effect))
    q_values = benjamini_hochberg_qvalues(p_values)

    out: list[StatisticalCandidateEvidence] = []
    for score, (wins, losses, ties, non_tie, effect), p, q in zip(seq, raw, p_values, q_values):
        checks = (
            (score.gate_pass, "multifold_generalization_gate_failed"),
            (non_tie >= policy.minimum_non_tie_folds, "insufficient_non_tie_folds"),
            (effect >= policy.minimum_effect_improvement, "effect_size_below_threshold"),
            (q <= policy.fdr_alpha, "fdr_q_value_above_threshold"),
        )
        failed = next((reason for ok, reason in checks if not ok), None)
        out.append(StatisticalCandidateEvidence(
            genome_id=score.genome_id,
            wins=wins,
            losses=losses,
            ties=ties,
            non_tie_folds=non_tie,
            sign_test_p_value=p,
            fdr_q_value=q,
            median_effect_improvement=effect,
            gate_pass=failed is None,
            reason="statistical_admission_gate_pass" if failed is None else failed,
        ))
    return tuple(out)
