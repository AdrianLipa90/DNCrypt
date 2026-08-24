from __future__ import annotations
from dataclasses import dataclass
import numpy as np
from .fitness import FitnessRecord, pareto_survivor_indices as _pareto
from .genome import CipherGenome, vectorized_mutation_population

@dataclass(frozen=True, slots=True)
class PopulationEvaluation:
    genome_ids: tuple[str, ...]
    leakage: tuple[float, ...]
    predictability: tuple[float, ...]
    delta_bits: tuple[float, ...]
    delta_alpha: tuple[float, ...]
    throughput: tuple[float, ...]

    def score_matrix(self) -> np.ndarray:
        return np.column_stack([np.asarray(self.leakage), np.asarray(self.predictability), np.maximum(0.0, np.asarray(self.delta_bits)), np.maximum(0.0, np.asarray(self.delta_alpha)), -np.asarray(self.throughput)])


def pareto_survivor_indices(evaluation: PopulationEvaluation) -> tuple[int, ...]:
    scores = evaluation.score_matrix(); n=scores.shape[0]; keep=np.ones(n,dtype=bool)
    for i in range(n):
        if not keep[i]: continue
        dominates_i=np.all(scores<=scores[i],axis=1)&np.any(scores<scores[i],axis=1); dominates_i[i]=False
        if np.any(dominates_i): keep[i]=False
    return tuple(np.flatnonzero(keep).astype(int).tolist())


def propose_population(parent: CipherGenome, population_size: int, *, entropy: bytes | None = None) -> tuple[CipherGenome, ...]:
    return vectorized_mutation_population(parent, population_size, entropy)


def pareto_fitness_indices(records: tuple[FitnessRecord, ...]) -> tuple[int, ...]:
    return _pareto(records)
