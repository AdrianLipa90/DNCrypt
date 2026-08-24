from __future__ import annotations
from dataclasses import dataclass, asdict
import math
import numpy as np
from .genome import CipherGenome
from .util import canonical_json_bytes, blake2b256

@dataclass(frozen=True, slots=True)
class FitnessRecord:
    genome_id: str
    generation: int
    structural_leakage: float
    predictability: float
    delta_bits: float
    delta_alpha: float
    avalanche_bias: float
    throughput: float
    decrypt_failures: int
    integrity_failures: int
    p_value: float
    source: str = "external_adversary"

    def __post_init__(self) -> None:
        floats = (self.structural_leakage, self.predictability, self.delta_bits, self.delta_alpha, self.avalanche_bias, self.throughput, self.p_value)
        if any(not math.isfinite(v) for v in floats):
            raise ValueError("fitness metrics must be finite")
        if self.generation < 0 or self.decrypt_failures < 0 or self.integrity_failures < 0:
            raise ValueError("generation/failure counts must be non-negative")
        if self.structural_leakage < 0 or self.predictability < 0 or self.avalanche_bias < 0 or self.throughput < 0:
            raise ValueError("leakage/predictability/avalanche_bias/throughput must be non-negative")
        if not 0.0 <= self.p_value <= 1.0:
            raise ValueError("p_value must be in [0,1]")
        if len(self.genome_id) != 64:
            raise ValueError("genome_id must be a 32-byte hex digest")

    @property
    def invariant_pass(self) -> bool:
        return self.decrypt_failures == 0 and self.integrity_failures == 0

    def adversarial_risk(self, significance_alpha: float = 0.05) -> float:
        if self.p_value > significance_alpha:
            advantage = 0.0
        else:
            advantage = max(0.0, self.delta_bits) + max(0.0, self.delta_alpha)
        return self.structural_leakage + self.predictability + self.avalanche_bias + advantage

@dataclass(frozen=True, slots=True)
class PopulationFitnessReport:
    schema: str
    request_id: str
    records: tuple[FitnessRecord, ...]

    def __post_init__(self) -> None:
        if self.schema != "dncrypt.external-evaluation/v0.2":
            raise ValueError("unsupported external evaluation schema")
        ids = [r.genome_id for r in self.records]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate genome_id in external evaluation")

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes({"schema": self.schema, "request_id": self.request_id, "records": [asdict(r) for r in self.records]}))

    def validate_population(self, population: tuple[CipherGenome, ...]) -> None:
        expected = {g.genome_id for g in population}
        observed = {r.genome_id for r in self.records}
        if observed != expected:
            missing = sorted(expected - observed)
            extra = sorted(observed - expected)
            raise ValueError(f"external evaluation does not exactly cover population; missing={missing} extra={extra}")
        generations = {g.generation for g in population}
        if len(generations) != 1:
            raise ValueError("population mixes generations")
        expected_generation = next(iter(generations))
        if any(r.generation != expected_generation for r in self.records):
            raise ValueError("external evaluation generation mismatch")

    def ordered_for(self, population: tuple[CipherGenome, ...]) -> tuple[FitnessRecord, ...]:
        self.validate_population(population)
        by_id = {r.genome_id: r for r in self.records}
        return tuple(by_id[g.genome_id] for g in population)


def objective_matrix(records: tuple[FitnessRecord, ...]) -> np.ndarray:
    if not records:
        return np.empty((0, 6), dtype=np.float64)
    return np.column_stack([
        np.asarray([r.structural_leakage for r in records], dtype=np.float64),
        np.asarray([r.predictability for r in records], dtype=np.float64),
        np.maximum(0.0, np.asarray([r.delta_bits for r in records], dtype=np.float64)),
        np.maximum(0.0, np.asarray([r.delta_alpha for r in records], dtype=np.float64)),
        np.asarray([r.avalanche_bias for r in records], dtype=np.float64),
        -np.asarray([r.throughput for r in records], dtype=np.float64),
    ])


def pareto_survivor_indices(records: tuple[FitnessRecord, ...]) -> tuple[int, ...]:
    scores = objective_matrix(records)
    n = scores.shape[0]
    keep = np.ones(n, dtype=bool)
    for i in range(n):
        if not keep[i]:
            continue
        dominates_i = np.all(scores <= scores[i], axis=1) & np.any(scores < scores[i], axis=1)
        dominates_i[i] = False
        if np.any(dominates_i):
            keep[i] = False
    return tuple(np.flatnonzero(keep).astype(int).tolist())
