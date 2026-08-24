from __future__ import annotations
from dataclasses import dataclass, asdict
import math
from .genome import CipherGenome, mutate_genome
from .util import canonical_json_bytes, blake2b256

@dataclass(frozen=True, slots=True)
class AttackReport:
    delta_bits: float
    delta_alpha: float
    structural_leakage: float
    predictability: float
    p_value: float
    source: str = "external_adversary"
    def __post_init__(self) -> None:
        vals=(self.delta_bits,self.delta_alpha,self.structural_leakage,self.predictability,self.p_value)
        if any(not math.isfinite(v) for v in vals): raise ValueError("attack metrics must be finite")
        if not 0.0 <= self.p_value <= 1.0: raise ValueError("p_value must be in [0,1]")

@dataclass(frozen=True, slots=True)
class MutationPolicy:
    max_delta_bits: float=0.0; max_delta_alpha: float=0.0; max_structural_leakage: float=0.02; max_predictability: float=0.02; significance_alpha: float=0.05
    def should_mutate(self, report: AttackReport) -> bool:
        significant=report.p_value<=self.significance_alpha
        return significant and (report.delta_bits>self.max_delta_bits or report.delta_alpha>self.max_delta_alpha or report.structural_leakage>self.max_structural_leakage or report.predictability>self.max_predictability)

@dataclass(frozen=True, slots=True)
class EvolutionReceipt:
    parent_genome_id: str; child_genome_id: str; mutated: bool; report_digest: str; reason: str


def evolve_from_attack(parent: CipherGenome, report: AttackReport, policy: MutationPolicy, *, entropy: bytes | None=None) -> tuple[CipherGenome,EvolutionReceipt]:
    report_digest=blake2b256(canonical_json_bytes(asdict(report))); do=policy.should_mutate(report); child=mutate_genome(parent,entropy) if do else parent
    return child,EvolutionReceipt(parent.genome_id,child.genome_id,do,report_digest,"significant_adversarial_signal" if do else "within_frozen_thresholds")
