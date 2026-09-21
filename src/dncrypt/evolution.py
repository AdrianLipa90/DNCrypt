from __future__ import annotations
from dataclasses import dataclass, asdict
import math, secrets
from .bus import make_evaluation_request
from .fitness import FitnessRecord, PopulationFitnessReport, pareto_survivor_indices
from .genome import CipherGenome, vectorized_mutation_population, population_commitment
from .surface import CipherSurface, transition_surface
from .util import canonical_json_bytes, blake2b256

@dataclass(frozen=True, slots=True)
class EvolutionPolicy:
    population_size: int = 64
    significance_alpha: float = 0.05
    mutation_risk_threshold: float = 0.02
    minimum_risk_improvement: float = 0.0
    minimum_throughput_ratio: float = 0.50
    surface_transition_steps: int = 1

    def __post_init__(self) -> None:
        if self.population_size <= 0:
            raise ValueError("population_size must be positive")
        if not 0 < self.significance_alpha <= 1:
            raise ValueError("invalid significance_alpha")
        if self.mutation_risk_threshold < 0 or self.minimum_risk_improvement < 0:
            raise ValueError("risk thresholds must be non-negative")
        if not 0 < self.minimum_throughput_ratio <= 1:
            raise ValueError("minimum_throughput_ratio must be in (0,1]")
        if self.surface_transition_steps <= 0:
            raise ValueError("surface_transition_steps must be positive")

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))

@dataclass(frozen=True, slots=True)
class ProposalReceipt:
    schema: str
    parent_genome_id: str
    parent_report_digest: str
    policy_digest: str
    population_commitment: str | None
    entropy_commitment: str | None
    proposed: bool
    reason: str

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))

@dataclass(frozen=True, slots=True)
class PromotionReceipt:
    schema: str
    parent_genome_id: str
    parent_surface_commitment: str
    parent_tick: int
    candidate_report_digest: str
    population_commitment: str
    policy_digest: str
    selected_genome_id: str | None
    selected_surface_commitment: str | None
    selected_tick: int | None
    promoted: bool
    reason: str

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))


def _single_report_digest(report: FitnessRecord) -> str:
    return blake2b256(canonical_json_bytes(asdict(report)))


def propose_generation(parent: CipherGenome, parent_report: FitnessRecord, policy: EvolutionPolicy, *, entropy: bytes | None = None) -> tuple[tuple[CipherGenome, ...], ProposalReceipt]:
    if parent_report.genome_id != parent.genome_id or parent_report.generation != parent.generation:
        raise ValueError("parent attack report binding mismatch")
    if not parent_report.invariant_pass:
        raise ValueError("parent invariant report is not clean")
    risk = parent_report.adversarial_risk(policy.significance_alpha)
    should_propose = risk > policy.mutation_risk_threshold
    if not should_propose:
        receipt = ProposalReceipt("dncrypt.proposal-receipt/v0.2", parent.genome_id, _single_report_digest(parent_report), policy.digest, None, None, False, "parent_within_frozen_risk_threshold")
        return tuple(), receipt
    raw = secrets.token_bytes(policy.population_size * 64) if entropy is None else bytes(entropy)
    if len(raw) != policy.population_size * 64:
        raise ValueError("proposal entropy must be exactly population_size*64 bytes")
    population = vectorized_mutation_population(parent, policy.population_size, raw)
    receipt = ProposalReceipt(
        "dncrypt.proposal-receipt/v0.2", parent.genome_id, _single_report_digest(parent_report), policy.digest,
        population_commitment(population), blake2b256(raw), True, "significant_adversarial_risk_above_threshold",
    )
    return population, receipt


def select_generation(parent: CipherGenome, parent_surface: CipherSurface, parent_report: FitnessRecord, population: tuple[CipherGenome, ...], candidate_report: PopulationFitnessReport, policy: EvolutionPolicy) -> tuple[CipherGenome, CipherSurface, PromotionReceipt]:
    if not population:
        raise ValueError("population must not be empty")
    if parent_report.genome_id != parent.genome_id or parent_report.generation != parent.generation:
        raise ValueError("parent report binding mismatch")
    if not parent_report.invariant_pass:
        raise ValueError("parent invariant report is not clean")
    if any(g.parent_id != parent.genome_id or g.generation != parent.generation + 1 for g in population):
        raise ValueError("population lineage mismatch")
    expected_request = make_evaluation_request(parent, population)
    if candidate_report.request_id != expected_request.request_id:
        raise ValueError("candidate report request_id mismatch")
    candidate_report.validate_population(population)
    ordered = candidate_report.ordered_for(population)
    valid_indices = tuple(i for i, r in enumerate(ordered) if r.invariant_pass)
    pop_commit = population_commitment(population)
    if not valid_indices:
        receipt = PromotionReceipt("dncrypt.promotion-receipt/v0.2", parent.genome_id, parent_surface.commitment, parent_surface.tick, candidate_report.digest, pop_commit, policy.digest, None, None, None, False, "no_candidate_passed_frozen_decrypt_integrity_invariants")
        return parent, parent_surface, receipt
    valid_records = tuple(ordered[i] for i in valid_indices)
    local_survivors = pareto_survivor_indices(valid_records)
    survivor_indices = tuple(valid_indices[i] for i in local_survivors)
    parent_risk = parent_report.adversarial_risk(policy.significance_alpha)
    parent_throughput = max(parent_report.throughput, 1e-12)

    def rank(i: int) -> tuple[float, float, float, str]:
        r = ordered[i]
        return (r.adversarial_risk(policy.significance_alpha), r.avalanche_bias, -r.throughput, r.genome_id)

    chosen_index = min(survivor_indices, key=rank)
    chosen = population[chosen_index]
    chosen_report = ordered[chosen_index]
    chosen_risk = chosen_report.adversarial_risk(policy.significance_alpha)
    risk_improved = chosen_risk + policy.minimum_risk_improvement < parent_risk
    throughput_ok = chosen_report.throughput >= parent_throughput * policy.minimum_throughput_ratio
    if not risk_improved:
        receipt = PromotionReceipt("dncrypt.promotion-receipt/v0.2", parent.genome_id, parent_surface.commitment, parent_surface.tick, candidate_report.digest, pop_commit, policy.digest, chosen.genome_id, None, None, False, "best_candidate_did_not_improve_adversarial_risk")
        return parent, parent_surface, receipt
    if not throughput_ok:
        receipt = PromotionReceipt("dncrypt.promotion-receipt/v0.2", parent.genome_id, parent_surface.commitment, parent_surface.tick, candidate_report.digest, pop_commit, policy.digest, chosen.genome_id, None, None, False, "best_candidate_failed_minimum_throughput_ratio")
        return parent, parent_surface, receipt
    child_surface = transition_surface(parent_surface, chosen, steps=policy.surface_transition_steps)
    receipt = PromotionReceipt("dncrypt.promotion-receipt/v0.2", parent.genome_id, parent_surface.commitment, parent_surface.tick, candidate_report.digest, pop_commit, policy.digest, chosen.genome_id, child_surface.commitment, child_surface.tick, True, "pareto_survivor_improved_risk_and_passed_frozen_invariants")
    return chosen, child_surface, receipt
