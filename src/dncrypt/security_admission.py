from __future__ import annotations

from dataclasses import asdict, dataclass, replace

from .fitness import FitnessRecord, PopulationFitnessReport
from .generalization import GeneralizationPolicy, GeneralizationPromotionReceipt, CandidateGeneralizationScore, select_generation_multifold
from .genome import CipherGenome
from .surface import CipherSurface
from .util import blake2b256, canonical_json_bytes


@dataclass(frozen=True, slots=True)
class SecurityAdmissionBinding:
    schema: str
    performance_mode: str
    normalized_parent_commitment: str
    normalized_candidate_commitment: str
    base_promotion_receipt_digest: str
    selected_genome_id: str | None
    promoted: bool

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))


def _security_record(record: FitnessRecord) -> FitnessRecord:
    return replace(record, throughput=1.0)


def _security_record_commitment(records: tuple[FitnessRecord, ...]) -> str:
    return blake2b256(canonical_json_bytes([asdict(record) for record in records]))


def _security_report(report: PopulationFitnessReport) -> PopulationFitnessReport:
    records = tuple(_security_record(record) for record in report.records)
    request_id = blake2b256(canonical_json_bytes({
        "domain": "dncrypt.security-admission-report/v0.4.1",
        "records": [asdict(record) for record in records],
    }))
    return PopulationFitnessReport(report.schema, request_id, records)


def select_generation_multifold_security_only(
    parent: CipherGenome,
    parent_surface: CipherSurface,
    parent_fold_reports: tuple[FitnessRecord, ...],
    population: tuple[CipherGenome, ...],
    candidate_fold_reports: tuple[PopulationFitnessReport, ...],
    policy: GeneralizationPolicy,
    *,
    sealed_holdout_commitment: str,
) -> tuple[
    CipherGenome,
    CipherSurface,
    GeneralizationPromotionReceipt,
    tuple[CandidateGeneralizationScore, ...],
    SecurityAdmissionBinding,
]:
    """Run v0.4 generalization admission with performance observational only.

    Wall-clock throughput is normalized to one for security admission. The caller
    retains the original reports as performance evidence, but throughput cannot
    influence hard gating, Pareto dominance, or deterministic tie-breaking.
    """
    security_parents = tuple(_security_record(record) for record in parent_fold_reports)
    security_candidates = tuple(_security_report(report) for report in candidate_fold_reports)
    security_policy = replace(policy, minimum_throughput_ratio=1.0)

    child, surface, receipt, scores = select_generation_multifold(
        parent,
        parent_surface,
        security_parents,
        population,
        security_candidates,
        security_policy,
        sealed_holdout_commitment=sealed_holdout_commitment,
    )
    normalized_candidate_records = tuple(
        record
        for report in security_candidates
        for record in report.records
    )
    binding = SecurityAdmissionBinding(
        schema="dncrypt.security-admission-binding/v0.4.1",
        performance_mode="observe_only",
        normalized_parent_commitment=_security_record_commitment(security_parents),
        normalized_candidate_commitment=_security_record_commitment(normalized_candidate_records),
        base_promotion_receipt_digest=receipt.digest,
        selected_genome_id=receipt.selected_genome_id,
        promoted=receipt.promoted,
    )
    return child, surface, receipt, scores, binding
