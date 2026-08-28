from __future__ import annotations

from dataclasses import asdict, dataclass, replace

from .fitness import FitnessRecord, PopulationFitnessReport
from .generalization import CandidateGeneralizationScore, GeneralizationPolicy, GeneralizationPromotionReceipt
from .genome import CipherGenome
from .security_admission import SecurityAdmissionBinding, select_generation_multifold_security_only
from .surface import CipherSurface
from .util import blake2b256, canonical_json_bytes

RISK_FIELDS = ("structural_leakage", "predictability", "delta_bits", "delta_alpha", "avalanche_bias")
KNOWN_FIELDS = frozenset((*RISK_FIELDS, "throughput", "decrypt_failures", "integrity_failures"))
ROLES = frozenset(("ADMISSION", "DIAGNOSTIC_ONLY", "HARD_INVARIANT", "PERFORMANCE_OBSERVATION"))


@dataclass(frozen=True, slots=True)
class MetricCausalityBinding:
    fitness_field: str
    role: str
    controlled_by: tuple[str, ...]
    mechanism_id: str
    falsification_test_id: str

    def __post_init__(self) -> None:
        if self.fitness_field not in KNOWN_FIELDS:
            raise ValueError(f"unknown fitness field: {self.fitness_field}")
        if self.role not in ROLES:
            raise ValueError(f"unknown causality role: {self.role}")
        if self.role == "ADMISSION":
            if not self.controlled_by or not self.mechanism_id or not self.falsification_test_id:
                raise ValueError("ADMISSION metric requires controls, mechanism, and falsification test")


@dataclass(frozen=True, slots=True)
class FitnessCausalityRegistry:
    schema: str
    bindings: tuple[MetricCausalityBinding, ...]

    def __post_init__(self) -> None:
        if self.schema != "dncrypt.fitness-causality-registry/v0.4.2":
            raise ValueError("unsupported causality registry schema")
        fields = [binding.fitness_field for binding in self.bindings]
        if len(fields) != len(set(fields)):
            raise ValueError("duplicate fitness field in causality registry")
        missing = KNOWN_FIELDS - set(fields)
        if missing:
            raise ValueError(f"causality registry missing fields: {sorted(missing)}")

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))

    @property
    def admission_fields(self) -> tuple[str, ...]:
        return tuple(sorted(binding.fitness_field for binding in self.bindings if binding.role == "ADMISSION"))

    @property
    def diagnostic_fields(self) -> tuple[str, ...]:
        return tuple(sorted(binding.fitness_field for binding in self.bindings if binding.role == "DIAGNOSTIC_ONLY"))

    def role_for(self, field: str) -> str:
        for binding in self.bindings:
            if binding.fitness_field == field:
                return binding.role
        raise KeyError(field)


def frozen_v02_causality_registry() -> FitnessCausalityRegistry:
    """Causal classification for the frozen v0.2 Python anchor.

    Ciphertext-distribution statistics remain diagnostics. The current genome binds
    the HKDF domain identity and the authenticated surface/provenance context; the
    frozen AEAD/KDF primitives remain fixed across candidates. Decrypt/integrity
    failures remain hard invariants.
    """
    return FitnessCausalityRegistry(
        schema="dncrypt.fitness-causality-registry/v0.4.2",
        bindings=(
            MetricCausalityBinding("structural_leakage", "DIAGNOSTIC_ONLY", ("genome_id",), "FROZEN_AEAD_OUTPUT_DIAGNOSTIC", "PAIRED_CORPUS_NULL_TEST"),
            MetricCausalityBinding("predictability", "DIAGNOSTIC_ONLY", ("genome_id",), "FROZEN_AEAD_OUTPUT_DIAGNOSTIC", "PAIRED_CORPUS_NULL_TEST"),
            MetricCausalityBinding("delta_bits", "DIAGNOSTIC_ONLY", (), "EXTERNAL_ATTACK_DIAGNOSTIC", "ATTACK_SPECIFIC_CAUSAL_BINDING_REQUIRED"),
            MetricCausalityBinding("delta_alpha", "DIAGNOSTIC_ONLY", (), "EXTERNAL_ATTACK_DIAGNOSTIC", "ATTACK_SPECIFIC_CAUSAL_BINDING_REQUIRED"),
            MetricCausalityBinding("avalanche_bias", "DIAGNOSTIC_ONLY", ("genome_id",), "FROZEN_AEAD_OUTPUT_DIAGNOSTIC", "PAIRED_CORPUS_NULL_TEST"),
            MetricCausalityBinding("throughput", "PERFORMANCE_OBSERVATION", (), "WALLCLOCK_MEASUREMENT", "REPEATED_HOST_MEASUREMENT"),
            MetricCausalityBinding("decrypt_failures", "HARD_INVARIANT", ("genome_id", "surface_commitment"), "ROUNDTRIP_BINDING", "DECRYPT_ROUNDTRIP_TEST"),
            MetricCausalityBinding("integrity_failures", "HARD_INVARIANT", ("genome_id", "surface_commitment", "aad"), "AEAD_PROVENANCE_BINDING", "TAMPER_REJECTION_TEST"),
        ),
    )


def _firewall_record(record: FitnessRecord, registry: FitnessCausalityRegistry) -> FitnessRecord:
    values = {
        field: getattr(record, field) if registry.role_for(field) == "ADMISSION" else 0.0
        for field in RISK_FIELDS
    }
    return replace(record, **values)


def _firewall_report(report: PopulationFitnessReport, registry: FitnessCausalityRegistry) -> PopulationFitnessReport:
    records = tuple(_firewall_record(record, registry) for record in report.records)
    request_id = blake2b256(canonical_json_bytes({
        "domain": "dncrypt.causality-firewall-report/v0.4.2",
        "registry_digest": registry.digest,
        "records": [asdict(record) for record in records],
    }))
    return PopulationFitnessReport(report.schema, request_id, records)


@dataclass(frozen=True, slots=True)
class CausalityFirewallReceipt:
    schema: str
    registry_digest: str
    admission_fields: tuple[str, ...]
    diagnostic_fields: tuple[str, ...]
    base_security_binding_digest: str
    selected_genome_id: str | None
    promoted: bool

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))


def select_generation_multifold_causal(
    parent: CipherGenome,
    parent_surface: CipherSurface,
    parent_fold_reports: tuple[FitnessRecord, ...],
    population: tuple[CipherGenome, ...],
    candidate_fold_reports: tuple[PopulationFitnessReport, ...],
    policy: GeneralizationPolicy,
    *,
    sealed_holdout_commitment: str,
    registry: FitnessCausalityRegistry | None = None,
) -> tuple[
    CipherGenome,
    CipherSurface,
    GeneralizationPromotionReceipt,
    tuple[CandidateGeneralizationScore, ...],
    SecurityAdmissionBinding,
    CausalityFirewallReceipt,
]:
    active = frozen_v02_causality_registry() if registry is None else registry
    parents = tuple(_firewall_record(record, active) for record in parent_fold_reports)
    candidates = tuple(_firewall_report(report, active) for report in candidate_fold_reports)
    child, surface, promotion, scores, security_binding = select_generation_multifold_security_only(
        parent,
        parent_surface,
        parents,
        population,
        candidates,
        policy,
        sealed_holdout_commitment=sealed_holdout_commitment,
    )
    firewall = CausalityFirewallReceipt(
        schema="dncrypt.causality-firewall-receipt/v0.4.2",
        registry_digest=active.digest,
        admission_fields=active.admission_fields,
        diagnostic_fields=active.diagnostic_fields,
        base_security_binding_digest=security_binding.digest,
        selected_genome_id=promotion.selected_genome_id,
        promoted=promotion.promoted,
    )
    return child, surface, promotion, scores, security_binding, firewall
