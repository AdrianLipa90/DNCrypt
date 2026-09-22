"""DNCrypt public API: frozen v0.2 AEAD anchor with v0.6 Genetic IR research interfaces."""
from .adversary import AttackReport, MutationPolicy, EvolutionReceipt, evolve_from_attack
from .anti_rollback import MonotonicJournalAnchor, MonotonicAnchorPort, InMemoryMonotonicAnchor, advance_journal_anchor, verify_journal_against_anchor
from .binary_envelope import CODEC_ID as BINARY_ENVELOPE_CODEC_ID, binary_envelope_id, pack_envelope, unpack_envelope
from .bus import EvaluationRequest, make_evaluation_request, write_evaluation_request, load_external_evaluation
from .evaluator_auth import SignedEvaluationEnvelope, sign_evaluation_report, verify_signed_evaluation, load_signed_external_evaluation
from .crypto import DNCryptEnvelope, decrypt, encrypt, encrypt_deterministic_for_test, generate_master_key
from .evolution import EvolutionPolicy, ProposalReceipt, PromotionReceipt, propose_generation, select_generation
from .generalization import (
    CandidateGeneralizationScore,
    GeneralizationPolicy,
    GeneralizationPromotionReceipt,
    robust_pareto_survivor_indices,
    select_generation_multifold,
)
from .security_admission import SecurityAdmissionBinding, select_generation_multifold_security_only
from .statistical_gate import StatisticalAdmissionPolicy, StatisticalCandidateEvidence, benjamini_hochberg_qvalues, population_statistical_gate, select_generation_multifold_statistically_hardened
from .causality import (
    CausalityFirewallReceipt,
    FitnessCausalityRegistry,
    MetricCausalityBinding,
    frozen_v02_causality_registry,
    select_generation_multifold_causal,
)
from .security_control import (
    SecurityControlPolicy, SecurityControlState, SecurityControlObservation, SecurityControlDecision,
    SecurityControlEvaluation, derive_security_control_policy, apply_security_control,
    rotate_control_state, evaluate_security_control,
)
from .evolution_ledger import append_evolution_receipt, verify_evolution_ledger
from .fitness import FitnessRecord, PopulationFitnessReport
from .genome import CipherGenome, initial_genome, mutate_genome, vectorized_mutation_population, population_commitment
from .genetic_ir import (
    GeneticIRNode,
    GeneticLevel,
    GeneticMutationReceipt,
    GeneticRelation,
    compile_ir_to_phase36,
    delete_child,
    import_cielingo_genomic_unit,
    rewrite_payload,
    source_binding as genetic_ir_source_binding,
    swap_adjacent_children,
)
from .genetic_binding import (
    decrypt_with_genetic_ir,
    encrypt_deterministic_with_genetic_ir_for_test,
    encrypt_with_genetic_ir,
    genetic_user_aad,
    verify_genetic_ir_binding,
)
from .pdna import PDNARecord, PDNA_SCHEMA
from .state import DNCryptState, load_state, save_state_atomic
from .ledger import append_ledger_record, resolve_ledger_record
from .surface import CipherSurface, initial_surface, evolve_surface, transition_surface
from .transport import bytes_to_dna, dna_to_bytes, envelope_to_dna, envelope_from_dna
from .twist_geometry_v02 import RelationalTwistClass, relative_permutation, permutation_cycles, relational_twist_class, vectorized_cyclic_novelty

__all__ = [
    "AttackReport","MutationPolicy","EvolutionReceipt","evolve_from_attack",
    "MonotonicJournalAnchor","MonotonicAnchorPort","InMemoryMonotonicAnchor","advance_journal_anchor","verify_journal_against_anchor",
    "BINARY_ENVELOPE_CODEC_ID","binary_envelope_id","pack_envelope","unpack_envelope",
    "EvaluationRequest","make_evaluation_request","write_evaluation_request","load_external_evaluation",
    "SignedEvaluationEnvelope","sign_evaluation_report","verify_signed_evaluation","load_signed_external_evaluation",
    "DNCryptEnvelope","decrypt","encrypt","encrypt_deterministic_for_test","generate_master_key",
    "EvolutionPolicy","ProposalReceipt","PromotionReceipt","propose_generation","select_generation",
    "GeneralizationPolicy","CandidateGeneralizationScore","GeneralizationPromotionReceipt",
    "robust_pareto_survivor_indices","select_generation_multifold",
    "SecurityAdmissionBinding","select_generation_multifold_security_only",
    "StatisticalAdmissionPolicy","StatisticalCandidateEvidence","benjamini_hochberg_qvalues","population_statistical_gate","select_generation_multifold_statistically_hardened",
    "CausalityFirewallReceipt","FitnessCausalityRegistry","MetricCausalityBinding",
    "frozen_v02_causality_registry","select_generation_multifold_causal",
    "SecurityControlPolicy","SecurityControlState","SecurityControlObservation","SecurityControlDecision",
    "SecurityControlEvaluation","derive_security_control_policy","apply_security_control",
    "rotate_control_state","evaluate_security_control",
    "append_evolution_receipt","verify_evolution_ledger",
    "FitnessRecord","PopulationFitnessReport",
    "CipherGenome","initial_genome","mutate_genome","vectorized_mutation_population","population_commitment",
    "GeneticIRNode","GeneticLevel","GeneticMutationReceipt","GeneticRelation",
    "compile_ir_to_phase36","delete_child","import_cielingo_genomic_unit",
    "rewrite_payload","genetic_ir_source_binding","swap_adjacent_children",
    "decrypt_with_genetic_ir","encrypt_deterministic_with_genetic_ir_for_test",
    "encrypt_with_genetic_ir","genetic_user_aad","verify_genetic_ir_binding",
    "PDNARecord","PDNA_SCHEMA",
    "DNCryptState","load_state","save_state_atomic","append_ledger_record","resolve_ledger_record",
    "CipherSurface","initial_surface","evolve_surface","transition_surface",
    "bytes_to_dna","dna_to_bytes","envelope_to_dna","envelope_from_dna",
    "RelationalTwistClass","relative_permutation","permutation_cycles","relational_twist_class","vectorized_cyclic_novelty",
]
