"""DNCrypt v0.2 public API with optional lossless transport codecs."""
from .adversary import AttackReport, MutationPolicy, EvolutionReceipt, evolve_from_attack
from .binary_envelope import CODEC_ID as BINARY_ENVELOPE_CODEC_ID, binary_envelope_id, pack_envelope, unpack_envelope
from .bus import EvaluationRequest, make_evaluation_request, write_evaluation_request, load_external_evaluation
from .crypto import DNCryptEnvelope, decrypt, encrypt, generate_master_key
from .evolution import EvolutionPolicy, ProposalReceipt, PromotionReceipt, propose_generation, select_generation
from .evolution_ledger import append_evolution_receipt, verify_evolution_ledger
from .fitness import FitnessRecord, PopulationFitnessReport
from .genome import CipherGenome, initial_genome, mutate_genome, vectorized_mutation_population, population_commitment
from .state import DNCryptState, load_state, save_state_atomic
from .ledger import append_ledger_record, resolve_ledger_record
from .surface import CipherSurface, initial_surface, evolve_surface, transition_surface
from .transport import bytes_to_dna, dna_to_bytes, envelope_to_dna, envelope_from_dna

__all__ = [
    "AttackReport","MutationPolicy","EvolutionReceipt","evolve_from_attack",
    "BINARY_ENVELOPE_CODEC_ID","binary_envelope_id","pack_envelope","unpack_envelope",
    "EvaluationRequest","make_evaluation_request","write_evaluation_request","load_external_evaluation",
    "DNCryptEnvelope","decrypt","encrypt","generate_master_key",
    "EvolutionPolicy","ProposalReceipt","PromotionReceipt","propose_generation","select_generation",
    "append_evolution_receipt","verify_evolution_ledger",
    "FitnessRecord","PopulationFitnessReport",
    "CipherGenome","initial_genome","mutate_genome","vectorized_mutation_population","population_commitment",
    "DNCryptState","load_state","save_state_atomic","append_ledger_record","resolve_ledger_record",
    "CipherSurface","initial_surface","evolve_surface","transition_surface",
    "bytes_to_dna","dna_to_bytes","envelope_to_dna","envelope_from_dna",
]
