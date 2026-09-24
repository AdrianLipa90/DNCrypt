"""Unified logical state for the DNCrypt v0.6.1 genetic-control candidate.

The frozen v0.2 cryptographic core remains untouched.  This module closes the
research-level identity across CipherGenome, CipherSurface, Genetic IR and PDNA
without allowing diagnostic genetics to become cryptographic entropy or
security-admission evidence.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping

from .genetic_compiler import MutationPhenotype, compile_genetic_program
from .genetic_ir import GeneticIRNode
from .genome import CipherGenome
from .pdna import PDNARecord
from .state import DNCryptState
from .surface import CipherSurface
from .util import blake2b256, canonical_json_bytes

UNIFIED_STATE_SCHEMA = "dncrypt.unified-state/v0.6.1-candidate"
PDNA_STATE_BINDING_SCHEMA = "dncrypt.pdna-state-binding/v0.6.1-candidate"


def _validate_digest(value: str | None, name: str) -> None:
    if value is None:
        return
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(name + " must be a 64-character hex digest")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(name + " must be hexadecimal") from exc


def _core_payload(state: DNCryptState) -> dict[str, object]:
    return {
        "genome": asdict(state.genome),
        "surface": asdict(state.surface),
        "last_receipt": state.last_receipt,
        "last_evolution_receipt": state.last_evolution_receipt,
    }


def _core_from_mapping(value: Mapping[str, Any]) -> DNCryptState:
    if set(value) != {"genome", "surface", "last_receipt", "last_evolution_receipt"}:
        raise ValueError("unified core_state schema mismatch")
    try:
        g = dict(value["genome"])
        s = dict(value["surface"])
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid unified core_state") from exc
    g["operator_vector"] = tuple(g["operator_vector"])
    g["route"] = tuple(g["route"])
    s["phi"] = tuple(s["phi"])
    s["omega"] = tuple(s["omega"])
    return DNCryptState(
        CipherGenome(**g),
        CipherSurface(**s),
        value.get("last_receipt"),
        value.get("last_evolution_receipt"),
    )


@dataclass(frozen=True, slots=True)
class UnifiedDNCryptState:
    core_state: DNCryptState
    program: GeneticIRNode
    parent_pdna_id: str | None = None
    evidence_commitment: str | None = None
    compiler_commitment: str | None = None
    schema: str = UNIFIED_STATE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != UNIFIED_STATE_SCHEMA:
            raise ValueError("unsupported unified-state schema")
        _validate_digest(self.parent_pdna_id, "parent_pdna_id")
        _validate_digest(self.evidence_commitment, "evidence_commitment")
        _validate_digest(self.compiler_commitment, "compiler_commitment")
        expected_compiler = compile_genetic_program(self.program).commitment
        if self.compiler_commitment is not None and self.compiler_commitment != expected_compiler:
            raise ValueError("compiler commitment does not match Genetic IR")

    @property
    def genome(self) -> CipherGenome:
        return self.core_state.genome

    @property
    def surface(self) -> CipherSurface:
        return self.core_state.surface

    @property
    def genetic_ir_id(self) -> str:
        return self.program.semantic_id

    @property
    def phenotype(self) -> MutationPhenotype:
        return compile_genetic_program(self.program)

    @property
    def effective_compiler_commitment(self) -> str:
        return self.compiler_commitment or self.phenotype.commitment

    def _closure_payload(self) -> dict[str, object]:
        return {
            "schema": PDNA_STATE_BINDING_SCHEMA,
            "genome_id": self.genome.genome_id,
            "generation": self.genome.generation,
            "surface_commitment": self.surface.commitment,
            "surface_tick": self.surface.tick,
            "genetic_ir_id": self.genetic_ir_id,
            "parent_pdna_id": self.parent_pdna_id,
            "evidence_commitment": self.evidence_commitment,
            "compiler_commitment": self.effective_compiler_commitment,
        }

    @property
    def closure_commitment(self) -> str:
        return blake2b256(canonical_json_bytes(self._closure_payload()))

    @property
    def pdna(self) -> PDNARecord:
        metadata = {
            "binding_schema": PDNA_STATE_BINDING_SCHEMA,
            "surface_commitment": self.surface.commitment,
            "surface_tick": self.surface.tick,
            "evidence_commitment": self.evidence_commitment,
            "compiler_commitment": self.effective_compiler_commitment,
            "closure_commitment": self.closure_commitment,
        }
        return PDNARecord(
            genome=self.genome,
            program=self.program,
            parent_pdna_id=self.parent_pdna_id,
            metadata=metadata,
        )

    @property
    def pdna_id(self) -> str:
        return self.pdna.pdna_id

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "core_state": _core_payload(self.core_state),
            "genetic_ir": self.program.to_dict(),
            "genetic_ir_id": self.genetic_ir_id,
            "parent_pdna_id": self.parent_pdna_id,
            "evidence_commitment": self.evidence_commitment,
            "compiler_commitment": self.effective_compiler_commitment,
            "closure_commitment": self.closure_commitment,
            "pdna_id": self.pdna_id,
            "authority": {
                "changes_frozen_aead": False,
                "cryptographic_entropy_from_genetic_ir": False,
                "security_admission_from_genetic_ir": False,
                "checkpoint_binding_required_for_rollback": True,
            },
        }

    @property
    def commitment(self) -> str:
        return blake2b256(canonical_json_bytes(self.to_dict()))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "UnifiedDNCryptState":
        expected = {
            "schema",
            "core_state",
            "genetic_ir",
            "genetic_ir_id",
            "parent_pdna_id",
            "evidence_commitment",
            "compiler_commitment",
            "closure_commitment",
            "pdna_id",
            "authority",
        }
        if set(value) != expected:
            raise ValueError("unified-state top-level schema mismatch")
        if value.get("schema") != UNIFIED_STATE_SCHEMA:
            raise ValueError("unsupported unified-state schema")

        raw_core = value.get("core_state")
        raw_program = value.get("genetic_ir")
        if not isinstance(raw_core, Mapping) or not isinstance(raw_program, Mapping):
            raise ValueError("unified-state core/program must be objects")

        state = cls(
            core_state=_core_from_mapping(raw_core),
            program=GeneticIRNode.from_mapping(raw_program),
            parent_pdna_id=value.get("parent_pdna_id"),
            evidence_commitment=value.get("evidence_commitment"),
            compiler_commitment=value.get("compiler_commitment"),
        )
        if value.get("genetic_ir_id") != state.genetic_ir_id:
            raise ValueError("unified-state genetic_ir_id mismatch")
        if value.get("closure_commitment") != state.closure_commitment:
            raise ValueError("unified-state closure commitment mismatch")
        if value.get("pdna_id") != state.pdna_id:
            raise ValueError("unified-state PDNA commitment mismatch")
        if value.get("authority") != state.to_dict()["authority"]:
            raise ValueError("unified-state authority block mismatch")
        return state

    def verify_pdna(self, record: PDNARecord | None = None) -> bool:
        active = self.pdna if record is None else record
        if active.genome.genome_id != self.genome.genome_id:
            raise ValueError("PDNA genome does not match unified state")
        if active.program.semantic_id != self.genetic_ir_id:
            raise ValueError("PDNA Genetic IR does not match unified state")
        if active.parent_pdna_id != self.parent_pdna_id:
            raise ValueError("PDNA parent lineage does not match unified state")
        metadata = dict(active.metadata)
        expected = dict(self.pdna.metadata)
        if metadata != expected:
            raise ValueError("PDNA state-binding metadata mismatch")
        if active.pdna_id != self.pdna_id:
            raise ValueError("PDNA id does not match unified state")
        return True


def bind_unified_state(
    core_state: DNCryptState,
    program: GeneticIRNode,
    *,
    parent_pdna_id: str | None = None,
    evidence_commitment: str | None = None,
) -> UnifiedDNCryptState:
    phenotype = compile_genetic_program(program)
    return UnifiedDNCryptState(
        core_state=core_state,
        program=program,
        parent_pdna_id=parent_pdna_id,
        evidence_commitment=evidence_commitment,
        compiler_commitment=phenotype.commitment,
    )


def transition_unified_state(
    parent: UnifiedDNCryptState,
    *,
    core_state: DNCryptState,
    program: GeneticIRNode | None = None,
    evidence_commitment: str | None = None,
) -> UnifiedDNCryptState:
    next_program = parent.program if program is None else program
    return bind_unified_state(
        core_state,
        next_program,
        parent_pdna_id=parent.pdna_id,
        evidence_commitment=evidence_commitment,
    )


__all__ = [
    "PDNA_STATE_BINDING_SCHEMA",
    "UNIFIED_STATE_SCHEMA",
    "UnifiedDNCryptState",
    "bind_unified_state",
    "transition_unified_state",
]
