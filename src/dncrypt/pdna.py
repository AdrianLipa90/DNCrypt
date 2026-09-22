"""Portable .pdna container for DNCrypt Genetic IR v0.6.

The container stores program/genome state and provenance.  It MUST NOT contain
DNCrypt master keys, AEAD salts/nonces, evaluator signing keys or other secret
key material.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import math
from typing import Any, Mapping

from .genetic_ir import (
    GeneticIRNode,
    compile_ir_to_phase36,
    source_binding,
)
from .genome import CipherGenome
from .util import blake2b256, canonical_json_bytes

PDNA_SCHEMA = "dncrypt.pdna/v0.6"
_TOP_LEVEL_FIELDS = frozenset({
    "schema",
    "pdna_id",
    "parent_pdna_id",
    "genome_id",
    "cipher_genome",
    "genetic_ir_id",
    "genetic_ir",
    "cipher_phase36",
    "genetic_phase36",
    "source_binding",
    "metadata",
    "authority",
})


@dataclass(frozen=True, slots=True)
class PDNARecord:
    genome: CipherGenome
    program: GeneticIRNode
    parent_pdna_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.parent_pdna_id is not None:
            if len(self.parent_pdna_id) != 64:
                raise ValueError("parent_pdna_id must be a 32-byte hex digest")
            try:
                int(self.parent_pdna_id, 16)
            except ValueError as exc:
                raise ValueError("parent_pdna_id must be hexadecimal") from exc
        canonical_json_bytes(dict(self.metadata))

    def _payload(self) -> dict[str, object]:
        cipher_phase = tuple(float(x) for x in self.genome.phase36())
        genetic_phase = tuple(float(x) for x in compile_ir_to_phase36(self.program))
        if (
            len(cipher_phase) != 36
            or len(genetic_phase) != 36
            or not all(math.isfinite(x) for x in cipher_phase + genetic_phase)
        ):
            raise ValueError("PDNA phase projections must be finite 36D vectors")
        return {
            "schema": PDNA_SCHEMA,
            "parent_pdna_id": self.parent_pdna_id,
            "genome_id": self.genome.genome_id,
            "cipher_genome": asdict(self.genome),
            "genetic_ir_id": self.program.semantic_id,
            "genetic_ir": self.program.to_dict(),
            "cipher_phase36": list(cipher_phase),
            "genetic_phase36": list(genetic_phase),
            "source_binding": source_binding(),
            "metadata": dict(self.metadata),
            "authority": {
                "diagnostic_only": True,
                "security_admission": False,
                "contains_master_key": False,
                "changes_frozen_aead": False,
            },
        }

    @property
    def pdna_id(self) -> str:
        return blake2b256(canonical_json_bytes(self._payload()))

    def to_dict(self) -> dict[str, object]:
        payload = self._payload()
        return {
            "schema": payload.pop("schema"),
            "pdna_id": self.pdna_id,
            **payload,
        }

    def to_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    @classmethod
    def from_bytes(cls, raw: bytes) -> "PDNARecord":
        try:
            value = json.loads(bytes(raw).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("PDNA payload is not valid UTF-8 JSON") from exc
        if not isinstance(value, dict):
            raise ValueError("PDNA root must be an object")
        if frozenset(value) != _TOP_LEVEL_FIELDS:
            raise ValueError("PDNA top-level schema mismatch")
        if value.get("schema") != PDNA_SCHEMA:
            raise ValueError("unsupported PDNA schema")
        if canonical_json_bytes(value) != bytes(raw):
            raise ValueError("PDNA encoding is not canonical")

        genome_value = value.get("cipher_genome")
        ir_value = value.get("genetic_ir")
        metadata = value.get("metadata")
        if not isinstance(genome_value, Mapping):
            raise ValueError("cipher_genome must be an object")
        if not isinstance(ir_value, Mapping):
            raise ValueError("genetic_ir must be an object")
        if not isinstance(metadata, Mapping):
            raise ValueError("metadata must be an object")

        try:
            genome = CipherGenome(**dict(genome_value))
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid cipher_genome") from exc
        program = GeneticIRNode.from_mapping(ir_value)

        record = cls(
            genome=genome,
            program=program,
            parent_pdna_id=value.get("parent_pdna_id"),
            metadata=dict(metadata),
        )
        if value.get("genome_id") != genome.genome_id:
            raise ValueError("PDNA genome_id mismatch")
        if value.get("genetic_ir_id") != program.semantic_id:
            raise ValueError("PDNA genetic_ir_id mismatch")
        if value.get("source_binding") != source_binding():
            raise ValueError("PDNA source binding mismatch")

        cipher_phase = value.get("cipher_phase36")
        genetic_phase = value.get("genetic_phase36")
        if (
            not isinstance(cipher_phase, list)
            or not isinstance(genetic_phase, list)
            or len(cipher_phase) != 36
            or len(genetic_phase) != 36
        ):
            raise ValueError("PDNA must carry two exact 36D projections")
        if tuple(float(x) for x in cipher_phase) != tuple(record.genome.phase36()):
            raise ValueError("PDNA cipher_phase36 mismatch")
        if tuple(float(x) for x in genetic_phase) != compile_ir_to_phase36(record.program):
            raise ValueError("PDNA genetic_phase36 mismatch")
        if value.get("pdna_id") != record.pdna_id:
            raise ValueError("PDNA commitment mismatch")
        authority = value.get("authority")
        if not isinstance(authority, Mapping):
            raise ValueError("PDNA authority block missing")
        if authority.get("contains_master_key") is not False:
            raise ValueError("PDNA secret-material boundary violated")
        return record
