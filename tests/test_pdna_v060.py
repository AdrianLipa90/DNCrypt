from __future__ import annotations

import json

import pytest

from dncrypt.genetic_ir import GeneticIRNode, GeneticLevel
from dncrypt.genome import initial_genome
from dncrypt.pdna import PDNARecord
from dncrypt.util import canonical_json_bytes


def sample_program() -> GeneticIRNode:
    kaku = GeneticIRNode("k1", GeneticLevel.KAKU, {"symbol": "A", "position_bp": 0})
    radical = GeneticIRNode("r1", GeneticLevel.RADICAL, {"motif_id": "A"}, (kaku,))
    concept = GeneticIRNode("c1", GeneticLevel.CONCEPT, {}, (radical,))
    return GeneticIRNode("s1", GeneticLevel.SENTENCE, {"record_id": "x"}, (concept,))


def test_pdna_roundtrip_is_canonical_and_commitment_preserving():
    record = PDNARecord(
        genome=initial_genome(b"p" * 64),
        program=sample_program(),
        metadata={"purpose": "test"},
    )
    raw = record.to_bytes()
    recovered = PDNARecord.from_bytes(raw)

    assert recovered.pdna_id == record.pdna_id
    assert recovered.genome.genome_id == record.genome.genome_id
    assert recovered.program.semantic_id == record.program.semantic_id
    value = json.loads(raw)
    assert len(value["cipher_phase36"]) == 36
    assert len(value["genetic_phase36"]) == 36
    assert value["authority"]["contains_master_key"] is False


def test_pdna_detects_tampered_genetic_phase():
    record = PDNARecord(
        genome=initial_genome(b"p" * 64),
        program=sample_program(),
    )
    value = record.to_dict()
    value["genetic_phase36"][0] += 0.25
    raw = canonical_json_bytes(value)

    with pytest.raises(ValueError, match="genetic_phase36 mismatch"):
        PDNARecord.from_bytes(raw)


def test_pdna_detects_commitment_tamper():
    record = PDNARecord(
        genome=initial_genome(b"p" * 64),
        program=sample_program(),
    )
    value = record.to_dict()
    value["pdna_id"] = "0" * 64

    with pytest.raises(ValueError, match="PDNA commitment mismatch"):
        PDNARecord.from_bytes(canonical_json_bytes(value))
