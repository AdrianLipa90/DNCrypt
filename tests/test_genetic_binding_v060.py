from __future__ import annotations

import pytest

from dncrypt.genetic_binding import (
    decrypt_with_genetic_ir,
    encrypt_deterministic_with_genetic_ir_for_test,
    verify_genetic_ir_binding,
)
from dncrypt.genetic_ir import GeneticIRNode, GeneticLevel
from dncrypt.genome import initial_genome
from dncrypt.surface import initial_surface


def program(symbol: str) -> GeneticIRNode:
    kaku = GeneticIRNode(
        f"k:{symbol}",
        GeneticLevel.KAKU,
        {"symbol": symbol, "position_bp": 0},
    )
    radical = GeneticIRNode(
        f"r:{symbol}",
        GeneticLevel.RADICAL,
        {"motif_id": f"m:{symbol}"},
        (kaku,),
    )
    concept = GeneticIRNode(
        f"c:{symbol}",
        GeneticLevel.CONCEPT,
        {},
        (radical,),
    )
    return GeneticIRNode(
        f"s:{symbol}",
        GeneticLevel.SENTENCE,
        {"record_id": "fixture"},
        (concept,),
    )


def test_genetic_ir_commitment_is_authenticated_inside_frozen_user_aad():
    genome = initial_genome(b"g" * 64)
    surface = initial_surface(genome)
    ir = program("A")
    master_key = b"k" * 32
    envelope = encrypt_deterministic_with_genetic_ir_for_test(
        master_key,
        b"payload",
        genome,
        surface,
        ir,
        entropy=b"e" * 44,
        user_aad=b"caller-aad",
    )

    assert verify_genetic_ir_binding(envelope, ir) == b"caller-aad"
    plaintext, aad = decrypt_with_genetic_ir(
        master_key,
        envelope,
        genome,
        surface,
        ir,
    )
    assert plaintext == b"payload"
    assert aad == b"caller-aad"
    assert envelope.protocol_id == "dncrypt.frozen-protocol/v0.2"


def test_wrong_genetic_ir_is_rejected_before_decryption():
    genome = initial_genome(b"g" * 64)
    surface = initial_surface(genome)
    master_key = b"k" * 32
    envelope = encrypt_deterministic_with_genetic_ir_for_test(
        master_key,
        b"payload",
        genome,
        surface,
        program("A"),
        entropy=b"e" * 44,
    )

    with pytest.raises(ValueError, match="Genetic IR commitment mismatch"):
        decrypt_with_genetic_ir(
            master_key,
            envelope,
            genome,
            surface,
            program("C"),
        )
