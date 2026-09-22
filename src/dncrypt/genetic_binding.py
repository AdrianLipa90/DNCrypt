"""Authenticated Genetic IR binding for the frozen DNCrypt v0.2 AEAD envelope.

The binding is carried entirely inside the existing authenticated user_aad
field.  No change is made to the frozen AEAD protocol, key derivation, nonce
generation or ChaCha20-Poly1305 primitive.
"""
from __future__ import annotations

import json

from .crypto import (
    DNCryptEnvelope,
    decrypt,
    encrypt,
    encrypt_deterministic_for_test,
)
from .genetic_ir import GeneticIRNode
from .genome import CipherGenome
from .surface import CipherSurface
from .util import b64d, b64e, canonical_json_bytes

GENETIC_AAD_SCHEMA = "dncrypt.genetic-ir-aad/v0.6"
_OUTER_AAD_FIELDS = frozenset({
    "version",
    "protocol_id",
    "generation",
    "tick",
    "genome_id",
    "surface_commitment",
    "parent_receipt",
    "user_aad",
})
_GENETIC_FIELDS = frozenset({
    "schema",
    "genetic_ir_id",
    "source_schema",
    "user_aad",
})


def genetic_user_aad(program: GeneticIRNode, user_aad: bytes = b"") -> bytes:
    if not isinstance(user_aad, (bytes, bytearray)):
        raise TypeError("user_aad must be bytes")
    return canonical_json_bytes({
        "schema": GENETIC_AAD_SCHEMA,
        "genetic_ir_id": program.semantic_id,
        "source_schema": "CIELINGO_GENOMIC_GRAMMAR_V0_1",
        "user_aad": b64e(bytes(user_aad)),
    })


def _extract_authenticated_user_aad(envelope: DNCryptEnvelope) -> bytes:
    try:
        raw = b64d(envelope.aad_b64)
        outer = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("authenticated AAD is malformed") from exc
    if not isinstance(outer, dict) or frozenset(outer) != _OUTER_AAD_FIELDS:
        raise ValueError("authenticated AAD schema mismatch")
    if canonical_json_bytes(outer) != raw:
        raise ValueError("authenticated AAD is not canonical")
    encoded = outer.get("user_aad")
    if not isinstance(encoded, str):
        raise ValueError("authenticated user_aad is invalid")
    try:
        return b64d(encoded)
    except Exception as exc:
        raise ValueError("authenticated user_aad is invalid") from exc


def verify_genetic_ir_binding(
    envelope: DNCryptEnvelope,
    program: GeneticIRNode,
) -> bytes:
    """Verify the authenticated IR commitment and return caller user AAD."""

    if not envelope.verify_receipt():
        raise ValueError("provenance receipt mismatch")
    nested_raw = _extract_authenticated_user_aad(envelope)
    try:
        nested = json.loads(nested_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Genetic IR AAD binding is malformed") from exc
    if not isinstance(nested, dict) or frozenset(nested) != _GENETIC_FIELDS:
        raise ValueError("Genetic IR AAD schema mismatch")
    if canonical_json_bytes(nested) != nested_raw:
        raise ValueError("Genetic IR AAD is not canonical")
    if nested.get("schema") != GENETIC_AAD_SCHEMA:
        raise ValueError("unsupported Genetic IR AAD schema")
    if nested.get("genetic_ir_id") != program.semantic_id:
        raise ValueError("Genetic IR commitment mismatch")
    if nested.get("source_schema") != "CIELINGO_GENOMIC_GRAMMAR_V0_1":
        raise ValueError("Genetic IR source schema mismatch")
    encoded = nested.get("user_aad")
    if not isinstance(encoded, str):
        raise ValueError("nested user_aad is invalid")
    try:
        return b64d(encoded)
    except Exception as exc:
        raise ValueError("nested user_aad is invalid") from exc


def encrypt_with_genetic_ir(
    master_key: bytes,
    plaintext: bytes,
    genome: CipherGenome,
    surface: CipherSurface,
    program: GeneticIRNode,
    *,
    user_aad: bytes = b"",
    parent_receipt: str | None = None,
) -> DNCryptEnvelope:
    return encrypt(
        master_key,
        plaintext,
        genome,
        surface,
        user_aad=genetic_user_aad(program, user_aad),
        parent_receipt=parent_receipt,
    )


def encrypt_deterministic_with_genetic_ir_for_test(
    master_key: bytes,
    plaintext: bytes,
    genome: CipherGenome,
    surface: CipherSurface,
    program: GeneticIRNode,
    *,
    entropy: bytes,
    user_aad: bytes = b"",
    parent_receipt: str | None = None,
) -> DNCryptEnvelope:
    """Deterministic conformance helper only. Never use in production."""

    return encrypt_deterministic_for_test(
        master_key,
        plaintext,
        genome,
        surface,
        entropy=entropy,
        user_aad=genetic_user_aad(program, user_aad),
        parent_receipt=parent_receipt,
    )


def decrypt_with_genetic_ir(
    master_key: bytes,
    envelope: DNCryptEnvelope,
    genome: CipherGenome,
    surface: CipherSurface,
    program: GeneticIRNode,
) -> tuple[bytes, bytes]:
    """Verify IR commitment, then decrypt; returns (plaintext, original_user_aad)."""

    original_user_aad = verify_genetic_ir_binding(envelope, program)
    plaintext = decrypt(master_key, envelope, genome, surface)
    return plaintext, original_user_aad
