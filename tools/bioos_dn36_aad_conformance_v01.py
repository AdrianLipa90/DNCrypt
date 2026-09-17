from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

from dncrypt import (
    binary_envelope_id,
    decrypt,
    encrypt,
    initial_genome,
    initial_surface,
    pack_envelope,
    unpack_envelope,
)

SCHEMA = "DNCRYPT_BIOOS_DN36_AAD_CONFORMANCE_V0_1"
PNSTORE_PAYLOAD_MAX = 3936
MASTER = bytes(range(32))
GENOME_ENTROPY = bytes(range(64))
MESSAGE_ENTROPY = bytes(range(44))

BIOOS_SOURCE = {
    "repository": "AdrianLipa90/PNCore-BioOS",
    "branch": "feat/bioos-dn36-fundamental-code-v0.1",
    "evidence_head": "430dfc8080edc8c30d95a946663b0c1c2195fafb",
    "workflow_run_id": 35240603224,
    "artifact_digest": "sha256:13cf2a5829027161043a31f3ca74cd4f813a301ef6cfa3788f48581effb79842",
    "aux_receipt_sha256": "691eb7ccbb5fd1d74a5ec8e68f9f1581e00d4f2a2a715a845dc0d9aac7870884",
}


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _fixture() -> tuple[bytes, bytes]:
    paux = hashlib.shake_256(b"BIOOS/DN36/DNCRYPT-AUX/PAUX/V0.1").digest(288)
    core = {
        "profile": "PAUX_EXACT_FLOAT64_LE_36_V0_2",
        "dimension": 36,
        "dtype": "float64-le",
        "object_id": "pnv:state:dn36-dncrypt-conformance-v01",
        "integrity_hash": "sha256:conformance-placeholder-not-authority",
        "state_id": "state:dn36-dncrypt-conformance-v01",
        "parent_id": "state:dn36-dncrypt-conformance-parent",
        "relation": "CHECKPOINT",
        "generation": 1,
        "persistence_context": "PNSTORE_CONFORMANCE_ONLY",
        "pncap_receipt_id": "pncap:conformance-only",
    }
    core_raw = canonical_json_bytes(core)
    binding_input = (
        b"BIOOS/DN36/DNCRYPT-AUX/V0.1\x00"
        + len(paux).to_bytes(4, "big")
        + paux
        + len(core_raw).to_bytes(4, "big")
        + core_raw
    )
    aux = {
        "schema": "BIOOS_DN36_DNCRYPT_AUX_BINDING_V0_1",
        "profile": "DN36_AUXILIARY_NON_AUTHORITY_V0_1",
        "paux_exact_bytes": 288,
        "paux_sha256": "912937b90bbdf3cd5bdda3d36fd26faaeb5782d41e2e3d2fcdfb8651e0688c3e",
        "aad_core_sha256": "3afdbbd645d162d37218bd9b58a79f22ed6067a368ba00fcc8e5ad06e73157bb",
        "binding_input_sha256": "e66802801ae178c915a1c5e8efea460d265dcfed2878e4f1379af8bd5189d0b5",
        "state2304_sha256": "418229fad46106fb6b232f45ad73d8d9f9ee33ca149bd2bc8415eb5725056b62",
        "fold256_hex": "daf1d074792867b623533f419111b49f33102357cbe36147c6948ad85d5e60e1",
        "standard_anchor": "blake2b-256:c7047655b1f775eab5886b2f08585402ce0ee9b463e3d60756e9696ebe91694c",
        "security_claim": False,
        "identity_authority": False,
        "aead_authority": False,
        "canon_allowed": False,
    }
    if hashlib.sha256(paux).hexdigest() != aux["paux_sha256"]:
        raise RuntimeError("BioOS PAUX fixture drift")
    if hashlib.sha256(core_raw).hexdigest() != aux["aad_core_sha256"]:
        raise RuntimeError("BioOS AAD-core fixture drift")
    if hashlib.sha256(binding_input).hexdigest() != aux["binding_input_sha256"]:
        raise RuntimeError("BioOS DN36 binding-input fixture drift")

    user_aad = canonical_json_bytes(
        {
            "schema": "BIOOS_DNCRYPT_USER_AAD_WITH_DN36_AUX_V0_1",
            "core": core,
            "dn36_aux": aux,
        }
    )
    if len(user_aad) != 1234:
        raise RuntimeError(f"BioOS user_aad length drift: {len(user_aad)} != 1234")
    if hashlib.sha256(user_aad).hexdigest() != "8921d4e288a994c82c75c1f996d83f41cb5a1692bdb49400ae76101fc93d45e5":
        raise RuntimeError("BioOS user_aad byte identity drift")
    return paux, user_aad


def _extract_user_aad(envelope) -> tuple[bytes, bytes]:
    outer_aad = base64.b64decode(envelope.aad_b64.encode("ascii"), validate=True)
    meta = json.loads(outer_aad.decode("utf-8"))
    if not isinstance(meta, dict):
        raise RuntimeError("DNCrypt authenticated AAD metadata is not an object")
    encoded = meta.get("user_aad")
    if not isinstance(encoded, str):
        raise RuntimeError("DNCrypt authenticated AAD metadata lacks user_aad")
    embedded = base64.b64decode(encoded.encode("ascii"), validate=True)
    return outer_aad, embedded


def run() -> dict[str, object]:
    plaintext, expected_user_aad = _fixture()
    genome = initial_genome(GENOME_ENTROPY)
    surface = initial_surface(genome)
    envelope = encrypt(
        MASTER,
        plaintext,
        genome,
        surface,
        user_aad=expected_user_aad,
        parent_receipt="bioos:dn36:parent:conformance-v01",
        entropy=MESSAGE_ENTROPY,
    )
    if not envelope.verify_receipt():
        raise RuntimeError("DNCrypt provenance receipt failed before packing")

    outer_aad, embedded_user_aad = _extract_user_aad(envelope)
    if embedded_user_aad != expected_user_aad:
        raise RuntimeError("authenticated embedded BioOS user_aad mismatch before packing")

    packed = pack_envelope(envelope)
    if len(packed) > PNSTORE_PAYLOAD_MAX:
        raise RuntimeError(
            f"DNCrypt binary envelope exceeds PNStore payload: {len(packed)} > {PNSTORE_PAYLOAD_MAX}"
        )

    restored = unpack_envelope(packed)
    if restored != envelope or restored.to_bytes() != envelope.to_bytes():
        raise RuntimeError("binary envelope roundtrip changed canonical DNCrypt envelope")
    if not restored.verify_receipt():
        raise RuntimeError("DNCrypt provenance receipt failed after unpack")

    restored_outer_aad, restored_user_aad = _extract_user_aad(restored)
    if restored_outer_aad != outer_aad:
        raise RuntimeError("authenticated outer AAD changed after binary roundtrip")
    if restored_user_aad != expected_user_aad:
        raise RuntimeError("authenticated BioOS user_aad changed after binary roundtrip")

    deliberately_wrong_expected = expected_user_aad + b"\x00"
    if restored_user_aad == deliberately_wrong_expected:
        raise RuntimeError("negative expected-user-AAD equality control unexpectedly matched")

    recovered = decrypt(MASTER, restored, genome, surface)
    if recovered != plaintext:
        raise RuntimeError("DNCrypt decrypt did not recover exact PAUX plaintext")

    ciphertext = base64.b64decode(restored.ciphertext_b64.encode("ascii"), validate=True)
    receipt: dict[str, object] = {
        "schema": SCHEMA,
        "status": "PASS_DNCRYPT_BIOOS_DN36_AEAD_BINARY_CAPACITY",
        "bioos_source": BIOOS_SOURCE,
        "dncrypt_protocol": restored.protocol_id,
        "binary_codec": "dncrypt.binary-envelope/v0.1",
        "sizes": {
            "paux_plaintext_bytes": len(plaintext),
            "bioos_user_aad_bytes": len(expected_user_aad),
            "dncrypt_authenticated_outer_aad_bytes": len(restored_outer_aad),
            "ciphertext_bytes": len(ciphertext),
            "canonical_json_envelope_bytes": len(restored.to_bytes()),
            "packed_binary_envelope_bytes": len(packed),
            "pnstore_payload_max_bytes": PNSTORE_PAYLOAD_MAX,
            "pnstore_remaining_margin_bytes": PNSTORE_PAYLOAD_MAX - len(packed),
        },
        "identity": {
            "bioos_user_aad_sha256": hashlib.sha256(expected_user_aad).hexdigest(),
            "paux_sha256": hashlib.sha256(plaintext).hexdigest(),
            "binary_envelope_id": binary_envelope_id(packed),
        },
        "gates": {
            "prepack_receipt_valid": True,
            "embedded_user_aad_exact_before_pack": True,
            "binary_roundtrip_envelope_identity": True,
            "postunpack_receipt_valid": True,
            "embedded_user_aad_exact_after_unpack": True,
            "wrong_expected_user_aad_rejected_by_equality_control": True,
            "decrypt_plaintext_exact": True,
            "pnstore_capacity_fit": True,
        },
        "security_claim": False,
        "dn36_identity_authority": False,
        "dn36_aead_authority": False,
        "canon_allowed": False,
        "claim_boundary": (
            "Deterministic compatibility/conformance execution for BioOS DN36-augmented user_aad "
            "through DNCrypt v0.2 AEAD and binary-envelope v0.1, including current PNStore 3936-byte "
            "capacity. It is not cryptanalysis and does not promote DN36 to cryptographic authority."
        ),
    }
    raw = canonical_json_bytes(receipt)
    receipt["receipt_sha256"] = hashlib.sha256(raw).hexdigest()
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("evidence/BIOOS_DN36_AAD_CONFORMANCE_V0_1.json"),
    )
    args = parser.parse_args()
    receipt = run()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
