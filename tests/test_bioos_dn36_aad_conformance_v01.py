from __future__ import annotations

from tools.bioos_dn36_aad_conformance_v01 import (
    BIOOS_SOURCE,
    DNCRYPT_IMPLEMENTATION,
    PNSTORE_PAYLOAD_MAX,
    _fixture,
    run,
)


def test_bioos_dn36_fixture_is_exact_and_pinned():
    paux, user_aad = _fixture()
    assert len(paux) == 288
    assert len(user_aad) == 1234
    assert BIOOS_SOURCE["evidence_head"] == "430dfc8080edc8c30d95a946663b0c1c2195fafb"
    assert BIOOS_SOURCE["workflow_run_id"] == 35240603224
    assert BIOOS_SOURCE["aux_receipt_sha256"] == "691eb7ccbb5fd1d74a5ec8e68f9f1581e00d4f2a2a715a845dc0d9aac7870884"
    assert DNCRYPT_IMPLEMENTATION["base_head"] == "88439967b97d4d607ab2c7d30211f91e1fe87a72"


def test_actual_dncrypt_bioos_dn36_aad_conformance_passes_fail_closed():
    receipt = run()
    assert receipt["status"] == "PASS_DNCRYPT_BIOOS_DN36_AEAD_BINARY_CAPACITY"
    assert receipt["security_claim"] is False
    assert receipt["dn36_identity_authority"] is False
    assert receipt["dn36_aead_authority"] is False
    assert receipt["canon_allowed"] is False

    sizes = receipt["sizes"]
    assert sizes["paux_plaintext_bytes"] == 288
    assert sizes["bioos_user_aad_bytes"] == 1234
    assert sizes["packed_binary_envelope_bytes"] <= PNSTORE_PAYLOAD_MAX
    assert sizes["pnstore_remaining_margin_bytes"] == PNSTORE_PAYLOAD_MAX - sizes["packed_binary_envelope_bytes"]
    assert sizes["pnstore_remaining_margin_bytes"] > 0

    gates = receipt["gates"]
    assert gates == {
        "prepack_receipt_valid": True,
        "embedded_user_aad_exact_before_pack": True,
        "binary_roundtrip_envelope_identity": True,
        "postunpack_receipt_valid": True,
        "embedded_user_aad_exact_after_unpack": True,
        "decrypt_plaintext_exact": True,
        "pnstore_capacity_fit": True,
        "actual_aead_adversarial_fail_closed": True,
    }

    cases = receipt["adversarial_cases"]
    assert receipt["adversarial_case_count"] == 4
    assert {case["name"] for case in cases} == {
        "authenticated_user_aad_mutation_retagged",
        "ciphertext_mutation_retagged",
        "wrong_master_key",
        "packed_binary_mutation",
    }
    assert all(case["status"] == "PASS_FAIL_CLOSED" for case in cases)
