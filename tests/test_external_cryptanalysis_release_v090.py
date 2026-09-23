from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from dncrypt.cryptanalysis_release import (
    CryptanalysisChallengeManifest,
    build_external_submission,
    verify_external_submission,
)


def manifest() -> CryptanalysisChallengeManifest:
    return CryptanalysisChallengeManifest(
        target_repository="AdrianLipa90/DNCrypt",
        target_commit_sha="8651c3914e060cad5fd6ca1751f4420eb7a8360d",
        target_version="0.8.1a0",
        frozen_protocol_id="dncrypt.frozen-protocol/v0.2",
        seed_commitment="e91e6878f53971cd22d10db824d32012ebfadf5caa6f246a4ca8f3fbf01f304d",
        attack_tracks=(
            "AEAD_AUTHENTICATION_AND_TAMPER",
            "ROLLBACK_AND_EXTERNAL_WITNESS_REPLAY",
            "HYBRID_KEM_TRANSCRIPT_AND_PROVIDER_CONFUSION",
        ),
        required_artifacts=(
            "raw_results",
            "tool_source_or_commitment",
            "environment_manifest",
            "limitations",
            "signed_submission",
        ),
    )


def test_manifest_is_bound_to_exact_target_commit():
    m = manifest()
    assert len(m.challenge_id) == 64
    assert m.target_commit_sha == "8651c3914e060cad5fd6ca1751f4420eb7a8360d"


def test_external_submission_signature_and_artifact_commitments_round_trip():
    m = manifest()
    private = Ed25519PrivateKey.generate()
    tool = b"independent evaluator tool bytes"
    result = b'{"status":"completed","finding_count":0}'
    submission = build_external_submission(
        manifest=m,
        evaluator_id="independent-lab-A",
        evaluator_key_id="lab-A-ed25519-2026",
        tool_bytes=tool,
        result_bytes=result,
        summary={"status": "COMPLETED", "finding_count": 0},
        private_key=private,
    )
    assert verify_external_submission(
        submission,
        manifest=m,
        public_key=private.public_key(),
        expected_tool_bytes=tool,
        expected_result_bytes=result,
    )
    assert len(submission.submission_id) == 64


def test_submission_for_other_commit_is_rejected():
    m = manifest()
    private = Ed25519PrivateKey.generate()
    submission = build_external_submission(
        manifest=m,
        evaluator_id="lab",
        evaluator_key_id="key",
        tool_bytes=b"tool",
        result_bytes=b"result",
        summary={"status": "DONE"},
        private_key=private,
    )
    other = CryptanalysisChallengeManifest(
        target_repository=m.target_repository,
        target_commit_sha="0" * 40,
        target_version=m.target_version,
        frozen_protocol_id=m.frozen_protocol_id,
        seed_commitment=m.seed_commitment,
        attack_tracks=m.attack_tracks,
        required_artifacts=m.required_artifacts,
    )
    with pytest.raises(ValueError, match="challenge_id"):
        submission.verify(manifest=other, public_key=private.public_key())


def test_result_or_tool_substitution_is_detected():
    m = manifest()
    private = Ed25519PrivateKey.generate()
    submission = build_external_submission(
        manifest=m,
        evaluator_id="lab",
        evaluator_key_id="key",
        tool_bytes=b"tool-v1",
        result_bytes=b"result-v1",
        summary={"status": "DONE"},
        private_key=private,
    )
    with pytest.raises(ValueError, match="tool commitment"):
        verify_external_submission(
            submission,
            manifest=m,
            public_key=private.public_key(),
            expected_tool_bytes=b"tool-v2",
        )
    with pytest.raises(ValueError, match="result commitment"):
        verify_external_submission(
            submission,
            manifest=m,
            public_key=private.public_key(),
            expected_result_bytes=b"result-v2",
        )


def test_wrong_evaluator_key_is_rejected():
    m = manifest()
    private = Ed25519PrivateKey.generate()
    submission = build_external_submission(
        manifest=m,
        evaluator_id="lab",
        evaluator_key_id="key",
        tool_bytes=b"tool",
        result_bytes=b"result",
        summary={"status": "DONE"},
        private_key=private,
    )
    wrong = Ed25519PrivateKey.generate().public_key()
    with pytest.raises(ValueError, match="signature"):
        submission.verify(manifest=m, public_key=wrong)
