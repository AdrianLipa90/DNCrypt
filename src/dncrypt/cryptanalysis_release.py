"""External cryptanalysis release protocol for DNCrypt v0.9.

This module binds an independent evaluation to one exact repository commit and
challenge manifest. It does not turn an internal benchmark into independent
cryptanalysis; independence comes only from an external evaluator and their
separately controlled tooling/environment.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .util import blake2b256, canonical_json_bytes

CHALLENGE_MANIFEST_SCHEMA = "dncrypt.external-cryptanalysis-manifest/v1"
EXTERNAL_SUBMISSION_SCHEMA = "dncrypt.external-cryptanalysis-submission/v1"


def _validate_hex(value: str, n: int, name: str) -> None:
    if not isinstance(value, str) or len(value) != n:
        raise ValueError(f"{name} must be {n} hexadecimal characters")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{name} must be hexadecimal") from exc


@dataclass(frozen=True, slots=True)
class CryptanalysisChallengeManifest:
    target_repository: str
    target_commit_sha: str
    target_version: str
    frozen_protocol_id: str
    seed_commitment: str
    attack_tracks: tuple[str, ...]
    required_artifacts: tuple[str, ...]
    evidence_class: str = "EXTERNAL_EVALUATION_REQUIRED"
    claim_scope: str = "SYSTEM_SECURITY_EVALUATION_NO_NOVEL_CIPHER_CLAIM"
    schema: str = CHALLENGE_MANIFEST_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != CHALLENGE_MANIFEST_SCHEMA:
            raise ValueError("unsupported challenge manifest schema")
        if self.target_repository != "AdrianLipa90/DNCrypt":
            raise ValueError("challenge target repository mismatch")
        _validate_hex(self.target_commit_sha, 40, "target_commit_sha")
        _validate_hex(self.seed_commitment, 64, "seed_commitment")
        if not self.target_version.strip() or not self.frozen_protocol_id.strip():
            raise ValueError("target_version/frozen_protocol_id must not be empty")
        if not self.attack_tracks or len(set(self.attack_tracks)) != len(self.attack_tracks):
            raise ValueError("attack_tracks must be non-empty and unique")
        if not self.required_artifacts or len(set(self.required_artifacts)) != len(self.required_artifacts):
            raise ValueError("required_artifacts must be non-empty and unique")
        if any(not item.strip() for item in self.attack_tracks + self.required_artifacts):
            raise ValueError("challenge track/artifact names must not be empty")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "target_repository": self.target_repository,
            "target_commit_sha": self.target_commit_sha,
            "target_version": self.target_version,
            "frozen_protocol_id": self.frozen_protocol_id,
            "seed_commitment": self.seed_commitment,
            "attack_tracks": list(self.attack_tracks),
            "required_artifacts": list(self.required_artifacts),
            "evidence_class": self.evidence_class,
            "claim_scope": self.claim_scope,
        }

    @property
    def challenge_id(self) -> str:
        return blake2b256(canonical_json_bytes(self.to_dict()))


@dataclass(frozen=True, slots=True)
class ExternalCryptanalysisSubmission:
    challenge_id: str
    target_commit_sha: str
    evaluator_id: str
    evaluator_key_id: str
    tool_commitment: str
    result_commitment: str
    summary: Mapping[str, Any]
    signature_hex: str
    schema: str = EXTERNAL_SUBMISSION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != EXTERNAL_SUBMISSION_SCHEMA:
            raise ValueError("unsupported external submission schema")
        _validate_hex(self.challenge_id, 64, "challenge_id")
        _validate_hex(self.target_commit_sha, 40, "target_commit_sha")
        _validate_hex(self.tool_commitment, 64, "tool_commitment")
        _validate_hex(self.result_commitment, 64, "result_commitment")
        if not self.evaluator_id.strip() or not self.evaluator_key_id.strip():
            raise ValueError("evaluator identity fields must not be empty")
        canonical_json_bytes(dict(self.summary))
        try:
            signature = bytes.fromhex(self.signature_hex)
        except ValueError as exc:
            raise ValueError("signature_hex must be hexadecimal") from exc
        if len(signature) != 64:
            raise ValueError("Ed25519 signature must contain 64 bytes")

    def signing_payload(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "challenge_id": self.challenge_id,
            "target_commit_sha": self.target_commit_sha,
            "evaluator_id": self.evaluator_id,
            "evaluator_key_id": self.evaluator_key_id,
            "tool_commitment": self.tool_commitment,
            "result_commitment": self.result_commitment,
            "summary": dict(self.summary),
        }

    @property
    def submission_id(self) -> str:
        return blake2b256(
            canonical_json_bytes(
                {**self.signing_payload(), "signature_hex": self.signature_hex}
            )
        )

    def verify(
        self,
        *,
        manifest: CryptanalysisChallengeManifest,
        public_key: Ed25519PublicKey,
    ) -> bool:
        if self.challenge_id != manifest.challenge_id:
            raise ValueError("submission challenge_id mismatch")
        if self.target_commit_sha != manifest.target_commit_sha:
            raise ValueError("submission target commit mismatch")
        try:
            public_key.verify(
                bytes.fromhex(self.signature_hex),
                canonical_json_bytes(self.signing_payload()),
            )
        except Exception as exc:
            raise ValueError("external cryptanalysis signature verification failed") from exc
        return True


def build_external_submission(
    *,
    manifest: CryptanalysisChallengeManifest,
    evaluator_id: str,
    evaluator_key_id: str,
    tool_bytes: bytes,
    result_bytes: bytes,
    summary: Mapping[str, Any],
    private_key: Ed25519PrivateKey,
) -> ExternalCryptanalysisSubmission:
    canonical_json_bytes(dict(summary))
    payload = {
        "schema": EXTERNAL_SUBMISSION_SCHEMA,
        "challenge_id": manifest.challenge_id,
        "target_commit_sha": manifest.target_commit_sha,
        "evaluator_id": evaluator_id,
        "evaluator_key_id": evaluator_key_id,
        "tool_commitment": blake2b256(bytes(tool_bytes)),
        "result_commitment": blake2b256(bytes(result_bytes)),
        "summary": dict(summary),
    }
    signature = private_key.sign(canonical_json_bytes(payload)).hex()
    return ExternalCryptanalysisSubmission(
        challenge_id=manifest.challenge_id,
        target_commit_sha=manifest.target_commit_sha,
        evaluator_id=evaluator_id,
        evaluator_key_id=evaluator_key_id,
        tool_commitment=payload["tool_commitment"],
        result_commitment=payload["result_commitment"],
        summary=dict(summary),
        signature_hex=signature,
    )


def verify_external_submission(
    submission: ExternalCryptanalysisSubmission,
    *,
    manifest: CryptanalysisChallengeManifest,
    public_key: Ed25519PublicKey,
    expected_tool_bytes: bytes | None = None,
    expected_result_bytes: bytes | None = None,
) -> bool:
    submission.verify(manifest=manifest, public_key=public_key)
    if expected_tool_bytes is not None:
        if submission.tool_commitment != blake2b256(bytes(expected_tool_bytes)):
            raise ValueError("external cryptanalysis tool commitment mismatch")
    if expected_result_bytes is not None:
        if submission.result_commitment != blake2b256(bytes(expected_result_bytes)):
            raise ValueError("external cryptanalysis result commitment mismatch")
    return True


__all__ = [
    "CHALLENGE_MANIFEST_SCHEMA",
    "EXTERNAL_SUBMISSION_SCHEMA",
    "CryptanalysisChallengeManifest",
    "ExternalCryptanalysisSubmission",
    "build_external_submission",
    "verify_external_submission",
]
