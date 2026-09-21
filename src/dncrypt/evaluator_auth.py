from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .bus import EvaluationRequest
from .fitness import FitnessRecord, PopulationFitnessReport
from .genome import CipherGenome
from .util import b64d, b64e, blake2b256, canonical_json_bytes

SIGNED_EVALUATION_SCHEMA = "dncrypt.signed-external-evaluation/v0.1"


def _report_payload(report: PopulationFitnessReport) -> dict[str, object]:
    return {
        "schema": report.schema,
        "request_id": report.request_id,
        "records": [asdict(record) for record in report.records],
    }


@dataclass(frozen=True, slots=True)
class SignedEvaluationEnvelope:
    schema: str
    evaluator_id: str
    report: PopulationFitnessReport
    signature_b64: str

    def __post_init__(self) -> None:
        if self.schema != SIGNED_EVALUATION_SCHEMA:
            raise ValueError("unsupported signed evaluation schema")
        if not self.evaluator_id or len(self.evaluator_id) > 256:
            raise ValueError("invalid evaluator_id")
        signature = b64d(self.signature_b64)
        if len(signature) != 64:
            raise ValueError("Ed25519 signature must be 64 bytes")

    @property
    def signed_payload(self) -> bytes:
        return canonical_json_bytes({
            "schema": self.schema,
            "evaluator_id": self.evaluator_id,
            "report": _report_payload(self.report),
        })

    @property
    def digest(self) -> str:
        return blake2b256(self.signed_payload + b64d(self.signature_b64))

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "evaluator_id": self.evaluator_id,
            "report": _report_payload(self.report),
            "signature_b64": self.signature_b64,
        }

    @classmethod
    def from_dict(cls, value: object) -> "SignedEvaluationEnvelope":
        if not isinstance(value, dict):
            raise ValueError("signed evaluation root must be an object")
        if set(value) != {"schema", "evaluator_id", "report", "signature_b64"}:
            raise ValueError("signed evaluation fields mismatch")
        raw_report = value["report"]
        if not isinstance(raw_report, dict):
            raise ValueError("signed evaluation report must be an object")
        if set(raw_report) != {"schema", "request_id", "records"}:
            raise ValueError("signed evaluation report fields mismatch")
        raw_records = raw_report["records"]
        if not isinstance(raw_records, list):
            raise ValueError("signed evaluation records must be a list")
        report = PopulationFitnessReport(
            str(raw_report["schema"]),
            str(raw_report["request_id"]),
            tuple(FitnessRecord(**item) for item in raw_records),
        )
        return cls(
            schema=str(value["schema"]),
            evaluator_id=str(value["evaluator_id"]),
            report=report,
            signature_b64=str(value["signature_b64"]),
        )


def sign_evaluation_report(
    report: PopulationFitnessReport,
    evaluator_id: str,
    private_key: Ed25519PrivateKey,
) -> SignedEvaluationEnvelope:
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be Ed25519PrivateKey")
    unsigned = SignedEvaluationEnvelope.__new__(SignedEvaluationEnvelope)
    object.__setattr__(unsigned, "schema", SIGNED_EVALUATION_SCHEMA)
    object.__setattr__(unsigned, "evaluator_id", evaluator_id)
    object.__setattr__(unsigned, "report", report)
    object.__setattr__(unsigned, "signature_b64", b64e(b"\x00" * 64))
    payload = unsigned.signed_payload
    return SignedEvaluationEnvelope(
        schema=SIGNED_EVALUATION_SCHEMA,
        evaluator_id=evaluator_id,
        report=report,
        signature_b64=b64e(private_key.sign(payload)),
    )


def verify_signed_evaluation(
    envelope: SignedEvaluationEnvelope,
    trusted_evaluators: Mapping[str, bytes],
) -> PopulationFitnessReport:
    raw_key = trusted_evaluators.get(envelope.evaluator_id)
    if raw_key is None:
        raise ValueError("untrusted external evaluator")
    raw_key = bytes(raw_key)
    if len(raw_key) != 32:
        raise ValueError("trusted Ed25519 public key must be 32 bytes")
    try:
        Ed25519PublicKey.from_public_bytes(raw_key).verify(
            b64d(envelope.signature_b64),
            envelope.signed_payload,
        )
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("external evaluation signature verification failed") from exc
    return envelope.report


def load_signed_external_evaluation(
    path: str | Path,
    request: EvaluationRequest,
    population: tuple[CipherGenome, ...],
    trusted_evaluators: Mapping[str, bytes],
) -> PopulationFitnessReport:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    envelope = SignedEvaluationEnvelope.from_dict(value)
    report = verify_signed_evaluation(envelope, trusted_evaluators)
    if report.request_id != request.request_id:
        raise ValueError("external evaluation request_id mismatch")
    report.validate_population(population)
    return report
