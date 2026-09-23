"""Spectral Evidence Vault vertical for DNCrypt v0.8.1.

Raw spectra remain ordinary AEAD plaintext payloads encrypted behind the opaque
secret-backend boundary. The 36D spectral fingerprint is authenticated metadata
for lineage/diagnostics only; it is never key, salt, nonce or security-admission
entropy.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import math
from typing import Any, Mapping

from .crypto import DNCryptEnvelope
from .genome import CipherGenome
from .secret_backend import (
    SecretBackendPort,
    SecretHandle,
    decrypt_with_secret_handle,
    encrypt_with_secret_handle,
)
from .surface import CipherSurface
from .util import b64d, blake2b256, canonical_json_bytes

SPECTRAL_RECORD_SCHEMA = "dncrypt.spectral-evidence-record/v0.8.1-candidate"
SPECTRAL_HEADER_SCHEMA = "dncrypt.spectral-evidence-header/v0.8.1-candidate"
SPECTRAL_VAULT_SCHEMA = "dncrypt.spectral-vault-entry/v0.8.1-candidate"
DIM = 36
TAU = 2.0 * math.pi
MAX_POINTS = 262_144


def _validate_digest(value: str | None, name: str, *, optional: bool = False) -> None:
    if value is None and optional:
        return
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(name + " must be a 64-character hex digest")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(name + " must be hexadecimal") from exc


def spectral_phase36(
    axis: tuple[float, ...],
    intensity: tuple[float, ...],
) -> tuple[float, ...]:
    """Deterministic relational 36D diagnostic projection of one spectrum."""

    n = len(axis)
    if n != len(intensity) or n < DIM:
        raise ValueError("spectral phase projection requires at least 36 paired points")
    if not all(math.isfinite(x) for x in axis + intensity):
        raise ValueError("spectrum must contain only finite values")
    if any(axis[i + 1] <= axis[i] for i in range(n - 1)):
        raise ValueError("spectral axis must be strictly increasing")

    mean_y = sum(intensity) / n
    variance = sum((y - mean_y) ** 2 for y in intensity) / n
    scale = math.sqrt(variance)
    if scale <= 1e-15:
        scale = 1.0
    norm = tuple((y - mean_y) / scale for y in intensity)

    span = axis[-1] - axis[0]
    xnorm = tuple((x - axis[0]) / span for x in axis)

    phases: list[float] = []
    for band in range(DIM):
        start = (band * n) // DIM
        stop = ((band + 1) * n) // DIM
        ys = norm[start:stop]
        local_mean = sum(ys) / len(ys)

        slopes: list[float] = []
        for i in range(start, max(start, stop - 1)):
            dx = xnorm[i + 1] - xnorm[i]
            if dx <= 0.0:
                raise ValueError("normalized spectral axis is not strictly increasing")
            slopes.append((norm[i + 1] - norm[i]) / dx)
        local_slope = 0.0 if not slopes else sum(slopes) / len(slopes)
        angle = math.atan2(local_slope, local_mean) % TAU
        phases.append(float(angle))

    result = tuple(phases)
    if len(result) != DIM or not all(math.isfinite(x) for x in result):
        raise ValueError("spectral phase projection must be finite 36D")
    return result


@dataclass(frozen=True, slots=True)
class SpectralEvidenceRecord:
    sample_id: str
    instrument_id: str
    axis_unit: str
    axis: tuple[float, ...]
    intensity: tuple[float, ...]
    calibration_commitment: str
    acquisition_metadata: Mapping[str, Any]
    parent_evidence_id: str | None = None
    schema: str = SPECTRAL_RECORD_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SPECTRAL_RECORD_SCHEMA:
            raise ValueError("unsupported spectral evidence schema")
        if not self.sample_id.strip() or not self.instrument_id.strip() or not self.axis_unit.strip():
            raise ValueError("sample_id/instrument_id/axis_unit must not be empty")
        _validate_digest(self.calibration_commitment, "calibration_commitment")
        _validate_digest(self.parent_evidence_id, "parent_evidence_id", optional=True)
        if len(self.axis) != len(self.intensity):
            raise ValueError("spectral axis/intensity lengths differ")
        if len(self.axis) < DIM or len(self.axis) > MAX_POINTS:
            raise ValueError("spectral point count outside admitted bounds")
        if not all(math.isfinite(x) for x in self.axis + self.intensity):
            raise ValueError("spectrum must contain only finite values")
        if any(self.axis[i + 1] <= self.axis[i] for i in range(len(self.axis) - 1)):
            raise ValueError("spectral axis must be strictly increasing")
        canonical_json_bytes(dict(self.acquisition_metadata))

    @property
    def spectrum_commitment(self) -> str:
        return blake2b256(
            canonical_json_bytes(
                {
                    "axis_unit": self.axis_unit,
                    "axis": list(self.axis),
                    "intensity": list(self.intensity),
                }
            )
        )

    @property
    def phase36(self) -> tuple[float, ...]:
        return spectral_phase36(self.axis, self.intensity)

    @property
    def acquisition_metadata_commitment(self) -> str:
        return blake2b256(canonical_json_bytes(dict(self.acquisition_metadata)))

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "sample_id": self.sample_id,
            "instrument_id": self.instrument_id,
            "axis_unit": self.axis_unit,
            "axis": list(self.axis),
            "intensity": list(self.intensity),
            "calibration_commitment": self.calibration_commitment,
            "acquisition_metadata": dict(self.acquisition_metadata),
            "parent_evidence_id": self.parent_evidence_id,
            "authority": {
                "spectral_phase36_diagnostic_only": True,
                "security_admission": False,
                "cryptographic_entropy": False,
            },
        }

    @property
    def record_id(self) -> str:
        return blake2b256(canonical_json_bytes(self.to_dict()))

    def to_bytes(self) -> bytes:
        return canonical_json_bytes({**self.to_dict(), "record_id": self.record_id})

    @classmethod
    def from_bytes(cls, raw: bytes) -> "SpectralEvidenceRecord":
        try:
            value = json.loads(bytes(raw).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("spectral record is not valid UTF-8 JSON") from exc
        if not isinstance(value, dict):
            raise ValueError("spectral record root must be an object")
        expected = {
            "schema",
            "sample_id",
            "instrument_id",
            "axis_unit",
            "axis",
            "intensity",
            "calibration_commitment",
            "acquisition_metadata",
            "parent_evidence_id",
            "authority",
            "record_id",
        }
        if set(value) != expected:
            raise ValueError("spectral record schema mismatch")
        if canonical_json_bytes(value) != bytes(raw):
            raise ValueError("spectral record encoding is not canonical")
        authority = value.get("authority")
        if authority != {
            "spectral_phase36_diagnostic_only": True,
            "security_admission": False,
            "cryptographic_entropy": False,
        }:
            raise ValueError("spectral record authority block mismatch")
        meta = value.get("acquisition_metadata")
        if not isinstance(meta, Mapping):
            raise ValueError("acquisition_metadata must be an object")
        record = cls(
            sample_id=str(value["sample_id"]),
            instrument_id=str(value["instrument_id"]),
            axis_unit=str(value["axis_unit"]),
            axis=tuple(float(x) for x in value["axis"]),
            intensity=tuple(float(x) for x in value["intensity"]),
            calibration_commitment=str(value["calibration_commitment"]),
            acquisition_metadata=dict(meta),
            parent_evidence_id=value["parent_evidence_id"],
            schema=str(value["schema"]),
        )
        if value.get("record_id") != record.record_id:
            raise ValueError("spectral record commitment mismatch")
        return record


@dataclass(frozen=True, slots=True)
class SpectralEvidenceHeader:
    sample_id: str
    instrument_id: str
    axis_unit: str
    point_count: int
    calibration_commitment: str
    spectrum_commitment: str
    phase36: tuple[float, ...]
    acquisition_metadata_commitment: str
    record_id: str
    parent_evidence_id: str | None
    schema: str = SPECTRAL_HEADER_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SPECTRAL_HEADER_SCHEMA:
            raise ValueError("unsupported spectral header schema")
        if self.point_count < DIM or self.point_count > MAX_POINTS:
            raise ValueError("spectral header point_count outside admitted bounds")
        for name, value in (
            ("calibration_commitment", self.calibration_commitment),
            ("spectrum_commitment", self.spectrum_commitment),
            ("acquisition_metadata_commitment", self.acquisition_metadata_commitment),
            ("record_id", self.record_id),
        ):
            _validate_digest(value, name)
        _validate_digest(self.parent_evidence_id, "parent_evidence_id", optional=True)
        if len(self.phase36) != DIM or not all(math.isfinite(x) for x in self.phase36):
            raise ValueError("spectral header phase36 must be finite 36D")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "sample_id": self.sample_id,
            "instrument_id": self.instrument_id,
            "axis_unit": self.axis_unit,
            "point_count": self.point_count,
            "calibration_commitment": self.calibration_commitment,
            "spectrum_commitment": self.spectrum_commitment,
            "phase36": list(self.phase36),
            "acquisition_metadata_commitment": self.acquisition_metadata_commitment,
            "record_id": self.record_id,
            "parent_evidence_id": self.parent_evidence_id,
            "authority": {
                "authenticated_metadata": True,
                "diagnostic_only": True,
                "security_admission": False,
                "cryptographic_entropy": False,
            },
        }

    @property
    def header_id(self) -> str:
        return blake2b256(canonical_json_bytes(self.to_dict()))


def spectral_header(record: SpectralEvidenceRecord) -> SpectralEvidenceHeader:
    return SpectralEvidenceHeader(
        sample_id=record.sample_id,
        instrument_id=record.instrument_id,
        axis_unit=record.axis_unit,
        point_count=len(record.axis),
        calibration_commitment=record.calibration_commitment,
        spectrum_commitment=record.spectrum_commitment,
        phase36=record.phase36,
        acquisition_metadata_commitment=record.acquisition_metadata_commitment,
        record_id=record.record_id,
        parent_evidence_id=record.parent_evidence_id,
    )


@dataclass(frozen=True, slots=True)
class SpectralVaultEntry:
    header: SpectralEvidenceHeader
    envelope: DNCryptEnvelope
    schema: str = SPECTRAL_VAULT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SPECTRAL_VAULT_SCHEMA:
            raise ValueError("unsupported spectral vault entry schema")
        if not self.envelope.verify_receipt():
            raise ValueError("spectral vault envelope receipt mismatch")

    @property
    def entry_id(self) -> str:
        return blake2b256(
            canonical_json_bytes(
                {
                    "schema": self.schema,
                    "header_id": self.header.header_id,
                    "envelope_receipt": self.envelope.receipt_blake2b,
                }
            )
        )


def seal_spectral_evidence(
    *,
    backend: SecretBackendPort,
    handle: SecretHandle,
    record: SpectralEvidenceRecord,
    genome: CipherGenome,
    surface: CipherSurface,
    parent_receipt: str | None = None,
) -> SpectralVaultEntry:
    header = spectral_header(record)
    envelope = encrypt_with_secret_handle(
        backend,
        handle,
        record.to_bytes(),
        genome,
        surface,
        user_aad=canonical_json_bytes(header.to_dict()),
        parent_receipt=parent_receipt,
    )
    return SpectralVaultEntry(header=header, envelope=envelope)


def _authenticated_user_aad(envelope: DNCryptEnvelope) -> bytes:
    try:
        meta = json.loads(b64d(envelope.aad_b64).decode("utf-8"))
        encoded = meta["user_aad"]
        if not isinstance(encoded, str):
            raise TypeError
        return b64d(encoded)
    except Exception as exc:
        raise ValueError("spectral vault authenticated metadata is malformed") from exc


def open_spectral_evidence(
    *,
    backend: SecretBackendPort,
    handle: SecretHandle,
    entry: SpectralVaultEntry,
    genome: CipherGenome,
    surface: CipherSurface,
) -> SpectralEvidenceRecord:
    expected_aad = canonical_json_bytes(entry.header.to_dict())
    if _authenticated_user_aad(entry.envelope) != expected_aad:
        raise ValueError("spectral header is not the authenticated envelope metadata")
    plaintext = decrypt_with_secret_handle(
        backend,
        handle,
        entry.envelope,
        genome,
        surface,
    )
    record = SpectralEvidenceRecord.from_bytes(plaintext)
    if spectral_header(record) != entry.header:
        raise ValueError("decrypted spectral record does not match authenticated header")
    return record


__all__ = [
    "DIM",
    "MAX_POINTS",
    "SPECTRAL_HEADER_SCHEMA",
    "SPECTRAL_RECORD_SCHEMA",
    "SPECTRAL_VAULT_SCHEMA",
    "SpectralEvidenceHeader",
    "SpectralEvidenceRecord",
    "SpectralVaultEntry",
    "open_spectral_evidence",
    "seal_spectral_evidence",
    "spectral_header",
    "spectral_phase36",
]
