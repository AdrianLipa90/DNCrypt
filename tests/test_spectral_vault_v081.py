from __future__ import annotations

from dataclasses import replace
import math

import pytest

from dncrypt.genome import initial_genome
from dncrypt.secret_backend import InMemorySecretBackend
from dncrypt.spectral_vault import (
    SpectralEvidenceRecord,
    SpectralVaultEntry,
    open_spectral_evidence,
    seal_spectral_evidence,
    spectral_phase36,
)
from dncrypt.surface import initial_surface


def sample_record(parent: str | None = None) -> SpectralEvidenceRecord:
    axis = tuple(400.0 + 0.25 * i for i in range(144))
    intensity = tuple(
        1.0
        + 0.15 * math.sin(i / 7.0)
        + 0.7 * math.exp(-((i - 50.0) / 8.0) ** 2)
        - 0.35 * math.exp(-((i - 102.0) / 5.0) ** 2)
        for i in range(144)
    )
    return SpectralEvidenceRecord(
        sample_id="sample-001",
        instrument_id="OES-fixture-01",
        axis_unit="nm",
        axis=axis,
        intensity=intensity,
        calibration_commitment="a" * 64,
        acquisition_metadata={"integration_ms": 25.0, "replicate": 1},
        parent_evidence_id=parent,
    )


def test_spectral_record_round_trip_and_phase_shape():
    record = sample_record()
    restored = SpectralEvidenceRecord.from_bytes(record.to_bytes())
    assert restored == record
    phase = spectral_phase36(record.axis, record.intensity)
    assert len(phase) == 36
    assert all(math.isfinite(x) and 0.0 <= x < 2.0 * math.pi for x in phase)
    assert len(record.record_id) == 64
    assert len(record.spectrum_commitment) == 64


def test_spectral_phase_is_invariant_to_positive_affine_intensity_rescaling():
    record = sample_record()
    transformed = tuple(10.0 + 3.0 * y for y in record.intensity)
    assert spectral_phase36(record.axis, transformed) == pytest.approx(record.phase36)


def test_vault_seal_open_uses_opaque_secret_backend_and_authenticated_header():
    backend = InMemorySecretBackend("spectral-test")
    handle = backend.generate_master_key_handle()
    genome = initial_genome(b"g" * 64)
    surface = initial_surface(genome)
    record = sample_record()

    entry = seal_spectral_evidence(
        backend=backend,
        handle=handle,
        record=record,
        genome=genome,
        surface=surface,
    )
    restored = open_spectral_evidence(
        backend=backend,
        handle=handle,
        entry=entry,
        genome=genome,
        surface=surface,
    )
    assert restored == record
    assert entry.header.record_id == record.record_id
    assert entry.header.to_dict()["authority"]["cryptographic_entropy"] is False
    assert entry.header.to_dict()["authority"]["security_admission"] is False


def test_header_tamper_is_rejected_before_accepting_record():
    backend = InMemorySecretBackend("spectral-test")
    handle = backend.generate_master_key_handle()
    genome = initial_genome(b"h" * 64)
    surface = initial_surface(genome)
    entry = seal_spectral_evidence(
        backend=backend,
        handle=handle,
        record=sample_record(),
        genome=genome,
        surface=surface,
    )
    phases = list(entry.header.phase36)
    phases[0] = (phases[0] + 0.25) % (2.0 * math.pi)
    forged_header = replace(entry.header, phase36=tuple(phases))
    forged_entry = SpectralVaultEntry(header=forged_header, envelope=entry.envelope)
    with pytest.raises(ValueError, match="authenticated envelope metadata"):
        open_spectral_evidence(
            backend=backend,
            handle=handle,
            entry=forged_entry,
            genome=genome,
            surface=surface,
        )


def test_parent_evidence_lineage_changes_record_identity():
    a = sample_record(None)
    b = sample_record("b" * 64)
    assert a.spectrum_commitment == b.spectrum_commitment
    assert a.record_id != b.record_id


def test_invalid_spectrum_fails_closed():
    base = sample_record()
    with pytest.raises(ValueError, match="strictly increasing"):
        replace(base, axis=tuple(reversed(base.axis)))
    bad = list(base.intensity)
    bad[5] = float("nan")
    with pytest.raises(ValueError, match="finite"):
        replace(base, intensity=tuple(bad))
