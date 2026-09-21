from __future__ import annotations

import math

import pytest

from dncrypt.twist_geometry_v01 import (
    DIM,
    TwistGeometryError,
    cyclic_mapping,
    cyclic_twist_scan,
    most_relationally_novel_cyclic_twist,
    relative_phase_field,
    twist_signature,
)


def nonuniform_slice():
    return tuple((0.031 * i * i + 0.17 * i + 0.004 * (i % 5)) % (2.0 * math.pi) for i in range(DIM))


def test_pure_common_rotation_has_zero_relational_novelty():
    a = nonuniform_slice()
    b = tuple(value + 0.731 for value in a)
    sig = twist_signature(a, b)
    assert sig.coherence == pytest.approx(1.0, abs=1e-12)
    assert sig.novelty == pytest.approx(0.0, abs=1e-12)
    assert sig.residual_rms_rad == pytest.approx(0.0, abs=1e-12)
    assert sig.common_rotation_only is True


def test_common_global_phase_shift_cancels_from_twist_signature():
    a = nonuniform_slice()
    b = tuple((value + 0.29 + 0.011 * (i % 3)) for i, value in enumerate(a))
    mapping = cyclic_mapping(7)
    first = twist_signature(a, b, mapping)
    alpha = 1.2345
    second = twist_signature(
        tuple(value + alpha for value in a),
        tuple(value + alpha for value in b),
        mapping,
    )
    assert first.coherence == pytest.approx(second.coherence, abs=1e-12)
    assert first.novelty == pytest.approx(second.novelty, abs=1e-12)
    assert first.residual_rms_rad == pytest.approx(second.residual_rms_rad, abs=1e-12)
    assert first.harmonic_magnitudes == pytest.approx(second.harmonic_magnitudes, abs=1e-12)
    assert first.diagnostic_fingerprint == second.diagnostic_fingerprint


def test_twisting_same_nonuniform_slice_exposes_relational_structure():
    a = nonuniform_slice()
    identity = twist_signature(a, a)
    twisted = twist_signature(a, a, cyclic_mapping(7))
    assert identity.common_rotation_only is True
    assert identity.novelty == pytest.approx(0.0, abs=1e-12)
    assert twisted.common_rotation_only is False
    assert twisted.novelty > 0.05
    assert twisted.residual_rms_rad > 0.1


def test_scan_identity_is_zero_and_nontrivial_shift_can_be_selected():
    a = nonuniform_slice()
    scan = cyclic_twist_scan(a, a)
    assert len(scan) == DIM
    assert scan[0].novelty == pytest.approx(0.0, abs=1e-12)
    shift, sig = most_relationally_novel_cyclic_twist(a, a)
    assert 1 <= shift < DIM
    assert sig.novelty > 0.0


def test_mapping_and_slice_domains_fail_closed():
    a = nonuniform_slice()
    with pytest.raises(TwistGeometryError):
        relative_phase_field(a[:-1], a)
    bad = list(range(DIM))
    bad[-1] = bad[-2]
    with pytest.raises(TwistGeometryError):
        twist_signature(a, a, bad)
