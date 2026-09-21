from __future__ import annotations

import math

import pytest

from dncrypt.twist_geometry_v01 import DIM, cyclic_mapping
from dncrypt.twist_geometry_v02 import (
    compose_permutations,
    inverse_permutation,
    permutation_cycles,
    relational_twist_class,
    relative_permutation,
)


def _slice():
    return tuple((0.037 * i * i + 0.19 * i + 0.013 * (i % 7)) % (2.0 * math.pi) for i in range(DIM))


def _relabel_slice(values, p):
    out = [0.0] * DIM
    for old, new in enumerate(p):
        out[new] = values[old]
    return tuple(out)


def _conjugate(route, p):
    pinv = inverse_permutation(p)
    return compose_permutations(p, compose_permutations(route, pinv))


def test_equal_routes_collapse_to_identity_class():
    route = tuple(reversed(range(DIM)))
    phase = _slice()
    cls = relational_twist_class(phase, phase, route, route)
    assert cls.relative_mapping == tuple(range(DIM))
    assert cls.cycle_lengths == (1,) * DIM
    assert cls.phase_novelty == pytest.approx(0.0, abs=1e-12)
    assert all(x == pytest.approx(0.0, abs=1e-12) for x in cls.cycle_holonomies_rad)


def test_relative_permutation_is_route_b_after_inverse_route_a():
    a = cyclic_mapping(5)
    b = cyclic_mapping(11)
    rel = relative_permutation(a, b)
    assert rel == cyclic_mapping(6)
    assert tuple(sorted(len(c) for c in permutation_cycles(rel))) == (6, 6, 6, 6, 6, 6)


def test_class_fingerprint_is_invariant_under_simultaneous_relabeling():
    phase_a = _slice()
    phase_b = tuple((x + 0.21 + 0.009 * (i % 5)) % (2.0 * math.pi) for i, x in enumerate(phase_a))
    route_a = cyclic_mapping(5)
    route_b = cyclic_mapping(11)
    original = relational_twist_class(phase_a, phase_b, route_a, route_b)

    p = tuple((7 * i + 3) % DIM for i in range(DIM))
    assert len(set(p)) == DIM
    relabeled = relational_twist_class(
        _relabel_slice(phase_a, p),
        _relabel_slice(phase_b, p),
        _conjugate(route_a, p),
        _conjugate(route_b, p),
    )

    assert original.class_fingerprint == relabeled.class_fingerprint
    assert original.canonical_cycle_signature == relabeled.canonical_cycle_signature
    assert original.phase_novelty == pytest.approx(relabeled.phase_novelty, abs=1e-12)


def test_cycle_structure_changes_when_relative_route_changes():
    phase = _slice()
    identity = relational_twist_class(phase, phase, tuple(range(DIM)), tuple(range(DIM)))
    shifted = relational_twist_class(phase, phase, tuple(range(DIM)), cyclic_mapping(9))
    assert identity.cycle_lengths != shifted.cycle_lengths
    assert shifted.phase_novelty > 0.0
    assert identity.class_fingerprint != shifted.class_fingerprint
