from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from typing import Sequence

from .twist_geometry_v01 import (
    DIM,
    TwistGeometryError,
    relative_phase_field,
    twist_signature,
)

SCHEMA = "dncrypt.relational-twist-class/v0.2"


def _validate_permutation(route: Sequence[int]) -> tuple[int, ...]:
    out = tuple(int(x) for x in route)
    if tuple(sorted(out)) != tuple(range(DIM)):
        raise TwistGeometryError("route must be a permutation of 0..35")
    return out


def inverse_permutation(route: Sequence[int]) -> tuple[int, ...]:
    r = _validate_permutation(route)
    inv = [0] * DIM
    for i, j in enumerate(r):
        inv[j] = i
    return tuple(inv)


def compose_permutations(left: Sequence[int], right: Sequence[int]) -> tuple[int, ...]:
    """Return left o right for index maps."""
    a = _validate_permutation(left)
    b = _validate_permutation(right)
    return tuple(a[b[i]] for i in range(DIM))


def relative_permutation(route_a: Sequence[int], route_b: Sequence[int]) -> tuple[int, ...]:
    """Return route_B o route_A^{-1}.

    Equal routes therefore collapse exactly to identity. A simultaneous relabeling
    conjugates this permutation without changing its cycle structure.
    """
    return compose_permutations(route_b, inverse_permutation(route_a))


def permutation_cycles(route: Sequence[int]) -> tuple[tuple[int, ...], ...]:
    r = _validate_permutation(route)
    seen: set[int] = set()
    cycles: list[tuple[int, ...]] = []
    for start in range(DIM):
        if start in seen:
            continue
        cycle: list[int] = []
        current = start
        while current not in seen:
            seen.add(current)
            cycle.append(current)
            current = r[current]
        if current != start:
            raise TwistGeometryError("route cycle closure failed")
        minimum = min(cycle)
        pivot = cycle.index(minimum)
        canonical = tuple(cycle[pivot:] + cycle[:pivot])
        cycles.append(canonical)
    return tuple(sorted(cycles, key=lambda c: (len(c), c)))


def _wrap(value: float) -> float:
    return math.atan2(math.sin(value), math.cos(value))


def _quantized(value: float) -> float:
    return round(float(value), 12)


@dataclass(frozen=True, slots=True)
class RelationalTwistClass:
    schema: str
    relative_mapping: tuple[int, ...]
    cycle_lengths: tuple[int, ...]
    cycle_holonomies_rad: tuple[float, ...]
    phase_coherence: float
    phase_novelty: float
    residual_rms_rad: float
    harmonic_magnitudes: tuple[float, ...]

    @property
    def canonical_cycle_signature(self) -> tuple[tuple[int, float], ...]:
        return tuple(sorted(
            (length, _quantized(holonomy))
            for length, holonomy in zip(self.cycle_lengths, self.cycle_holonomies_rad)
        ))

    @property
    def class_fingerprint(self) -> str:
        # Deliberately excludes raw labels and the explicit relative_mapping.
        # The digest identifies the relational class modulo simultaneous relabeling.
        payload = {
            "schema": self.schema,
            "cycles": self.canonical_cycle_signature,
            "phase_coherence": _quantized(self.phase_coherence),
            "phase_novelty": _quantized(self.phase_novelty),
            "residual_rms_rad": _quantized(self.residual_rms_rad),
            "harmonic_magnitudes": tuple(_quantized(x) for x in self.harmonic_magnitudes),
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.blake2b(raw, digest_size=32).hexdigest()


def relational_twist_class(
    slice_a: Sequence[float],
    slice_b: Sequence[float],
    route_a: Sequence[int],
    route_b: Sequence[int],
) -> RelationalTwistClass:
    rel = relative_permutation(route_a, route_b)
    cycles = permutation_cycles(rel)
    field = relative_phase_field(slice_a, slice_b, rel)
    signature = twist_signature(slice_a, slice_b, rel)

    holonomies = tuple(
        _wrap(sum(field[index] for index in cycle))
        for cycle in cycles
    )
    return RelationalTwistClass(
        schema=SCHEMA,
        relative_mapping=rel,
        cycle_lengths=tuple(len(cycle) for cycle in cycles),
        cycle_holonomies_rad=holonomies,
        phase_coherence=signature.coherence,
        phase_novelty=signature.novelty,
        residual_rms_rad=signature.residual_rms_rad,
        harmonic_magnitudes=signature.harmonic_magnitudes,
    )
