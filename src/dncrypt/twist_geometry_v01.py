from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math
from typing import Iterable, Sequence

DIM = 36
TAU = 2.0 * math.pi
SCHEMA = "dncrypt.twist-geometry/v0.1"


class TwistGeometryError(ValueError):
    pass


def _wrap_phase(value: float) -> float:
    return math.atan2(math.sin(value), math.cos(value))


def _validated_slice(values: Sequence[float]) -> tuple[float, ...]:
    if len(values) != DIM:
        raise TwistGeometryError("phase slice must contain exactly 36 values")
    out = tuple(float(value) for value in values)
    if not all(math.isfinite(value) for value in out):
        raise TwistGeometryError("phase slice values must be finite")
    return out


def _validated_mapping(mapping: Sequence[int] | None) -> tuple[int, ...]:
    if mapping is None:
        return tuple(range(DIM))
    out = tuple(int(index) for index in mapping)
    if tuple(sorted(out)) != tuple(range(DIM)):
        raise TwistGeometryError("mapping must be a permutation of 0..35")
    return out


def cyclic_mapping(shift: int) -> tuple[int, ...]:
    s = int(shift) % DIM
    return tuple((index + s) % DIM for index in range(DIM))


def relative_phase_field(
    slice_a: Sequence[float],
    slice_b: Sequence[float],
    mapping: Sequence[int] | None = None,
) -> tuple[float, ...]:
    """Gauge-clean relative phase field between two 36D slices.

    A common global phase added to both slices cancels exactly. ``mapping`` says
    which coordinate of ``slice_b`` is compared with each coordinate of
    ``slice_a``; a cyclic mapping is the discrete analogue of twisting one slice
    relative to another.
    """
    a = _validated_slice(slice_a)
    b = _validated_slice(slice_b)
    route = _validated_mapping(mapping)
    return tuple(_wrap_phase(b[route[index]] - a[index]) for index in range(DIM))


def _complex_order(field: Sequence[float], harmonic: int = 1) -> complex:
    if harmonic <= 0:
        raise TwistGeometryError("harmonic must be positive")
    return sum(
        complex(math.cos(harmonic * value), math.sin(harmonic * value))
        for value in field
    ) / float(len(field))


def _quantized(value: float) -> float:
    # Diagnostic content addressing only. This is not a security commitment.
    return round(float(value), 12)


@dataclass(frozen=True, slots=True)
class TwistSignature:
    schema: str
    mapping: tuple[int, ...]
    coherence: float
    novelty: float
    common_rotation_rad: float
    residual_rms_rad: float
    gradient_rms_rad: float
    harmonic_magnitudes: tuple[float, ...]
    common_rotation_only: bool

    @property
    def diagnostic_fingerprint(self) -> str:
        payload = {
            "schema": self.schema,
            "mapping": self.mapping,
            "coherence": _quantized(self.coherence),
            "novelty": _quantized(self.novelty),
            "common_rotation_rad": _quantized(self.common_rotation_rad),
            "residual_rms_rad": _quantized(self.residual_rms_rad),
            "gradient_rms_rad": _quantized(self.gradient_rms_rad),
            "harmonic_magnitudes": tuple(_quantized(x) for x in self.harmonic_magnitudes),
            "common_rotation_only": self.common_rotation_only,
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.blake2b(raw, digest_size=32).hexdigest()


def twist_signature(
    slice_a: Sequence[float],
    slice_b: Sequence[float],
    mapping: Sequence[int] | None = None,
    *,
    harmonics: Iterable[int] = (1, 2, 3, 4),
    common_rotation_tolerance: float = 1e-12,
) -> TwistSignature:
    route = _validated_mapping(mapping)
    field = relative_phase_field(slice_a, slice_b, route)
    z1 = _complex_order(field, 1)
    coherence = min(1.0, max(0.0, abs(z1)))
    common_rotation = math.atan2(z1.imag, z1.real) if coherence > 0.0 else 0.0
    residuals = tuple(_wrap_phase(value - common_rotation) for value in field)
    residual_rms = math.sqrt(sum(value * value for value in residuals) / DIM)
    gradients = tuple(_wrap_phase(field[(i + 1) % DIM] - field[i]) for i in range(DIM))
    gradient_rms = math.sqrt(sum(value * value for value in gradients) / DIM)
    hs = tuple(int(h) for h in harmonics)
    if not hs or any(h <= 0 for h in hs):
        raise TwistGeometryError("harmonics must contain positive integers")
    harmonic_magnitudes = tuple(abs(_complex_order(field, h)) for h in hs)
    return TwistSignature(
        schema=SCHEMA,
        mapping=route,
        coherence=coherence,
        novelty=1.0 - coherence,
        common_rotation_rad=common_rotation,
        residual_rms_rad=residual_rms,
        gradient_rms_rad=gradient_rms,
        harmonic_magnitudes=harmonic_magnitudes,
        common_rotation_only=residual_rms <= float(common_rotation_tolerance),
    )


def cyclic_twist_scan(
    slice_a: Sequence[float],
    slice_b: Sequence[float],
) -> tuple[TwistSignature, ...]:
    return tuple(twist_signature(slice_a, slice_b, cyclic_mapping(shift)) for shift in range(DIM))


def most_relationally_novel_cyclic_twist(
    slice_a: Sequence[float],
    slice_b: Sequence[float],
    *,
    include_identity: bool = False,
) -> tuple[int, TwistSignature]:
    scan = cyclic_twist_scan(slice_a, slice_b)
    start = 0 if include_identity else 1
    candidates = tuple(enumerate(scan[start:], start=start))
    if not candidates:
        raise TwistGeometryError("no cyclic twist candidates")
    return max(
        candidates,
        key=lambda item: (
            item[1].novelty,
            item[1].residual_rms_rad,
            item[1].gradient_rms_rad,
            -item[0],
        ),
    )
