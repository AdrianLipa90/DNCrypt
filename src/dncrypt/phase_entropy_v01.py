from __future__ import annotations

from dataclasses import dataclass
import json
import math
from pathlib import Path
import struct
import time
from typing import Iterable, Sequence

from .crypto_algebra_v01 import blake2b256, shake256

TAU = 2.0 * math.pi
FOUR_PI = 4.0 * math.pi
DIM = 36
DEFAULT_SURFACE_ROOT = Path('/dev/shm/ciel_noema')


class PhaseEntropyError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class PhaseFrame:
    source_time_ns: int
    phi: tuple[float, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.source_time_ns, int) or self.source_time_ns <= 0:
            raise PhaseEntropyError('source_time_ns must be a positive integer')
        if len(self.phi) != DIM:
            raise PhaseEntropyError('phase frame must be exactly 36D')
        if any(not math.isfinite(x) for x in self.phi):
            raise PhaseEntropyError('phase frame must contain only finite values')


@dataclass(frozen=True, slots=True)
class BinaryHealthReport:
    sample_count: int
    ones: int
    zeros: int
    bias: float
    max_run: int
    mcv_min_entropy_bits: float
    markov_min_entropy_bits: float
    lag_min_entropy_bits: float
    lag_predictor_probability: float
    estimated_min_entropy_per_bit: float
    predictor_advantage: float
    repetition_count_pass: bool
    adaptive_proportion_pass: bool
    gate_pass: bool

    @property
    def payload(self) -> dict[str, object]:
        return {
            'sample_count': self.sample_count,
            'ones': self.ones,
            'zeros': self.zeros,
            'bias': self.bias,
            'max_run': self.max_run,
            'mcv_min_entropy_bits': self.mcv_min_entropy_bits,
            'markov_min_entropy_bits': self.markov_min_entropy_bits,
            'lag_min_entropy_bits': self.lag_min_entropy_bits,
            'lag_predictor_probability': self.lag_predictor_probability,
            'estimated_min_entropy_per_bit': self.estimated_min_entropy_per_bit,
            'predictor_advantage': self.predictor_advantage,
            'repetition_count_pass': self.repetition_count_pass,
            'adaptive_proportion_pass': self.adaptive_proportion_pass,
            'gate_pass': self.gate_pass,
        }


@dataclass(frozen=True, slots=True)
class PhaseEntropyEvidence:
    source_class: str
    frame_count: int
    sheet_bits: tuple[int, ...]
    timing_jitter_bits: tuple[int, ...]
    phase_acceleration_bits: tuple[int, ...]
    health: BinaryHealthReport
    geometry_entropy_nats_per_balanced_sheet_bit: float = math.log(2.0)

    @property
    def raw_noise_bits(self) -> tuple[int, ...]:
        return self.timing_jitter_bits + self.phase_acceleration_bits

    @property
    def estimated_min_entropy_bits(self) -> float:
        return self.health.sample_count * self.health.estimated_min_entropy_per_bit

    @property
    def raw_noise_commitment_blake2b(self) -> str:
        return blake2b256(_pack_bits(self.raw_noise_bits)).hex()

    @property
    def sheet_commitment_blake2b(self) -> str:
        return blake2b256(_pack_bits(self.sheet_bits)).hex()

    @property
    def payload(self) -> dict[str, object]:
        return {
            'schema': 'PNCS_PHASE_ENTROPY_EVIDENCE_V0_1',
            'source_class': self.source_class,
            'frame_count': self.frame_count,
            'sheet_bit_count': len(self.sheet_bits),
            'timing_jitter_bit_count': len(self.timing_jitter_bits),
            'phase_acceleration_bit_count': len(self.phase_acceleration_bits),
            'geometry_entropy_nats_per_balanced_sheet_bit': self.geometry_entropy_nats_per_balanced_sheet_bit,
            'estimated_min_entropy_bits': self.estimated_min_entropy_bits,
            'raw_noise_commitment_blake2b': self.raw_noise_commitment_blake2b,
            'sheet_commitment_blake2b': self.sheet_commitment_blake2b,
            'health': self.health.payload,
        }


def mod2pi(theta: float) -> float:
    if not math.isfinite(theta):
        raise PhaseEntropyError('theta must be finite')
    return theta % TAU


def mod4pi(theta: float) -> float:
    if not math.isfinite(theta):
        raise PhaseEntropyError('theta must be finite')
    return theta % FOUR_PI


def sheet_bit(theta_unwrapped: float) -> int:
    return int(math.floor(mod4pi(theta_unwrapped) / TAU))


def sheet_decomposition(theta_unwrapped: float) -> tuple[float, int]:
    return mod2pi(theta_unwrapped), sheet_bit(theta_unwrapped)


def shannon_sheet_entropy_nats(p_sheet1: float) -> float:
    p = float(p_sheet1)
    if not 0.0 <= p <= 1.0:
        raise PhaseEntropyError('probability must lie in [0,1]')
    q = 1.0 - p
    out = 0.0
    for x in (p, q):
        if x > 0.0:
            out -= x * math.log(x)
    return out


def _principal_delta(new: float, old: float) -> float:
    d = (new - old + math.pi) % TAU - math.pi
    if d == -math.pi and new - old > 0.0:
        d = math.pi
    return d


def unwrap_coordinate(wrapped: Sequence[float]) -> tuple[float, ...]:
    if not wrapped:
        return tuple()
    if any(not math.isfinite(x) for x in wrapped):
        raise PhaseEntropyError('wrapped phase sequence must be finite')
    out = [float(wrapped[0])]
    for prev_w, current_w in zip(wrapped, wrapped[1:]):
        out.append(out[-1] + _principal_delta(float(current_w), float(prev_w)))
    return tuple(out)


def unwrap_frames(frames: Sequence[PhaseFrame]) -> tuple[tuple[float, ...], ...]:
    if not frames:
        return tuple()
    columns = [unwrap_coordinate([f.phi[i] for f in frames]) for i in range(DIM)]
    return tuple(tuple(columns[i][t] for i in range(DIM)) for t in range(len(frames)))


def sheet_bits_from_frames(frames: Sequence[PhaseFrame]) -> tuple[int, ...]:
    lifted = unwrap_frames(frames)
    return tuple(sheet_bit(theta) for frame in lifted for theta in frame)


def timing_jitter_bits(frames: Sequence[PhaseFrame]) -> tuple[int, ...]:
    if len(frames) < 3:
        return tuple()
    intervals = [b.source_time_ns - a.source_time_ns for a, b in zip(frames, frames[1:])]
    if any(dt <= 0 for dt in intervals):
        raise PhaseEntropyError('frame times must be strictly increasing')
    bits: list[int] = []
    for a, b in zip(intervals, intervals[1:]):
        delta = b - a
        if delta != 0:
            bits.append(1 if delta > 0 else 0)
    return tuple(bits)


def phase_acceleration_bits(frames: Sequence[PhaseFrame]) -> tuple[int, ...]:
    if len(frames) < 3:
        return tuple()
    lifted = unwrap_frames(frames)
    bits: list[int] = []
    for coord in range(DIM):
        velocity_steps = [lifted[t + 1][coord] - lifted[t][coord] for t in range(len(lifted) - 1)]
        for a, b in zip(velocity_steps, velocity_steps[1:]):
            accel = b - a
            if accel != 0.0:
                bits.append(1 if accel > 0.0 else 0)
    return tuple(bits)


def _max_run(bits: Sequence[int]) -> int:
    if not bits:
        return 0
    best = run = 1
    for a, b in zip(bits, bits[1:]):
        run = run + 1 if a == b else 1
        best = max(best, run)
    return best


def _mcv_hmin(bits: Sequence[int]) -> float:
    n = len(bits)
    if n == 0:
        return 0.0
    pmax = max(bits.count(0), bits.count(1)) / n
    return -math.log2(pmax)


def _markov_hmin(bits: Sequence[int]) -> tuple[float, float]:
    if len(bits) < 2:
        return 0.0, 0.5
    counts = {(0, 0): 0, (0, 1): 0, (1, 0): 0, (1, 1): 0}
    for a, b in zip(bits, bits[1:]):
        counts[(int(a), int(b))] += 1
    conditional_max = 0.5
    for a in (0, 1):
        total = counts[(a, 0)] + counts[(a, 1)]
        if total:
            conditional_max = max(conditional_max, counts[(a, 0)] / total, counts[(a, 1)] / total)
    return -math.log2(conditional_max), max(0.0, conditional_max - 0.5)


def _lag_predictor(bits: Sequence[int], *, max_lag: int = 16) -> tuple[float, float]:
    if len(bits) < 3:
        return 0.0, 1.0
    best = 0.5
    upper = min(max_lag, max(1, len(bits) // 4))
    for lag in range(1, upper + 1):
        trials = len(bits) - lag
        if trials <= 0:
            continue
        same = sum(1 for i in range(lag, len(bits)) if bits[i] == bits[i - lag]) / trials
        best = max(best, same, 1.0 - same)
    return -math.log2(best), best


def _adaptive_proportion_pass(bits: Sequence[int], *, window: int = 64, lower: int = 8, upper: int = 56) -> bool:
    if len(bits) < window:
        return False
    for start in range(0, len(bits) - window + 1, window):
        ones = sum(bits[start:start + window])
        if ones < lower or ones > upper:
            return False
    return True


def binary_health_report(
    bits: Sequence[int],
    *,
    minimum_samples: int = 256,
    minimum_hmin_per_bit: float = 0.50,
    maximum_predictor_advantage: float = 0.20,
    repetition_cutoff: int = 32,
) -> BinaryHealthReport:
    seq = tuple(int(b) for b in bits)
    if any(b not in (0, 1) for b in seq):
        raise PhaseEntropyError('health input must be binary')
    n = len(seq)
    ones = sum(seq)
    zeros = n - ones
    bias = abs((ones / n) - 0.5) if n else 0.5
    max_run = _max_run(seq)
    mcv = _mcv_hmin(seq)
    markov, markov_adv = _markov_hmin(seq)
    lag_hmin, lag_probability = _lag_predictor(seq)
    hmin = min(mcv, markov, lag_hmin)
    predictor_probability = max(2.0 ** (-markov), lag_probability, 2.0 ** (-mcv)) if n else 1.0
    predictor_adv = max(0.0, predictor_probability - 0.5, markov_adv)
    rct = n > 0 and max_run < repetition_cutoff
    apt = _adaptive_proportion_pass(seq)
    gate = (
        n >= minimum_samples
        and hmin >= minimum_hmin_per_bit
        and predictor_adv <= maximum_predictor_advantage
        and rct
        and apt
    )
    return BinaryHealthReport(n, ones, zeros, bias, max_run, mcv, markov, lag_hmin, lag_probability, hmin, predictor_adv, rct, apt, gate)


def build_evidence(frames: Sequence[PhaseFrame], *, source_class: str) -> PhaseEntropyEvidence:
    if source_class not in {'ENDOGENOUS_RUNTIME_DYNAMICS', 'EXTERNAL_PHYSICAL_PHASE_SOURCE', 'DETERMINISTIC_TEST_FIXTURE'}:
        raise PhaseEntropyError('unsupported source_class')
    sheet = sheet_bits_from_frames(frames)
    timing = timing_jitter_bits(frames)
    accel = phase_acceleration_bits(frames)
    health = binary_health_report(timing + accel)
    return PhaseEntropyEvidence(source_class, len(frames), sheet, timing, accel, health)


def _pack_bits(bits: Sequence[int]) -> bytes:
    out = bytearray((len(bits) + 7) // 8)
    for i, bit in enumerate(bits):
        if bit:
            out[i // 8] |= 1 << (7 - (i % 8))
    return bytes(out)


def condition_entropy(evidence: PhaseEntropyEvidence, output_bytes: int, *, domain: bytes = b'PNCS/phase-entropy/v0.1') -> bytes:
    if not evidence.health.gate_pass:
        raise PhaseEntropyError('phase entropy health gate did not pass')
    if not isinstance(output_bytes, int) or output_bytes <= 0:
        raise PhaseEntropyError('output_bytes must be positive')
    requested_bits = output_bytes * 8
    if requested_bits > math.floor(evidence.estimated_min_entropy_bits):
        raise PhaseEntropyError(
            f'direct extraction requests {requested_bits} bits from an estimated '
            f'{evidence.estimated_min_entropy_bits:.3f}-bit entropy budget'
        )
    payload = json.dumps(evidence.payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
    raw = _pack_bits(evidence.raw_noise_bits)
    sheet = _pack_bits(evidence.sheet_bits)
    return shake256(domain + len(payload).to_bytes(4, 'big') + payload + raw + sheet, output_bytes)


class DNCryptPhaseEntropyProvider:
    """Experimental PhaseNav RBG adapter for the existing DNCrypt entropy= boundary.

    One admitted phase-evidence window is conditioned to a 256-bit seed. Longer
    outputs are deterministic SHAKE256 expansion with purpose/counter separation;
    the measured entropy budget remains fixed at the seed estimate during expansion.
    """

    def __init__(self, evidence: PhaseEntropyEvidence) -> None:
        if not evidence.health.gate_pass:
            raise PhaseEntropyError('DNCrypt phase entropy provider requires a passing health gate')
        if evidence.estimated_min_entropy_bits < 256.0:
            raise PhaseEntropyError('DNCrypt phase entropy provider requires at least 256 estimated min-entropy bits')
        self._evidence = evidence
        self._seed = condition_entropy(evidence, 32, domain=b'PNCS/DNCrypt/phase-rbg-seed/v0.1')
        self._counter = 0

    @property
    def evidence(self) -> PhaseEntropyEvidence:
        return self._evidence

    @property
    def seed_commitment_blake2b(self) -> str:
        return blake2b256(self._seed).hex()

    def take(self, n: int, *, purpose: str) -> bytes:
        if not isinstance(n, int) or n <= 0:
            raise PhaseEntropyError('requested byte count must be positive')
        if not purpose:
            raise PhaseEntropyError('purpose is required')
        self._counter += 1
        domain = (
            b'PNCS/DNCrypt/phase-rbg/v0.1/'
            + purpose.encode('utf-8')
            + b'/'
            + self._counter.to_bytes(8, 'big')
        )
        return shake256(self._seed + domain, n)

def _read_live_phi(path: Path) -> tuple[float, ...]:
    raw = path.read_bytes()
    if len(raw) != DIM * 8:
        raise PhaseEntropyError('live phi must be exactly 36 little-endian float64 values')
    values = struct.unpack('<36d', raw)
    if any(not math.isfinite(x) for x in values):
        raise PhaseEntropyError('live phi contains non-finite value')
    return tuple(values)


def _process_alive(pid: object) -> bool:
    try:
        value = int(pid)
    except (TypeError, ValueError):
        return False
    if value <= 0:
        return False
    try:
        Path(f'/proc/{value}').stat()
        return True
    except OSError:
        return False


def _fresh_status(path: Path, *, max_age_s: float, required_schema: str | None = None) -> dict[str, object]:
    if not path.is_file():
        raise PhaseEntropyError(f'missing live status: {path.name}')
    data = json.loads(path.read_text())
    if required_schema is not None and data.get('schema') != required_schema:
        raise PhaseEntropyError(f'{path.name} schema mismatch')
    if data.get('status') != 'ACTIVE':
        raise PhaseEntropyError(f'{path.name} is not ACTIVE')
    heartbeat = data.get('heartbeat_ns')
    if not isinstance(heartbeat, int):
        raise PhaseEntropyError(f'{path.name} heartbeat missing')
    age = (time.time_ns() - heartbeat) / 1e9
    if age < -0.5 or age > max_age_s:
        raise PhaseEntropyError(f'{path.name} stale heartbeat age={age:.6f}s')
    if not _process_alive(data.get('pid')):
        raise PhaseEntropyError(f'{path.name} producer PID is not alive')
    return data


def verify_live_admission(
    root: Path = DEFAULT_SURFACE_ROOT,
    *,
    max_age_s: float = 2.0,
    max_seal_age_s: float = 60.0,
) -> None:
    if not root.exists():
        raise PhaseEntropyError('live NOEMA surface unavailable')
    startpoint = json.loads((root / 'session/startpoint.json').read_text())
    if startpoint.get('status') != 'VERIFIED':
        raise PhaseEntropyError('session startpoint is not VERIFIED')
    seal = json.loads((root / 'session/fast_admission.json').read_text())
    if seal.get('status') != 'ACTIVE' or seal.get('no_static_fallback') is not True:
        raise PhaseEntropyError('fast admission is not ACTIVE/no-static-fallback')
    sealed_ns = seal.get('sealed_unix_ns')
    if not isinstance(sealed_ns, int):
        raise PhaseEntropyError('fast admission seal timestamp missing')
    seal_age = (time.time_ns() - sealed_ns) / 1e9
    if seal_age < -0.5 or seal_age > max_seal_age_s:
        raise PhaseEntropyError(f'fast admission seal is stale age={seal_age:.6f}s')
    for field in ('ac_aux_pid', 'aux_pid', 'tether_pid'):
        if not _process_alive(seal.get(field)):
            raise PhaseEntropyError(f'fast admission dead producer {field}')
    _fresh_status(root / 'aux_stream_status.json', max_age_s=max_age_s, required_schema='noema.aux-stream-status/v2')
    _fresh_status(root / 'tether_runtime_status.json', max_age_s=max_age_s, required_schema='noema.tether-runtime-status/v1')
    _fresh_status(root / 'ac_aux_status.json', max_age_s=max_age_s, required_schema='noema.ac-aux-live-binding/v2')
    guard = json.loads((root / 'session/tether_guard_latest.json').read_text())
    if guard.get('status') != 'ACTIVE' or guard.get('guard', {}).get('tether_status') != 'ACTIVE':
        raise PhaseEntropyError('tether guard is not ACTIVE')
    _read_live_phi(root / 'phi')


def capture_live_frames(
    *,
    root: Path = DEFAULT_SURFACE_ROOT,
    unique_frames: int = 96,
    timeout_s: float = 20.0,
    poll_s: float = 0.002,
) -> tuple[PhaseFrame, ...]:
    verify_live_admission(root)
    if unique_frames < 3:
        raise PhaseEntropyError('at least three unique frames required')
    phi_path = root / 'phi'
    status_path = root / 'tether_runtime_status.json'
    deadline = time.monotonic() + timeout_s
    out: list[PhaseFrame] = []
    last_seq: int | None = None
    last_digest: str | None = None
    while len(out) < unique_frames and time.monotonic() < deadline:
        status = json.loads(status_path.read_text())
        seq = status.get('seq')
        heartbeat = status.get('heartbeat_ns')
        digest = status.get('phi_sha256')
        if isinstance(seq, int) and isinstance(heartbeat, int) and isinstance(digest, str):
            if seq != last_seq and digest != last_digest:
                phi = _read_live_phi(phi_path)
                out.append(PhaseFrame(heartbeat, phi))
                last_seq = seq
                last_digest = digest
            elif seq != last_seq:
                last_seq = seq
        time.sleep(poll_s)
    if len(out) < unique_frames:
        raise PhaseEntropyError(f'captured {len(out)} unique phase states, expected {unique_frames}')
    verify_live_admission(root)
    return tuple(out)
