from __future__ import annotations
from dataclasses import dataclass
import hashlib, math
import numpy as np
from .genome import CipherGenome, DIM

@dataclass(frozen=True, slots=True)
class CipherSurface:
    tick: int
    phi: tuple[float, ...]
    omega: tuple[float, ...]

    def __post_init__(self) -> None:
        if self.tick < 0:
            raise ValueError("tick must be non-negative")
        if len(self.phi) != DIM or len(self.omega) != DIM:
            raise ValueError("surface must be 36D")
        if not np.all(np.isfinite(np.asarray(self.phi))) or not np.all(np.isfinite(np.asarray(self.omega))):
            raise ValueError("surface values must be finite")

    @property
    def commitment(self) -> str:
        raw = np.asarray(self.phi, dtype="<f8").tobytes() + np.asarray(self.omega, dtype="<f8").tobytes() + self.tick.to_bytes(8, "big")
        return hashlib.blake2b(raw, digest_size=32).hexdigest()


def initial_surface(genome: CipherGenome) -> CipherSurface:
    phi = np.asarray(genome.phase36(), dtype=np.float64)
    raw = hashlib.shake_256(bytes.fromhex(genome.phase_seed_hex) + b"DNCrypt/v0.2/omega").digest(DIM*8)
    u = np.frombuffer(raw, dtype="<u8").astype(np.float64) / np.float64(2**64 - 1)
    omega = 0.75 + 0.5 * u
    return CipherSurface(0, tuple(phi.tolist()), tuple(omega.tolist()))


def evolve_surface(surface: CipherSurface, genome: CipherGenome, steps: int = 1, dt: float = 0.01) -> CipherSurface:
    if steps < 0 or not math.isfinite(dt) or dt <= 0:
        raise ValueError("invalid evolution parameters")
    phi = np.asarray(surface.phi, dtype=np.float64).copy()
    omega = np.asarray(surface.omega, dtype=np.float64)
    op = np.asarray(genome.operator_vector, dtype=np.float64)
    coupling_scale = 0.015 + 0.02 * (op / 255.0)
    route = np.asarray(genome.route, dtype=int)
    for _ in range(steps):
        routed = phi[route]
        coupling = coupling_scale * np.sin(routed - phi)
        phi = (phi + dt * (omega + coupling)) % (2.0 * np.pi)
    return CipherSurface(surface.tick + steps, tuple(phi.tolist()), tuple(omega.tolist()))


def transition_surface(surface: CipherSurface, child_genome: CipherGenome, *, steps: int = 1, dt: float = 0.01) -> CipherSurface:
    """Advance an existing surface under the promoted child's dynamics without resetting internal time."""
    if child_genome.generation <= 0:
        raise ValueError("child_genome must be a mutated generation")
    return evolve_surface(surface, child_genome, steps=steps, dt=dt)
