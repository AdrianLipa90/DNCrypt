from __future__ import annotations
from dataclasses import dataclass, asdict
import hashlib, math, secrets
import numpy as np
from .util import canonical_json_bytes, blake2b256

DIM = 36
VERSION = "DNCrypt/v0.2"

@dataclass(frozen=True, slots=True)
class CipherGenome:
    version: str
    generation: int
    parent_id: str | None
    operator_vector: tuple[int, ...]
    route: tuple[int, ...]
    phase_seed_hex: str
    mutation_nonce_hex: str

    def __post_init__(self) -> None:
        if self.version != VERSION:
            raise ValueError("unsupported genome version")
        if self.generation < 0:
            raise ValueError("generation must be non-negative")
        if len(self.operator_vector) != DIM or any(not 0 <= x <= 255 for x in self.operator_vector):
            raise ValueError("operator_vector must contain 36 uint8 values")
        if tuple(sorted(self.route)) != tuple(range(DIM)):
            raise ValueError("route must be a permutation of 0..35")
        if len(bytes.fromhex(self.phase_seed_hex)) != 32:
            raise ValueError("phase_seed_hex must encode 32 bytes")
        if len(bytes.fromhex(self.mutation_nonce_hex)) != 16:
            raise ValueError("mutation_nonce_hex must encode 16 bytes")

    @property
    def genome_id(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))

    def phase36(self) -> tuple[float, ...]:
        raw = hashlib.shake_256(bytes.fromhex(self.phase_seed_hex) + b"DNCrypt/v0.2/phase36").digest(DIM * 8)
        vals = np.frombuffer(raw, dtype="<u8").astype(np.float64)
        vals /= np.float64(2**64 - 1)
        return tuple((vals * (2.0 * math.pi)).tolist())


def _derive_bytes(seed: bytes, label: bytes, n: int) -> bytes:
    return hashlib.shake_256(seed + b"|" + label).digest(n)


def initial_genome(entropy: bytes | None = None) -> CipherGenome:
    seed = secrets.token_bytes(64) if entropy is None else bytes(entropy)
    if len(seed) < 32:
        raise ValueError("entropy must contain at least 32 bytes")
    op = tuple(_derive_bytes(seed, b"operator", DIM))
    keys = np.frombuffer(_derive_bytes(seed, b"route", DIM * 8), dtype="<u8")
    route = tuple(np.argsort(keys, kind="stable").astype(int).tolist())
    phase = _derive_bytes(seed, b"phase", 32).hex()
    nonce = _derive_bytes(seed, b"mutation-nonce", 16).hex()
    return CipherGenome(VERSION, 0, None, op, route, phase, nonce)


def mutate_genome(parent: CipherGenome, entropy: bytes | None = None) -> CipherGenome:
    e = secrets.token_bytes(64) if entropy is None else bytes(entropy)
    if len(e) < 32:
        raise ValueError("mutation entropy must contain at least 32 bytes")
    seed = bytes.fromhex(parent.phase_seed_hex) + bytes.fromhex(parent.mutation_nonce_hex) + e
    base = np.asarray(parent.operator_vector, dtype=np.uint16)
    delta = np.frombuffer(_derive_bytes(seed, b"delta", DIM), dtype=np.uint8).astype(np.uint16)
    mask = np.frombuffer(_derive_bytes(seed, b"mask", DIM), dtype=np.uint8) < 96
    child = base.copy()
    child[mask] = (child[mask] + delta[mask] + 1) & 0xFF
    route_keys = np.frombuffer(_derive_bytes(seed, b"route", DIM * 8), dtype="<u8")
    parent_route = np.asarray(parent.route, dtype=int)
    route = tuple(parent_route[np.argsort(route_keys, kind="stable")].astype(int).tolist())
    return CipherGenome(
        VERSION,
        parent.generation + 1,
        parent.genome_id,
        tuple(int(x) for x in child),
        route,
        _derive_bytes(seed, b"phase", 32).hex(),
        _derive_bytes(seed, b"mutation-nonce", 16).hex(),
    )


def vectorized_mutation_population(parent: CipherGenome, population_size: int, entropy: bytes | None = None) -> tuple[CipherGenome, ...]:
    if population_size <= 0:
        raise ValueError("population_size must be positive")
    raw = secrets.token_bytes(population_size * 64) if entropy is None else bytes(entropy)
    if len(raw) != population_size * 64:
        raise ValueError("entropy must be exactly population_size*64 bytes")
    blocks = np.frombuffer(raw, dtype=np.uint8).reshape(population_size, 64)
    seeds = [
        hashlib.shake_256(bytes(row) + bytes.fromhex(parent.phase_seed_hex) + i.to_bytes(8, "big") + b"DNCrypt/v0.2/pop").digest(128)
        for i, row in enumerate(blocks)
    ]
    delta = np.stack([np.frombuffer(s[:DIM], dtype=np.uint8) for s in seeds]).astype(np.uint16)
    mask = np.stack([np.frombuffer(s[DIM:2*DIM], dtype=np.uint8) for s in seeds]) < 96
    base = np.broadcast_to(np.asarray(parent.operator_vector, dtype=np.uint16), (population_size, DIM)).copy()
    base[mask] = (base[mask] + delta[mask] + 1) & 0xFF
    out = []
    parent_route = np.asarray(parent.route, dtype=int)
    for i, s in enumerate(seeds):
        keys = np.frombuffer(hashlib.shake_256(s + b"route").digest(DIM*8), dtype="<u8")
        route = tuple(parent_route[np.argsort(keys, kind="stable")].astype(int).tolist())
        out.append(CipherGenome(
            VERSION, parent.generation + 1, parent.genome_id,
            tuple(int(x) for x in base[i]), route,
            hashlib.shake_256(s + b"phase").digest(32).hex(),
            hashlib.shake_256(s + b"nonce").digest(16).hex(),
        ))
    return tuple(out)


def population_commitment(population: tuple[CipherGenome, ...]) -> str:
    ids = [genome.genome_id for genome in population]
    if len(ids) != len(set(ids)):
        raise ValueError("population contains duplicate genome ids")
    return blake2b256(canonical_json_bytes(ids))
