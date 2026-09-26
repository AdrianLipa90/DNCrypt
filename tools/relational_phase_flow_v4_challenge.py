from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import importlib.util
from pathlib import Path
from typing import Sequence

from dncrypt.genetic_compiler import compile_genetic_program
from dncrypt.genome import CipherGenome, DIM, mutate_genome
from dncrypt.util import blake2b256, canonical_json_bytes

ROOT = Path(__file__).resolve().parents[1]

SPEC_AB = importlib.util.spec_from_file_location(
    "dncrypt_noema_abcd_v01",
    ROOT / "tools" / "prime_phase_abcd_challenge_v01.py",
)
ab = importlib.util.module_from_spec(SPEC_AB)
assert SPEC_AB.loader is not None
SPEC_AB.loader.exec_module(ab)

SPEC_V4 = importlib.util.spec_from_file_location(
    "dncrypt_noema_relflow_core_v4",
    ROOT / "tools" / "relational_phase_flow_core_v4.py",
)
v4 = importlib.util.module_from_spec(SPEC_V4)
assert SPEC_V4.loader is not None
SPEC_V4.loader.exec_module(v4)

SCHEMA = "dncrypt.noema-relational-phase-flow-v4/v0.1"
BINDING_SCHEMA = "dncrypt.noema-relational-phase-flow-v4-binding/v0.1"
STRATEGIES = ("B_RANDOM_LOCUS_NULL", "F_RELATIONAL_MATCHED_NUISANCE_V4")


@dataclass(frozen=True, slots=True)
class V4CandidateBinding:
    schema: str
    strategy: str
    parent_genome_id: str
    child_genome_id: str
    phenotype_commitment: str
    fresh_entropy_commitment: str
    relational_source_commitment: str | None
    random_null_skeleton: tuple[int, ...]
    selected_loci: tuple[int, ...]
    allowed_loci: tuple[int, ...]
    candidate_pool: tuple[int, ...]
    mutation_budget: int
    nuisance_signature: tuple[tuple[int, ...], tuple[int, ...]]
    frozen_aead_changed: bool = False
    cryptographic_entropy_authority: bool = False
    security_admission_authority: bool = False

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))


def _native_bound_entropy(raw_entropy: bytes, phenotype_commitment: str) -> bytes:
    return hashlib.shake_256(
        b"DNCrypt/v0.6.1/genetic-mutation/fresh|"
        + raw_entropy
        + bytes.fromhex(phenotype_commitment)
    ).digest(max(64, len(raw_entropy)))


def _candidate_pool(parent: CipherGenome, unconstrained: CipherGenome, allowed: Sequence[int]) -> tuple[int, ...]:
    changed = tuple(
        i for i in allowed
        if unconstrained.operator_vector[i] != parent.operator_vector[i]
    )
    # If the native unconstrained mutation missed every admitted locus, both arms
    # fall back to the same allowed-locus pool and therefore share the same forced-
    # mutation semantics.  No extra v4 authority is introduced.
    return changed if changed else tuple(allowed)


def _null_skeleton(pool: Sequence[int], fresh_entropy: bytes, budget: int) -> tuple[int, ...]:
    ranking = ab._rank_null(pool, fresh_entropy)
    k = min(int(budget), len(ranking))
    if k < 1:
        raise RuntimeError("empty DNCrypt candidate pool")
    return tuple(ranking[:k])


def _selected_loci(
    strategy: str,
    pool: Sequence[int],
    fresh_entropy: bytes,
    budget: int,
) -> tuple[tuple[int, ...], tuple[int, ...], str | None]:
    skeleton = _null_skeleton(pool, fresh_entropy, budget)
    if strategy == "B_RANDOM_LOCUS_NULL":
        return skeleton, skeleton, None
    if strategy != "F_RELATIONAL_MATCHED_NUISANCE_V4":
        raise ValueError(f"unsupported strategy {strategy!r}")
    source = v4.v3.relational_source_triple(fresh_entropy)
    chosen = v4.select_subset(source, pool, skeleton, fresh_entropy)
    if v4.nuisance_signature(chosen) != v4.nuisance_signature(skeleton):
        raise RuntimeError("v4 violated exact shell/flavour nuisance matching")
    return chosen, skeleton, source.commitment


def mutate_with_strategy(
    parent: CipherGenome,
    program,
    *,
    fresh_entropy: bytes,
    strategy: str,
) -> tuple[CipherGenome, V4CandidateBinding]:
    raw_entropy = bytes(fresh_entropy)
    if len(raw_entropy) < 32:
        raise ValueError("fresh mutation entropy must contain at least 32 bytes")
    phenotype = compile_genetic_program(program)
    allowed = tuple(phenotype.allowed_loci)

    unconstrained = mutate_genome(
        parent,
        _native_bound_entropy(raw_entropy, phenotype.commitment),
    )
    pool = _candidate_pool(parent, unconstrained, allowed)
    selected, skeleton, source_commitment = _selected_loci(
        strategy,
        pool,
        raw_entropy,
        phenotype.mutation_budget,
    )

    operator = list(parent.operator_vector)
    native_seed = ab._native_order_seed(raw_entropy)
    for index in selected:
        candidate_value = unconstrained.operator_vector[index]
        if candidate_value == parent.operator_vector[index]:
            delta = 1 + (native_seed[index] % 255)
            candidate_value = (parent.operator_vector[index] + delta) & 0xFF
        operator[index] = candidate_value

    route = list(unconstrained.route)
    shift = (phenotype.route_direction * phenotype.route_stride) % DIM
    route = route[shift:] + route[:shift]

    child = CipherGenome(
        version=unconstrained.version,
        generation=unconstrained.generation,
        parent_id=unconstrained.parent_id,
        operator_vector=tuple(operator),
        route=tuple(route),
        phase_seed_hex=unconstrained.phase_seed_hex,
        mutation_nonce_hex=unconstrained.mutation_nonce_hex,
    )
    changed_loci = tuple(
        i for i in range(DIM)
        if child.operator_vector[i] != parent.operator_vector[i]
    )
    if changed_loci != tuple(sorted(selected)):
        # Both branches are expected to have one non-zero mutation per selected locus.
        # Fail closed if an implementation change breaks that exact substrate model.
        raise RuntimeError("selected-locus and realized-mutation sets diverged")
    if not set(changed_loci).issubset(set(allowed)):
        raise RuntimeError("v4 escaped native Genetic IR allowed_loci")
    if len(changed_loci) > phenotype.mutation_budget:
        raise RuntimeError("v4 exceeded native Genetic IR mutation budget")

    sig = v4.nuisance_signature(selected)
    binding = V4CandidateBinding(
        schema=BINDING_SCHEMA,
        strategy=strategy,
        parent_genome_id=parent.genome_id,
        child_genome_id=child.genome_id,
        phenotype_commitment=phenotype.commitment,
        fresh_entropy_commitment=blake2b256(raw_entropy),
        relational_source_commitment=source_commitment,
        random_null_skeleton=tuple(skeleton),
        selected_loci=tuple(selected),
        allowed_loci=allowed,
        candidate_pool=tuple(pool),
        mutation_budget=phenotype.mutation_budget,
        nuisance_signature=sig,
    )
    return child, binding


def compare_candidate_pair(parent: CipherGenome, program, *, fresh_entropy: bytes) -> dict[str, object]:
    b_child, b = mutate_with_strategy(
        parent, program, fresh_entropy=fresh_entropy, strategy="B_RANDOM_LOCUS_NULL"
    )
    f_child, f = mutate_with_strategy(
        parent, program, fresh_entropy=fresh_entropy, strategy="F_RELATIONAL_MATCHED_NUISANCE_V4"
    )
    same_substrate = (
        b_child.route == f_child.route
        and b_child.phase_seed_hex == f_child.phase_seed_hex
        and b_child.mutation_nonce_hex == f_child.mutation_nonce_hex
        and b_child.parent_id == f_child.parent_id
        and b_child.generation == f_child.generation
        and b.allowed_loci == f.allowed_loci
        and b.candidate_pool == f.candidate_pool
        and b.mutation_budget == f.mutation_budget
    )
    exact_nuisance_match = b.nuisance_signature == f.nuisance_signature
    return {
        "same_substrate": same_substrate,
        "exact_nuisance_match": exact_nuisance_match,
        "selection_changed": b.selected_loci != f.selected_loci,
        "B": asdict(b),
        "F": asdict(f),
    }


__all__ = [
    "SCHEMA",
    "BINDING_SCHEMA",
    "STRATEGIES",
    "V4CandidateBinding",
    "mutate_with_strategy",
    "compare_candidate_pair",
]