"""Bounded Genetic IR -> mutation phenotype compiler for DNCrypt v0.6.1.

This is an experimental search-control layer.  It does not derive keys, salts,
nonces, evaluator credentials or security-admission evidence.  Fresh external
mutation entropy remains mandatory for every generated genome candidate.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any

from .genetic_ir import GeneticIRNode, GeneticLevel
from .genome import CipherGenome, mutate_genome, population_commitment
from .util import blake2b256, canonical_json_bytes

COMPILER_SCHEMA = "dncrypt.genetic-compiler/v0.6.1-candidate"
PHENOTYPE_SCHEMA = "dncrypt.mutation-phenotype/v0.6.1-candidate"
DICTIONARY_SCHEMA = "dncrypt.genetic-dictionary/v1"
DIM = 36

# This dictionary describes admitted search operations.  It is not a biological
# claim and grants no cryptographic authority.
_GENETIC_DICTIONARY_V1: dict[str, tuple[str, ...]] = {
    "KAKU": ("REWRITE_PAYLOAD",),
    "RADICAL": ("REWRITE_PAYLOAD", "DUPLICATE_CANDIDATE", "DELETE_CHILD_CANDIDATE"),
    "CONCEPT": ("REWRITE_PAYLOAD", "SWAP_ADJACENT", "DUPLICATE_CANDIDATE", "DELETE_CHILD_CANDIDATE"),
    "SENTENCE": ("REWRITE_PAYLOAD", "SWAP_ADJACENT", "INVERSION_CANDIDATE", "RECOMBINATION_CANDIDATE"),
    "PARAGRAPH": ("SWAP_ADJACENT", "INVERSION_CANDIDATE", "RECOMBINATION_CANDIDATE"),
    "CHAPTER": ("INVERSION_CANDIDATE", "TRANSLOCATION_CANDIDATE", "RECOMBINATION_CANDIDATE"),
    "BOOK": ("TRANSLOCATION_CANDIDATE", "RECOMBINATION_CANDIDATE"),
}


def genetic_dictionary_v1() -> dict[str, object]:
    return {
        "schema": DICTIONARY_SCHEMA,
        "authority": {
            "diagnostic_only": True,
            "security_admission": False,
            "cryptographic_entropy": False,
        },
        "levels": {name: list(ops) for name, ops in _GENETIC_DICTIONARY_V1.items()},
    }


@dataclass(frozen=True, slots=True)
class GeneticProgramStats:
    node_count: int
    relation_count: int
    payload_bytes: int
    max_depth: int
    level_counts: tuple[tuple[str, int], ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "node_count": self.node_count,
            "relation_count": self.relation_count,
            "payload_bytes": self.payload_bytes,
            "max_depth": self.max_depth,
            "level_counts": [[name, count] for name, count in self.level_counts],
        }


def program_stats(program: GeneticIRNode) -> GeneticProgramStats:
    counts: dict[str, int] = {level.name: 0 for level in GeneticLevel}
    node_count = 0
    relation_count = 0
    payload_bytes = 0
    max_depth = 0
    stack: list[tuple[GeneticIRNode, int]] = [(program, 0)]
    seen: set[int] = set()
    while stack:
        node, depth = stack.pop()
        # GeneticIRNode is a tree value, but guard against accidental object cycles
        # in hand-constructed Python structures.
        marker = id(node)
        if marker in seen:
            raise ValueError("Genetic IR object graph contains a repeated object reference")
        seen.add(marker)
        node_count += 1
        relation_count += len(node.relations)
        payload_bytes += len(canonical_json_bytes(dict(node.payload)))
        max_depth = max(max_depth, depth)
        counts[node.level.name] += 1
        stack.extend((child, depth + 1) for child in node.children)
    return GeneticProgramStats(
        node_count=node_count,
        relation_count=relation_count,
        payload_bytes=payload_bytes,
        max_depth=max_depth,
        level_counts=tuple((level.name, counts[level.name]) for level in GeneticLevel),
    )


@dataclass(frozen=True, slots=True)
class MutationPhenotype:
    genetic_ir_id: str
    allowed_loci: tuple[int, ...]
    mutation_budget: int
    route_stride: int
    route_direction: int
    stats: GeneticProgramStats
    schema: str = PHENOTYPE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != PHENOTYPE_SCHEMA:
            raise ValueError("unsupported mutation phenotype schema")
        if len(self.genetic_ir_id) != 64:
            raise ValueError("genetic_ir_id must be a 32-byte hex digest")
        int(self.genetic_ir_id, 16)
        if not self.allowed_loci:
            raise ValueError("allowed_loci must not be empty")
        if tuple(sorted(set(self.allowed_loci))) != self.allowed_loci:
            raise ValueError("allowed_loci must be unique and sorted")
        if any(index < 0 or index >= DIM for index in self.allowed_loci):
            raise ValueError("allowed_loci index out of range")
        if self.mutation_budget < 1 or self.mutation_budget > len(self.allowed_loci):
            raise ValueError("mutation_budget outside allowed_loci")
        if self.route_stride < 1 or self.route_stride >= DIM:
            raise ValueError("route_stride outside 1..35")
        if self.route_direction not in {-1, 1}:
            raise ValueError("route_direction must be -1 or +1")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "genetic_ir_id": self.genetic_ir_id,
            "allowed_loci": list(self.allowed_loci),
            "mutation_budget": self.mutation_budget,
            "route_stride": self.route_stride,
            "route_direction": self.route_direction,
            "stats": self.stats.to_dict(),
            "authority": {
                "search_control_only": True,
                "cryptographic_entropy": False,
                "security_admission": False,
            },
        }

    @property
    def commitment(self) -> str:
        return blake2b256(canonical_json_bytes(self.to_dict()))


def _unique_loci(seed: bytes, count: int) -> tuple[int, ...]:
    selected: list[int] = []
    counter = 0
    while len(selected) < count:
        block = hashlib.shake_256(
            b"DNCrypt/v0.6.1/genetic-compiler/loci|" + seed + counter.to_bytes(4, "big")
        ).digest(64)
        for value in block:
            locus = value % DIM
            if locus not in selected:
                selected.append(locus)
                if len(selected) == count:
                    break
        counter += 1
    return tuple(sorted(selected))


def compile_genetic_program(program: GeneticIRNode) -> MutationPhenotype:
    """Compile public Genetic IR structure into a bounded search phenotype.

    The compiler is deterministic and intentionally public.  Its output is a
    search constraint, not an entropy source.
    """

    stats = program_stats(program)
    canonical = canonical_json_bytes(program.to_dict())
    seed = hashlib.shake_256(
        b"DNCrypt/v0.6.1/genetic-compiler|" + canonical
    ).digest(96)

    structural_width = 1 + stats.node_count // 4 + stats.relation_count // 2
    allowed_count = max(1, min(DIM, structural_width))
    allowed = _unique_loci(seed[:64], allowed_count)

    # Budget grows more slowly than structural width so grammar can widen the
    # candidate surface without allowing every locus to change at once.
    budget = max(1, min(len(allowed), 1 + stats.relation_count + stats.max_depth // 2))
    stride = 1 + (seed[64] % (DIM - 1))
    direction = -1 if seed[65] & 1 else 1

    return MutationPhenotype(
        genetic_ir_id=program.semantic_id,
        allowed_loci=allowed,
        mutation_budget=budget,
        route_stride=stride,
        route_direction=direction,
        stats=stats,
    )


@dataclass(frozen=True, slots=True)
class GeneticMutationBinding:
    parent_genome_id: str
    child_genome_id: str
    genetic_ir_id: str
    phenotype_commitment: str
    fresh_entropy_commitment: str
    changed_loci: tuple[int, ...]
    schema: str = COMPILER_SCHEMA

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "parent_genome_id": self.parent_genome_id,
            "child_genome_id": self.child_genome_id,
            "genetic_ir_id": self.genetic_ir_id,
            "phenotype_commitment": self.phenotype_commitment,
            "fresh_entropy_commitment": self.fresh_entropy_commitment,
            "changed_loci": list(self.changed_loci),
            "authority": {
                "changes_frozen_aead": False,
                "security_admission": False,
                "fresh_entropy_required": True,
            },
        }

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(self.to_dict()))


def mutate_genome_with_program(
    parent: CipherGenome,
    program: GeneticIRNode,
    *,
    entropy: bytes,
) -> tuple[CipherGenome, GeneticMutationBinding]:
    """Generate one grammar-shaped candidate while requiring fresh entropy."""

    raw_entropy = bytes(entropy)
    if len(raw_entropy) < 32:
        raise ValueError("fresh mutation entropy must contain at least 32 bytes")

    phenotype = compile_genetic_program(program)
    # The public phenotype commitment is domain separation, not entropy.
    bound_entropy = hashlib.shake_256(
        b"DNCrypt/v0.6.1/genetic-mutation/fresh|"
        + raw_entropy
        + bytes.fromhex(phenotype.commitment)
    ).digest(max(64, len(raw_entropy)))

    unconstrained = mutate_genome(parent, bound_entropy)
    allowed = set(phenotype.allowed_loci)
    changed = [
        index
        for index in phenotype.allowed_loci
        if unconstrained.operator_vector[index] != parent.operator_vector[index]
    ]

    # Deterministically choose no more than the phenotype budget using the fresh
    # entropy ordering.  If the underlying mutator happened not to touch any
    # admitted locus, force one bounded non-zero delta using fresh entropy.
    order_seed = hashlib.shake_256(
        b"DNCrypt/v0.6.1/genetic-mutation/order|" + raw_entropy
    ).digest(DIM * 2)
    ranking = sorted(
        phenotype.allowed_loci,
        key=lambda index: (
            order_seed[2 * index],
            order_seed[2 * index + 1],
            index,
        ),
    )
    keep = set([index for index in ranking if index in changed][: phenotype.mutation_budget])
    if not keep:
        keep = {ranking[0]}

    operator = list(parent.operator_vector)
    for index in keep:
        candidate_value = unconstrained.operator_vector[index]
        if candidate_value == parent.operator_vector[index]:
            delta = 1 + (order_seed[index] % 255)
            candidate_value = (parent.operator_vector[index] + delta) & 0xFF
        operator[index] = candidate_value

    # Route search remains a permutation.  We start from the underlying fresh
    # entropy mutation then apply a public phenotype rotation; this changes search
    # topology without creating key/nonce entropy.
    route = list(unconstrained.route)
    shift = phenotype.route_direction * phenotype.route_stride
    shift %= DIM
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
        index
        for index in range(DIM)
        if child.operator_vector[index] != parent.operator_vector[index]
    )
    if not changed_loci or any(index not in allowed for index in changed_loci):
        raise RuntimeError("genetic compiler mutation escaped its admitted locus set")

    binding = GeneticMutationBinding(
        parent_genome_id=parent.genome_id,
        child_genome_id=child.genome_id,
        genetic_ir_id=program.semantic_id,
        phenotype_commitment=phenotype.commitment,
        fresh_entropy_commitment=blake2b256(raw_entropy),
        changed_loci=changed_loci,
    )
    return child, binding


def vectorized_genetic_population(
    parent: CipherGenome,
    program: GeneticIRNode,
    population_size: int,
    *,
    entropy: bytes,
) -> tuple[tuple[CipherGenome, ...], tuple[GeneticMutationBinding, ...], str]:
    if population_size < 1:
        raise ValueError("population_size must be positive")
    raw = bytes(entropy)
    if len(raw) < 32:
        raise ValueError("fresh mutation entropy must contain at least 32 bytes")

    genomes: list[CipherGenome] = []
    bindings: list[GeneticMutationBinding] = []
    for index in range(population_size):
        child_entropy = hashlib.shake_256(
            b"DNCrypt/v0.6.1/genetic-population|"
            + raw
            + index.to_bytes(8, "big")
        ).digest(64)
        child, binding = mutate_genome_with_program(parent, program, entropy=child_entropy)
        genomes.append(child)
        bindings.append(binding)

    population = tuple(genomes)
    if len({genome.genome_id for genome in population}) != len(population):
        raise RuntimeError("genetic population produced duplicate genome ids")
    return population, tuple(bindings), population_commitment(population)


__all__ = [
    "COMPILER_SCHEMA",
    "DICTIONARY_SCHEMA",
    "GeneticMutationBinding",
    "GeneticProgramStats",
    "MutationPhenotype",
    "compile_genetic_program",
    "genetic_dictionary_v1",
    "mutate_genome_with_program",
    "program_stats",
    "vectorized_genetic_population",
]
