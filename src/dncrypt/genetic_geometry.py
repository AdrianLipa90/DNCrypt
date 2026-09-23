"""Hierarchical diagnostic geometry and resource guards for Genetic IR v0.6.1."""
from __future__ import annotations

from dataclasses import dataclass
import cmath
import math
from typing import Any, Mapping, Sequence

from .genetic_ir import GeneticIRNode, GeneticLevel, compile_ir_to_phase36
from .util import canonical_json_bytes

DIM = 36


@dataclass(frozen=True, slots=True)
class GeneticResourceLimits:
    max_nodes: int = 4096
    max_relations: int = 8192
    max_depth: int = 8
    max_children_per_node: int = 1024
    max_payload_bytes: int = 4 * 1024 * 1024

    def __post_init__(self) -> None:
        for name, value in (
            ("max_nodes", self.max_nodes),
            ("max_relations", self.max_relations),
            ("max_depth", self.max_depth),
            ("max_children_per_node", self.max_children_per_node),
            ("max_payload_bytes", self.max_payload_bytes),
        ):
            if value < 1:
                raise ValueError(name + " must be positive")


DEFAULT_RESOURCE_LIMITS = GeneticResourceLimits()


def bounded_genetic_ir_from_mapping(
    value: Mapping[str, Any],
    *,
    limits: GeneticResourceLimits = DEFAULT_RESOURCE_LIMITS,
) -> GeneticIRNode:
    """Preflight raw nested input iteratively before recursive typed parsing."""

    if not isinstance(value, Mapping):
        raise ValueError("Genetic IR root must be an object")
    stack: list[tuple[Mapping[str, Any], int]] = [(value, 0)]
    nodes = 0
    relations = 0
    payload_bytes = 0

    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > limits.max_nodes:
            raise ValueError("Genetic IR node budget exceeded")
        if depth > limits.max_depth:
            raise ValueError("Genetic IR depth budget exceeded")

        payload = node.get("payload", {})
        if not isinstance(payload, Mapping):
            raise ValueError("Genetic IR payload must be an object")
        payload_bytes += len(canonical_json_bytes(dict(payload)))
        if payload_bytes > limits.max_payload_bytes:
            raise ValueError("Genetic IR payload budget exceeded")

        children = node.get("children", ())
        rels = node.get("relations", ())
        if not isinstance(children, Sequence) or isinstance(children, (str, bytes)):
            raise ValueError("Genetic IR children must be an array")
        if not isinstance(rels, Sequence) or isinstance(rels, (str, bytes)):
            raise ValueError("Genetic IR relations must be an array")
        if len(children) > limits.max_children_per_node:
            raise ValueError("Genetic IR child fanout budget exceeded")
        relations += len(rels)
        if relations > limits.max_relations:
            raise ValueError("Genetic IR relation budget exceeded")

        for child in children:
            if not isinstance(child, Mapping):
                raise ValueError("every Genetic IR child must be an object")
            stack.append((child, depth + 1))

    return GeneticIRNode.from_mapping(value)


@dataclass(frozen=True, slots=True)
class GeneticPhaseNode:
    path: tuple[str, ...]
    unit_id: str
    level: str
    semantic_id: str
    phase36: tuple[float, ...]

    @property
    def depth(self) -> int:
        return len(self.path) - 1


def genetic_phase_tree(program: GeneticIRNode) -> tuple[GeneticPhaseNode, ...]:
    """Return one deterministic 36D diagnostic projection per IR node."""

    out: list[GeneticPhaseNode] = []
    stack: list[tuple[GeneticIRNode, tuple[str, ...]]] = [
        (program, (program.unit_id,))
    ]
    while stack:
        node, path = stack.pop()
        phase = tuple(float(x) for x in compile_ir_to_phase36(node))
        if len(phase) != DIM or not all(math.isfinite(x) for x in phase):
            raise ValueError("Genetic IR node phase must be finite 36D")
        out.append(
            GeneticPhaseNode(
                path=path,
                unit_id=node.unit_id,
                level=node.level.name,
                semantic_id=node.semantic_id,
                phase36=phase,
            )
        )
        for child in reversed(node.children):
            stack.append((child, path + (child.unit_id,)))
    return tuple(out)


def _coherence(vectors: Sequence[tuple[float, ...]]) -> float:
    if not vectors:
        return 0.0
    per_dimension = []
    for index in range(DIM):
        mean = sum(cmath.exp(1j * vector[index]) for vector in vectors) / len(vectors)
        per_dimension.append(abs(mean))
    return float(sum(per_dimension) / DIM)


def level_phase_coherence(program: GeneticIRNode) -> dict[str, float]:
    """Compute local order parameters per grammar level.

    This is diagnostic geometry only.  It is not a security-admission metric.
    """

    grouped: dict[str, list[tuple[float, ...]]] = {
        level.name: [] for level in GeneticLevel
    }
    for record in genetic_phase_tree(program):
        grouped[record.level].append(record.phase36)
    return {
        level.name: _coherence(grouped[level.name])
        for level in GeneticLevel
        if grouped[level.name]
    }


def parent_child_phase_distance(program: GeneticIRNode) -> dict[str, float]:
    """RMS wrapped distance for each non-root node against its immediate parent."""

    result: dict[str, float] = {}
    stack: list[GeneticIRNode] = [program]
    while stack:
        parent = stack.pop()
        parent_phase = compile_ir_to_phase36(parent)
        for child in parent.children:
            child_phase = compile_ir_to_phase36(child)
            delta = [
                (b - a + math.pi) % (2.0 * math.pi) - math.pi
                for a, b in zip(parent_phase, child_phase)
            ]
            result[child.semantic_id] = math.sqrt(
                sum(value * value for value in delta) / DIM
            )
            stack.append(child)
    return result


__all__ = [
    "DEFAULT_RESOURCE_LIMITS",
    "GeneticPhaseNode",
    "GeneticResourceLimits",
    "bounded_genetic_ir_from_mapping",
    "genetic_phase_tree",
    "level_phase_coherence",
    "parent_child_phase_distance",
]
