"""DNCrypt Genetic IR v0.6.

This module provides a typed, canonical intermediate representation compatible
with the CIELingo genomic-grammar research contract.  It is deliberately kept
outside the frozen DNCrypt v0.2 AEAD primitive: Genetic IR may steer diagnostics,
selection and provenance, but it is not key/nonce entropy and does not gain
security-admission authority merely by existing.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import IntEnum
import hashlib
import math
from typing import Any, Mapping, Sequence

from .util import blake2b256, canonical_json_bytes

IR_SCHEMA = "DNCRYPT_GENETIC_IR_V0_6"
CIELINGO_SCHEMA = "CIELINGO_GENOMIC_GRAMMAR_V0_1"
SOURCE_BINDING_STATUS = "CANDIDATE_RESEARCH_BINDING"
CIELINGO_SOURCE_REPOSITORY = "AdrianLipa90/cielingo-canon"
CIELINGO_SOURCE_BRANCH = "feature/cielingo-gremlin-genomic-grammar-v01-20260922"
CIELINGO_SOURCE_COMMIT = "59297d21fba563e17c7a656e0cb3139a5a302ee5"
CIELINGO_GRAMMAR_BLOB_SHA = "f6e9ec64ad993b83821c9709c194dcd9dbb2aa5b"
CIELINGO_PARSER_BLOB_SHA = "0d464e124e5adf753138fba3e417f77a832e1406"

DIM = 36
TAU = 2.0 * math.pi


class GeneticLevel(IntEnum):
    KAKU = 0
    RADICAL = 1
    CONCEPT = 2
    SENTENCE = 3
    PARAGRAPH = 4
    CHAPTER = 5
    BOOK = 6


@dataclass(frozen=True, slots=True)
class GeneticRelation:
    source_id: str
    target_id: str
    distance_bp: float
    relative_phase_rad: float
    orientation: str = "unspecified"
    relation_type: str = "relational"

    def __post_init__(self) -> None:
        if not self.source_id or not self.target_id:
            raise ValueError("source_id and target_id are required")
        if self.source_id == self.target_id:
            raise ValueError("self-relations are not admitted")
        if not math.isfinite(self.distance_bp):
            raise ValueError("distance_bp must be finite")
        if not math.isfinite(self.relative_phase_rad):
            raise ValueError("relative_phase_rad must be finite")
        if not self.orientation:
            raise ValueError("orientation must be non-empty")
        if not self.relation_type:
            raise ValueError("relation_type must be non-empty")

    def to_dict(self) -> dict[str, object]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "distance_bp": float(self.distance_bp),
            "relative_phase_rad": float(self.relative_phase_rad % TAU),
            "orientation": self.orientation,
            "relation_type": self.relation_type,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "GeneticRelation":
        allowed = {
            "source_id",
            "target_id",
            "distance_bp",
            "relative_phase_rad",
            "orientation",
            "relation_type",
            "chromatin_context",
        }
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"unknown relation fields: {sorted(unknown)}")
        # CIELingo v0.1 calls the optional context chromatin_context.  DNCrypt
        # keeps it out of the executable relation semantics; if present, it is
        # represented as a typed relation tag rather than silently discarded.
        relation_type = value.get("relation_type", "relational")
        context = value.get("chromatin_context")
        if context is not None:
            relation_type = f"{relation_type}:context:{context}"
        return cls(
            source_id=str(value["source_id"]),
            target_id=str(value["target_id"]),
            distance_bp=float(value["distance_bp"]),
            relative_phase_rad=float(value["relative_phase_rad"]),
            orientation=str(value.get("orientation", "unspecified")),
            relation_type=str(relation_type),
        )


@dataclass(frozen=True, slots=True)
class GeneticIRNode:
    unit_id: str
    level: GeneticLevel
    payload: Mapping[str, Any] = field(default_factory=dict)
    children: tuple["GeneticIRNode", ...] = field(default_factory=tuple)
    relations: tuple[GeneticRelation, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.unit_id:
            raise ValueError("unit_id is required")
        if not isinstance(self.level, GeneticLevel):
            raise TypeError("level must be GeneticLevel")

        # Fail closed on values that cannot be represented canonically.
        canonical_json_bytes(dict(self.payload))

        if self.level is GeneticLevel.KAKU:
            if self.children:
                raise ValueError("KAKU is atomic and cannot contain children")
            if self.relations:
                raise ValueError("KAKU cannot contain relations")
            return

        if not self.children:
            raise ValueError(f"{self.level.name} must contain at least one child")

        expected = GeneticLevel(int(self.level) - 1)
        child_ids = [child.unit_id for child in self.children]
        if len(child_ids) != len(set(child_ids)):
            raise ValueError("child unit_id values must be unique")
        for child in self.children:
            if child.level is not expected:
                raise ValueError(
                    f"{self.level.name} children must be {expected.name}"
                )

        endpoints = set(child_ids)
        seen_relations: set[tuple[str, str, str]] = set()
        for relation in self.relations:
            if relation.source_id not in endpoints or relation.target_id not in endpoints:
                raise ValueError("relations must connect immediate children")
            key = (
                relation.source_id,
                relation.target_id,
                relation.relation_type,
            )
            if key in seen_relations:
                raise ValueError("duplicate relation")
            seen_relations.add(key)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": IR_SCHEMA,
            "source_schema": CIELINGO_SCHEMA,
            "unit_id": self.unit_id,
            "level": self.level.name,
            "payload": dict(self.payload),
            "children": [child.to_dict() for child in self.children],
            "relations": [relation.to_dict() for relation in self.relations],
            "authority": {
                "diagnostic_only": True,
                "security_admission": False,
                "changes_frozen_aead": False,
            },
        }

    @property
    def semantic_id(self) -> str:
        return blake2b256(canonical_json_bytes(self.to_dict()))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "GeneticIRNode":
        allowed = {
            "schema",
            "source_schema",
            "unit_id",
            "level",
            "payload",
            "children",
            "relations",
            "authority",
            "epistemic_status",
            "biological_equivalence_claim",
        }
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"unknown Genetic IR fields: {sorted(unknown)}")

        schema = value.get("schema")
        if schema not in {IR_SCHEMA, CIELINGO_SCHEMA}:
            raise ValueError(f"unsupported Genetic IR schema: {schema!r}")

        level_raw = value.get("level")
        try:
            level = GeneticLevel[str(level_raw)]
        except (KeyError, TypeError) as exc:
            raise ValueError(f"unsupported Genetic IR level: {level_raw!r}") from exc

        payload = value.get("payload", {})
        children = value.get("children", ())
        relations = value.get("relations", ())
        if not isinstance(payload, Mapping):
            raise ValueError("payload must be an object")
        if not isinstance(children, Sequence) or isinstance(children, (str, bytes)):
            raise ValueError("children must be an array")
        if not isinstance(relations, Sequence) or isinstance(relations, (str, bytes)):
            raise ValueError("relations must be an array")

        child_nodes = tuple(
            cls.from_mapping(child)
            for child in children
            if isinstance(child, Mapping)
        )
        if len(child_nodes) != len(children):
            raise ValueError("every child must be an object")

        relation_nodes = tuple(
            GeneticRelation.from_mapping(relation)
            for relation in relations
            if isinstance(relation, Mapping)
        )
        if len(relation_nodes) != len(relations):
            raise ValueError("every relation must be an object")

        return cls(
            unit_id=str(value.get("unit_id", "")),
            level=level,
            payload=dict(payload),
            children=child_nodes,
            relations=relation_nodes,
        )


def import_cielingo_genomic_unit(value: Mapping[str, Any]) -> GeneticIRNode:
    """Import exact CIELingo v0.1 serialized units into DNCrypt Genetic IR."""

    if value.get("schema") != CIELINGO_SCHEMA:
        raise ValueError("CIELingo genomic unit must use the pinned v0.1 schema")
    if value.get("biological_equivalence_claim") not in {None, False}:
        raise ValueError("biological-equivalence promotion is not admitted")
    return GeneticIRNode.from_mapping(value)


def source_binding() -> dict[str, object]:
    return {
        "status": SOURCE_BINDING_STATUS,
        "repository": CIELINGO_SOURCE_REPOSITORY,
        "branch": CIELINGO_SOURCE_BRANCH,
        "commit": CIELINGO_SOURCE_COMMIT,
        "source_schema": CIELINGO_SCHEMA,
        "grammar_blob_sha": CIELINGO_GRAMMAR_BLOB_SHA,
        "parser_blob_sha": CIELINGO_PARSER_BLOB_SHA,
        "canon_claim": False,
    }


def compile_ir_to_phase36(program: GeneticIRNode) -> tuple[float, ...]:
    """Deterministic diagnostic projection; never use as cryptographic entropy."""

    seed = hashlib.shake_256(
        b"DNCrypt/v0.6/genetic-ir/phase36|" + canonical_json_bytes(program.to_dict())
    ).digest(DIM * 8)
    out = []
    denominator = float((1 << 64) - 1)
    for i in range(DIM):
        word = int.from_bytes(seed[i * 8 : (i + 1) * 8], "little")
        out.append((word / denominator) * TAU)
    return tuple(out)


def _rewrite_node(
    node: GeneticIRNode,
    target_id: str,
    transform,
) -> GeneticIRNode:
    if node.unit_id == target_id:
        updated = transform(node)
        if not isinstance(updated, GeneticIRNode):
            raise TypeError("mutation transform must return GeneticIRNode")
        return updated
    if not node.children:
        return node
    children = tuple(
        _rewrite_node(child, target_id, transform)
        for child in node.children
    )
    if children == node.children:
        return node
    return replace(node, children=children)


@dataclass(frozen=True, slots=True)
class GeneticMutationReceipt:
    operation: str
    target_id: str
    parent_semantic_id: str
    child_semantic_id: str
    diagnostic_only: bool = True
    security_admission: bool = False


def rewrite_payload(
    program: GeneticIRNode,
    target_id: str,
    updates: Mapping[str, Any],
) -> tuple[GeneticIRNode, GeneticMutationReceipt]:
    """Rewrite payload fields while preserving the complete typed hierarchy."""

    canonical_json_bytes(dict(updates))
    found = False

    def transform(node: GeneticIRNode) -> GeneticIRNode:
        nonlocal found
        found = True
        payload = dict(node.payload)
        payload.update(dict(updates))
        return replace(node, payload=payload)

    child = _rewrite_node(program, target_id, transform)
    if not found:
        raise KeyError(f"unknown Genetic IR unit: {target_id}")
    return child, GeneticMutationReceipt(
        "REWRITE_PAYLOAD",
        target_id,
        program.semantic_id,
        child.semantic_id,
    )


def swap_adjacent_children(
    program: GeneticIRNode,
    target_id: str,
    left_index: int,
) -> tuple[GeneticIRNode, GeneticMutationReceipt]:
    """Swap two adjacent children without changing relation endpoints."""

    found = False

    def transform(node: GeneticIRNode) -> GeneticIRNode:
        nonlocal found
        found = True
        if node.level is GeneticLevel.KAKU:
            raise ValueError("KAKU has no children to swap")
        if left_index < 0 or left_index + 1 >= len(node.children):
            raise IndexError("adjacent-child swap index out of range")
        children = list(node.children)
        children[left_index], children[left_index + 1] = (
            children[left_index + 1],
            children[left_index],
        )
        return replace(node, children=tuple(children))

    child = _rewrite_node(program, target_id, transform)
    if not found:
        raise KeyError(f"unknown Genetic IR unit: {target_id}")
    return child, GeneticMutationReceipt(
        "SWAP_ADJACENT_CHILDREN",
        target_id,
        program.semantic_id,
        child.semantic_id,
    )


def delete_child(
    program: GeneticIRNode,
    target_id: str,
    child_index: int,
) -> tuple[GeneticIRNode, GeneticMutationReceipt]:
    """Delete one child and any incident relations, never creating an empty unit."""

    found = False

    def transform(node: GeneticIRNode) -> GeneticIRNode:
        nonlocal found
        found = True
        if node.level is GeneticLevel.KAKU:
            raise ValueError("KAKU has no children to delete")
        if len(node.children) <= 1:
            raise ValueError("mutation would create an empty non-atomic unit")
        if child_index < 0 or child_index >= len(node.children):
            raise IndexError("child deletion index out of range")
        removed = node.children[child_index].unit_id
        children = tuple(
            child for i, child in enumerate(node.children) if i != child_index
        )
        relations = tuple(
            relation
            for relation in node.relations
            if relation.source_id != removed and relation.target_id != removed
        )
        return replace(node, children=children, relations=relations)

    child = _rewrite_node(program, target_id, transform)
    if not found:
        raise KeyError(f"unknown Genetic IR unit: {target_id}")
    return child, GeneticMutationReceipt(
        "DELETE_CHILD",
        target_id,
        program.semantic_id,
        child.semantic_id,
    )
