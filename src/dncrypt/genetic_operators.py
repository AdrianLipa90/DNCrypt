"""Bounded structural Genetic IR operators for DNCrypt v0.6.2.

These operators mutate the research/control representation only. They never derive
keys, salts, nonces or evaluator credentials, and every result remains
CANDIDATE_ONLY until admitted by the existing security evidence pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import re
from typing import Callable

from .genetic_ir import GeneticIRNode, GeneticLevel, GeneticRelation
from .util import blake2b256, canonical_json_bytes

OPERATOR_SCHEMA = "dncrypt.genetic-operator/v0.6.2-candidate"
_TAG_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")


@dataclass(frozen=True, slots=True)
class GeneticOperatorReceipt:
    operation: str
    target_id: str
    parent_semantic_id: str
    child_semantic_id: str
    operand_commitment: str
    schema: str = OPERATOR_SCHEMA

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "operation": self.operation,
            "target_id": self.target_id,
            "parent_semantic_id": self.parent_semantic_id,
            "child_semantic_id": self.child_semantic_id,
            "operand_commitment": self.operand_commitment,
            "authority": {
                "candidate_only": True,
                "security_admission": False,
                "cryptographic_entropy": False,
                "changes_frozen_aead": False,
            },
        }

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(self.to_dict()))


def _validate_tag(tag: str) -> None:
    if not isinstance(tag, str) or _TAG_RE.fullmatch(tag) is None:
        raise ValueError("operator tag must match [A-Za-z0-9._-]{1,32}")


def _match_count(program: GeneticIRNode, target_id: str) -> int:
    count = 0
    stack = [program]
    while stack:
        node = stack.pop()
        if node.unit_id == target_id:
            count += 1
        stack.extend(node.children)
    return count


def _rewrite_unique(
    program: GeneticIRNode,
    target_id: str,
    transform: Callable[[GeneticIRNode], GeneticIRNode],
) -> GeneticIRNode:
    count = _match_count(program, target_id)
    if count == 0:
        raise KeyError(f"unknown Genetic IR unit: {target_id}")
    if count != 1:
        raise ValueError("operator target_id must be globally unique")

    def walk(node: GeneticIRNode) -> GeneticIRNode:
        if node.unit_id == target_id:
            updated = transform(node)
            if not isinstance(updated, GeneticIRNode):
                raise TypeError("operator transform must return GeneticIRNode")
            return updated
        if not node.children:
            return node
        children = tuple(walk(child) for child in node.children)
        return node if children == node.children else replace(node, children=children)

    return walk(program)


def _find_unique(program: GeneticIRNode, target_id: str) -> GeneticIRNode:
    matches: list[GeneticIRNode] = []
    stack = [program]
    while stack:
        node = stack.pop()
        if node.unit_id == target_id:
            matches.append(node)
        stack.extend(node.children)
    if not matches:
        raise KeyError(f"unknown Genetic IR unit: {target_id}")
    if len(matches) != 1:
        raise ValueError("operator target_id must be globally unique")
    return matches[0]


def _clone_with_tag(node: GeneticIRNode, tag: str) -> GeneticIRNode:
    """Clone a subtree while namespacing every unit id and local relation endpoint."""

    _validate_tag(tag)
    cloned_children = tuple(_clone_with_tag(child, tag) for child in node.children)
    child_map = {
        original.unit_id: cloned.unit_id
        for original, cloned in zip(node.children, cloned_children)
    }
    cloned_relations = tuple(
        GeneticRelation(
            source_id=child_map[relation.source_id],
            target_id=child_map[relation.target_id],
            distance_bp=relation.distance_bp,
            relative_phase_rad=relation.relative_phase_rad,
            orientation=relation.orientation,
            relation_type=relation.relation_type,
        )
        for relation in node.relations
    )
    return GeneticIRNode(
        unit_id=f"{node.unit_id}__{tag}",
        level=node.level,
        payload=dict(node.payload),
        children=cloned_children,
        relations=cloned_relations,
    )


def _receipt(
    operation: str,
    target_id: str,
    parent: GeneticIRNode,
    child: GeneticIRNode,
    details: dict[str, object],
) -> GeneticOperatorReceipt:
    return GeneticOperatorReceipt(
        operation=operation,
        target_id=target_id,
        parent_semantic_id=parent.semantic_id,
        child_semantic_id=child.semantic_id,
        operand_commitment=blake2b256(canonical_json_bytes(details)),
    )


def duplicate_child(
    program: GeneticIRNode,
    target_id: str,
    child_index: int,
    *,
    tag: str,
) -> tuple[GeneticIRNode, GeneticOperatorReceipt]:
    """Duplicate one immediate child with a fully namespaced subtree.

    Existing relations are intentionally not copied onto the duplicate. This
    avoids silently inventing semantic edges.
    """

    _validate_tag(tag)

    def transform(node: GeneticIRNode) -> GeneticIRNode:
        if node.level is GeneticLevel.KAKU:
            raise ValueError("KAKU has no child to duplicate")
        if child_index < 0 or child_index >= len(node.children):
            raise IndexError("duplicate child index out of range")
        clone = _clone_with_tag(node.children[child_index], f"dup_{tag}")
        ids = {child.unit_id for child in node.children}
        if clone.unit_id in ids:
            raise ValueError("duplicate operator would collide with an existing unit_id")
        children = list(node.children)
        children.insert(child_index + 1, clone)
        return replace(node, children=tuple(children))

    child = _rewrite_unique(program, target_id, transform)
    return child, _receipt(
        "DUPLICATE_CHILD",
        target_id,
        program,
        child,
        {"child_index": child_index, "tag": tag},
    )


def invert_children(
    program: GeneticIRNode,
    target_id: str,
    start: int,
    stop: int,
) -> tuple[GeneticIRNode, GeneticOperatorReceipt]:
    """Reverse a non-empty child slice [start:stop]."""

    def transform(node: GeneticIRNode) -> GeneticIRNode:
        if node.level is GeneticLevel.KAKU:
            raise ValueError("KAKU has no children to invert")
        if start < 0 or stop > len(node.children) or stop - start < 2:
            raise IndexError("inversion must cover at least two valid children")
        children = list(node.children)
        children[start:stop] = reversed(children[start:stop])
        return replace(node, children=tuple(children))

    child = _rewrite_unique(program, target_id, transform)
    return child, _receipt(
        "INVERT_CHILDREN",
        target_id,
        program,
        child,
        {"start": start, "stop": stop},
    )


def translocate_child(
    program: GeneticIRNode,
    target_id: str,
    source_index: int,
    destination_index: int,
) -> tuple[GeneticIRNode, GeneticOperatorReceipt]:
    """Move one immediate child to a new position within the same typed unit."""

    def transform(node: GeneticIRNode) -> GeneticIRNode:
        if node.level is GeneticLevel.KAKU:
            raise ValueError("KAKU has no child to translocate")
        n = len(node.children)
        if source_index < 0 or source_index >= n:
            raise IndexError("translocation source index out of range")
        if destination_index < 0 or destination_index >= n:
            raise IndexError("translocation destination index out of range")
        if source_index == destination_index:
            raise ValueError("translocation must change child position")
        children = list(node.children)
        moved = children.pop(source_index)
        children.insert(destination_index, moved)
        return replace(node, children=tuple(children))

    child = _rewrite_unique(program, target_id, transform)
    return child, _receipt(
        "TRANSLOCATE_CHILD",
        target_id,
        program,
        child,
        {"source_index": source_index, "destination_index": destination_index},
    )


def recombine_children(
    left: GeneticIRNode,
    right: GeneticIRNode,
    target_id: str,
    *,
    left_cut: int,
    right_cut: int,
    tag: str,
) -> tuple[GeneticIRNode, GeneticOperatorReceipt]:
    """Crossover two same-level units at one uniquely named target.

    Left prefix children are retained. Right suffix children are copied with a
    namespace. Relations are retained only when both endpoints survive inside
    their original side; no synthetic cross-boundary relation is invented.
    """

    _validate_tag(tag)
    left_target = _find_unique(left, target_id)
    right_target = _find_unique(right, target_id)
    if left_target.level is not right_target.level:
        raise ValueError("recombination targets must have the same GeneticLevel")
    if left_target.level is GeneticLevel.KAKU:
        raise ValueError("KAKU cannot be recombined by child crossover")
    if not 0 <= left_cut <= len(left_target.children):
        raise IndexError("left_cut out of range")
    if not 0 <= right_cut <= len(right_target.children):
        raise IndexError("right_cut out of range")

    left_children = left_target.children[:left_cut]
    donor_original = right_target.children[right_cut:]
    donor_children = tuple(
        _clone_with_tag(child, f"xo_{tag}") for child in donor_original
    )
    combined = left_children + donor_children
    if not combined:
        raise ValueError("recombination cannot create an empty non-atomic unit")

    left_ids = {child.unit_id for child in left_children}
    left_relations = tuple(
        rel
        for rel in left_target.relations
        if rel.source_id in left_ids and rel.target_id in left_ids
    )

    donor_map = {
        original.unit_id: cloned.unit_id
        for original, cloned in zip(donor_original, donor_children)
    }
    donor_ids = set(donor_map)
    donor_relations = tuple(
        GeneticRelation(
            source_id=donor_map[rel.source_id],
            target_id=donor_map[rel.target_id],
            distance_bp=rel.distance_bp,
            relative_phase_rad=rel.relative_phase_rad,
            orientation=rel.orientation,
            relation_type=rel.relation_type,
        )
        for rel in right_target.relations
        if rel.source_id in donor_ids and rel.target_id in donor_ids
    )

    replacement = replace(
        left_target,
        children=combined,
        relations=left_relations + donor_relations,
    )
    child = _rewrite_unique(left, target_id, lambda _: replacement)
    return child, _receipt(
        "RECOMBINE_CHILDREN",
        target_id,
        left,
        child,
        {
            "right_parent_semantic_id": right.semantic_id,
            "left_cut": left_cut,
            "right_cut": right_cut,
            "tag": tag,
        },
    )


__all__ = [
    "OPERATOR_SCHEMA",
    "GeneticOperatorReceipt",
    "duplicate_child",
    "invert_children",
    "recombine_children",
    "translocate_child",
]
