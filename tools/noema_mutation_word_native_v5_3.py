from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from dncrypt.genetic_ir import GeneticIRNode
from dncrypt.genetic_operators import (
    duplicate_child,
    invert_children,
    translocate_child,
    recombine_children,
)
from noema_telekom.mutation_word_v5 import MutationToken, MutationWord, OPERATORS

ANCHORS = ("r1", "r2", "r3", "r4")
INVERT_PAIRS = (
    ("r1", "r2"), ("r1", "r3"), ("r1", "r4"),
    ("r2", "r3"), ("r2", "r4"), ("r3", "r4"),
)
TRANSLOCATE_PAIRS = tuple((a, b) for a in ANCHORS for b in ANCHORS if a != b)
SCHEMA = "DNCRYPT_NOEMA_MUTATION_WORD_NATIVE_V5_3"


class NativeWordV53Error(ValueError):
    pass


def _index(program: GeneticIRNode, unit_id: str) -> int:
    matches = [i for i, child in enumerate(program.children) if child.unit_id == unit_id]
    if len(matches) != 1:
        raise NativeWordV53Error(f"expected exactly one anchor {unit_id!r}, got {len(matches)}")
    return matches[0]


def semantic_binding(token: MutationToken) -> dict[str, object]:
    u = int(token.parameter_u64)
    op = token.operation
    if op == "DUPLICATE_CHILD":
        return {
            "operation": op,
            "anchor": ANCHORS[u % len(ANCHORS)],
            "tag": f"d{u & 0xffffffff:08x}",
        }
    if op == "INVERT_CHILDREN":
        a, b = INVERT_PAIRS[u % len(INVERT_PAIRS)]
        return {"operation": op, "left_anchor": a, "right_anchor": b}
    if op == "TRANSLOCATE_CHILD":
        source, destination = TRANSLOCATE_PAIRS[u % len(TRANSLOCATE_PAIRS)]
        return {
            "operation": op,
            "source_anchor": source,
            "destination_anchor": destination,
        }
    if op == "RECOMBINE_CHILDREN":
        return {
            "operation": op,
            "right_cut": u % len(ANCHORS),
            "tag": f"r{u & 0xffffffff:08x}",
            "left_policy": "KEEP_ALL_CURRENT_LEFT_CHILDREN",
        }
    raise NativeWordV53Error(f"unsupported operation {op!r}")


def semantic_parameter_map(word: MutationWord) -> dict[str, dict[str, object]]:
    return {token.operation: semantic_binding(token) for token in word.tokens}


@dataclass(frozen=True, slots=True)
class NativeOperationStep:
    operation: str
    token_parameter_u64: int
    token_parameter_commitment: str
    semantic_binding: Mapping[str, object]
    resolved_arguments: Mapping[str, object]
    parent_semantic_id: str
    child_semantic_id: str
    native_receipt_digest: str

    def as_dict(self) -> dict[str, object]:
        return {
            "operation": self.operation,
            "token_parameter_u64": self.token_parameter_u64,
            "token_parameter_commitment": self.token_parameter_commitment,
            "semantic_binding": dict(self.semantic_binding),
            "resolved_arguments": dict(self.resolved_arguments),
            "parent_semantic_id": self.parent_semantic_id,
            "child_semantic_id": self.child_semantic_id,
            "native_receipt_digest": self.native_receipt_digest,
        }


@dataclass(frozen=True, slots=True)
class NativeWordExecutionV53:
    word_sha256: str
    strategy: str
    source_state_sha256: str
    fresh_entropy_commitment: str
    initial_semantic_id: str
    final_semantic_id: str
    final_children: tuple[str, ...]
    steps: tuple[NativeOperationStep, ...]
    schema: str = SCHEMA

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "word_sha256": self.word_sha256,
            "strategy": self.strategy,
            "source_state_sha256": self.source_state_sha256,
            "fresh_entropy_commitment": self.fresh_entropy_commitment,
            "initial_semantic_id": self.initial_semantic_id,
            "final_semantic_id": self.final_semantic_id,
            "final_children": list(self.final_children),
            "steps": [step.as_dict() for step in self.steps],
            "authority": {
                "candidate_only": True,
                "security_admission": False,
                "cryptographic_entropy": False,
                "changes_frozen_aead": False,
            },
        }


def execute_native_word_v5_3(
    word: MutationWord,
    *,
    initial_program: GeneticIRNode,
    donor_program: GeneticIRNode,
) -> tuple[GeneticIRNode, NativeWordExecutionV53]:
    if tuple(sorted(t.operation for t in word.tokens)) != tuple(sorted(OPERATORS)):
        raise NativeWordV53Error("word must contain each operator exactly once")
    state = initial_program
    initial_semantic_id = state.semantic_id
    steps: list[NativeOperationStep] = []

    for token in word.tokens:
        op = token.operation
        binding = semantic_binding(token)
        parent_id = state.semantic_id

        if op == "DUPLICATE_CHILD":
            anchor = str(binding["anchor"])
            child_index = _index(state, anchor)
            tag = str(binding["tag"])
            child, native_receipt = duplicate_child(state, "c1", child_index, tag=tag)
            resolved = {"target_id": "c1", "child_index": child_index, "anchor": anchor, "tag": tag}

        elif op == "INVERT_CHILDREN":
            a = str(binding["left_anchor"]); b = str(binding["right_anchor"])
            ia, ib = _index(state, a), _index(state, b)
            start, stop_inclusive = sorted((ia, ib))
            stop = stop_inclusive + 1
            child, native_receipt = invert_children(state, "c1", start, stop)
            resolved = {
                "target_id": "c1", "start": start, "stop": stop,
                "left_anchor": a, "right_anchor": b,
            }

        elif op == "TRANSLOCATE_CHILD":
            source = str(binding["source_anchor"]); destination = str(binding["destination_anchor"])
            source_index = _index(state, source)
            destination_index = _index(state, destination)
            if source_index == destination_index:
                raise NativeWordV53Error("translocation semantic anchors resolved to same index")
            child, native_receipt = translocate_child(
                state, "c1", source_index, destination_index
            )
            resolved = {
                "target_id": "c1", "source_index": source_index,
                "destination_index": destination_index,
                "source_anchor": source, "destination_anchor": destination,
            }

        elif op == "RECOMBINE_CHILDREN":
            right_cut = int(binding["right_cut"])
            tag = str(binding["tag"])
            left_cut = len(state.children)
            child, native_receipt = recombine_children(
                state, donor_program, "c1",
                left_cut=left_cut, right_cut=right_cut, tag=tag,
            )
            resolved = {
                "target_id": "c1", "left_cut": left_cut,
                "right_cut": right_cut, "tag": tag,
                "left_policy": "KEEP_ALL_CURRENT_LEFT_CHILDREN",
            }
        else:
            raise NativeWordV53Error(op)

        if native_receipt.parent_semantic_id != parent_id:
            raise NativeWordV53Error("native receipt parent semantic id mismatch")
        if native_receipt.child_semantic_id != child.semantic_id:
            raise NativeWordV53Error("native receipt child semantic id mismatch")
        steps.append(
            NativeOperationStep(
                operation=op,
                token_parameter_u64=token.parameter_u64,
                token_parameter_commitment=token.parameter_commitment,
                semantic_binding=binding,
                resolved_arguments=resolved,
                parent_semantic_id=parent_id,
                child_semantic_id=child.semantic_id,
                native_receipt_digest=native_receipt.digest,
            )
        )
        state = child

    receipt = NativeWordExecutionV53(
        word_sha256=word.word_sha256,
        strategy=word.strategy,
        source_state_sha256=word.source_state_sha256,
        fresh_entropy_commitment=word.fresh_entropy_commitment,
        initial_semantic_id=initial_semantic_id,
        final_semantic_id=state.semantic_id,
        final_children=tuple(child.unit_id for child in state.children),
        steps=tuple(steps),
    )
    return state, receipt


__all__ = [
    "SCHEMA", "NativeWordV53Error", "NativeOperationStep", "NativeWordExecutionV53",
    "semantic_binding", "semantic_parameter_map", "execute_native_word_v5_3",
]