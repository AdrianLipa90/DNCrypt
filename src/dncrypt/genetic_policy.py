"""Genetic IR -> bounded candidate security-policy compiler for DNCrypt v0.6.2.

The compiler is deterministic and public. Its output is a CANDIDATE_ONLY policy
proposal. It is not cryptographic entropy and it never bypasses the existing
causality, generalization, statistical, signed-evaluator or rollback gates.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib

from .genetic_compiler import compile_genetic_program
from .genetic_ir import GeneticIRNode
from .security_control import SecurityControlPolicy
from .util import blake2b256, canonical_json_bytes

POLICY_COMPILER_SCHEMA = "dncrypt.genetic-security-policy-compiler/v0.6.2-candidate"


@dataclass(frozen=True, slots=True)
class GeneticSecurityPolicyCandidate:
    genetic_ir_id: str
    phenotype_commitment: str
    policy: SecurityControlPolicy
    schema: str = POLICY_COMPILER_SCHEMA

    def __post_init__(self) -> None:
        for name, value in (
            ("genetic_ir_id", self.genetic_ir_id),
            ("phenotype_commitment", self.phenotype_commitment),
        ):
            if len(value) != 64:
                raise ValueError(name + " must be a 64-character hex digest")
            try:
                int(value, 16)
            except ValueError as exc:
                raise ValueError(name + " must be hexadecimal") from exc

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "genetic_ir_id": self.genetic_ir_id,
            "phenotype_commitment": self.phenotype_commitment,
            "policy": asdict(self.policy),
            "policy_digest": self.policy.digest,
            "authority": {
                "candidate_only": True,
                "security_admission": False,
                "cryptographic_entropy": False,
                "changes_frozen_aead": False,
                "fail_closed_invariants_locked": True,
            },
        }

    @property
    def candidate_id(self) -> str:
        return blake2b256(canonical_json_bytes(self.to_dict()))


def compile_genetic_security_policy(
    program: GeneticIRNode,
) -> GeneticSecurityPolicyCandidate:
    """Compile Genetic IR into one policy proposal inside frozen safe bounds."""

    phenotype = compile_genetic_program(program)
    seed = hashlib.shake_256(
        b"DNCrypt/v0.6.2/genetic-security-policy|"
        + canonical_json_bytes(program.to_dict())
        + bytes.fromhex(phenotype.commitment)
    ).digest(16)

    # Preserve the exact safe ranges enforced by SecurityControlPolicy.
    message_steps = ((4096 - 256) // 16) + 1
    message_budget = 256 + 16 * (int.from_bytes(seed[0:2], "big") % message_steps)
    byte_budget = (1 + (seed[2] % 8)) * 1_048_576
    attack_word = int.from_bytes(seed[3:5], "big")
    attack_risk_threshold = 0.01 + (attack_word / 65535.0) * 0.09
    risk_window = 4 + (seed[5] % 13)

    policy = SecurityControlPolicy(
        message_budget=message_budget,
        byte_budget=byte_budget,
        attack_risk_threshold=attack_risk_threshold,
        risk_window=risk_window,
        nonce_domain_tracking=True,
        quarantine_on_integrity_failure=True,
        quarantine_on_decrypt_failure=True,
    )
    return GeneticSecurityPolicyCandidate(
        genetic_ir_id=program.semantic_id,
        phenotype_commitment=phenotype.commitment,
        policy=policy,
    )


__all__ = [
    "POLICY_COMPILER_SCHEMA",
    "GeneticSecurityPolicyCandidate",
    "compile_genetic_security_policy",
]
