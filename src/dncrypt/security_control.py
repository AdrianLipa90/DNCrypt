from __future__ import annotations

from dataclasses import asdict, dataclass
import math

from .fitness import FitnessRecord
from .genome import CipherGenome
from .util import blake2b256, canonical_json_bytes


@dataclass(frozen=True, slots=True)
class SecurityControlPolicy:
    message_budget: int
    byte_budget: int
    attack_risk_threshold: float
    risk_window: int
    nonce_domain_tracking: bool = True
    quarantine_on_integrity_failure: bool = True
    quarantine_on_decrypt_failure: bool = True

    def __post_init__(self) -> None:
        if not 256 <= self.message_budget <= 4096:
            raise ValueError("message_budget outside frozen safe bounds")
        if not 1_048_576 <= self.byte_budget <= 8_388_608:
            raise ValueError("byte_budget outside frozen safe bounds")
        if not 0.01 <= self.attack_risk_threshold <= 0.10:
            raise ValueError("attack_risk_threshold outside frozen safe bounds")
        if not 4 <= self.risk_window <= 16:
            raise ValueError("risk_window outside frozen safe bounds")
        if not (self.nonce_domain_tracking and self.quarantine_on_integrity_failure and self.quarantine_on_decrypt_failure):
            raise ValueError("fail-closed control invariants must remain enabled")

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))


@dataclass(frozen=True, slots=True)
class SecurityControlState:
    epoch: int = 0
    messages: int = 0
    bytes_processed: int = 0
    risk_history: tuple[float, ...] = ()
    nonce_domains: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if min(self.epoch, self.messages, self.bytes_processed) < 0:
            raise ValueError("control counters must be non-negative")
        if any(not 0.0 <= x <= 1.0 or not math.isfinite(x) for x in self.risk_history):
            raise ValueError("risk_history values must be finite in [0,1]")

    @property
    def commitment(self) -> str:
        return blake2b256(canonical_json_bytes({
            "epoch": self.epoch,
            "messages": self.messages,
            "bytes_processed": self.bytes_processed,
            "risk_history": list(self.risk_history),
            "nonce_domains": sorted(self.nonce_domains),
        }))


@dataclass(frozen=True, slots=True)
class SecurityControlObservation:
    payload_bytes: int
    attack_risk: float
    nonce_domain_commitment: str
    decrypt_failures: int = 0
    integrity_failures: int = 0

    def __post_init__(self) -> None:
        if self.payload_bytes <= 0:
            raise ValueError("payload_bytes must be positive")
        if not math.isfinite(self.attack_risk) or not 0.0 <= self.attack_risk <= 1.0:
            raise ValueError("attack_risk must be finite in [0,1]")
        if len(self.nonce_domain_commitment) != 64:
            raise ValueError("nonce_domain_commitment must be a 32-byte hex digest")
        try:
            int(self.nonce_domain_commitment, 16)
        except ValueError as exc:
            raise ValueError("nonce_domain_commitment must be hexadecimal") from exc
        if self.decrypt_failures < 0 or self.integrity_failures < 0:
            raise ValueError("failure counts must be non-negative")


@dataclass(frozen=True, slots=True)
class SecurityControlDecision:
    action: str
    reason: str
    state_before: str
    state_after: str
    policy_digest: str

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))


def derive_security_control_policy(genome: CipherGenome) -> SecurityControlPolicy:
    op = genome.operator_vector
    message_budget = min(4096, 256 + 16 * int(op[0]))
    byte_budget = (1 + int(op[1]) // 32) * 1_048_576
    attack_risk_threshold = 0.01 + (int(op[2]) / 255.0) * 0.09
    risk_window = 4 + int(op[3]) % 13
    return SecurityControlPolicy(
        message_budget=message_budget,
        byte_budget=byte_budget,
        attack_risk_threshold=attack_risk_threshold,
        risk_window=risk_window,
    )


def rotate_control_state(state: SecurityControlState) -> SecurityControlState:
    return SecurityControlState(epoch=state.epoch + 1)


def apply_security_control(
    state: SecurityControlState,
    observation: SecurityControlObservation,
    policy: SecurityControlPolicy,
) -> tuple[SecurityControlState, SecurityControlDecision]:
    before = state.commitment
    if observation.integrity_failures:
        decision = SecurityControlDecision("QUARANTINE", "integrity_failure", before, before, policy.digest)
        return state, decision
    if observation.decrypt_failures:
        decision = SecurityControlDecision("QUARANTINE", "decrypt_failure", before, before, policy.digest)
        return state, decision
    if observation.nonce_domain_commitment in state.nonce_domains:
        decision = SecurityControlDecision("QUARANTINE", "nonce_domain_reuse", before, before, policy.digest)
        return state, decision

    history = (state.risk_history + (observation.attack_risk,))[-policy.risk_window:]
    next_state = SecurityControlState(
        epoch=state.epoch,
        messages=state.messages + 1,
        bytes_processed=state.bytes_processed + observation.payload_bytes,
        risk_history=history,
        nonce_domains=state.nonce_domains | {observation.nonce_domain_commitment},
    )
    moving_risk = sum(history) / len(history)
    if moving_risk >= policy.attack_risk_threshold:
        action, reason = "ROTATE_REQUIRED", "attack_risk_threshold"
    elif next_state.messages >= policy.message_budget:
        action, reason = "ROTATE_REQUIRED", "message_budget"
    elif next_state.bytes_processed >= policy.byte_budget:
        action, reason = "ROTATE_REQUIRED", "byte_budget"
    else:
        action, reason = "ACCEPT", "within_control_budget"
    return next_state, SecurityControlDecision(action, reason, before, next_state.commitment, policy.digest)


@dataclass(frozen=True, slots=True)
class SecurityControlEvaluation:
    genome_id: str
    generation: int
    observations: int
    mean_residual_exposure: float
    accepted_high_risk_fraction: float
    rotation_fraction: float
    quarantine_count: int
    decision_commitment: str

    @property
    def risk(self) -> float:
        return self.mean_residual_exposure + self.accepted_high_risk_fraction

    def to_fitness_record(self) -> FitnessRecord:
        return FitnessRecord(
            genome_id=self.genome_id,
            generation=self.generation,
            structural_leakage=self.mean_residual_exposure,
            predictability=self.accepted_high_risk_fraction,
            delta_bits=0.0,
            delta_alpha=0.0,
            avalanche_bias=0.0,
            throughput=1.0,
            decrypt_failures=0,
            integrity_failures=0,
            p_value=1.0,
            source="security_control_policy_v0.4.2",
        )


def evaluate_security_control(
    genome: CipherGenome,
    observations: tuple[SecurityControlObservation, ...],
) -> SecurityControlEvaluation:
    if not observations:
        raise ValueError("observations must not be empty")
    policy = derive_security_control_policy(genome)
    state = SecurityControlState()
    exposure = 0.0
    high_risk_accepted = 0
    rotations = 0
    quarantines = 0
    digests: list[str] = []
    for observation in observations:
        next_state, decision = apply_security_control(state, observation, policy)
        digests.append(decision.digest)
        if decision.action == "QUARANTINE":
            quarantines += 1
            continue
        if decision.action == "ROTATE_REQUIRED":
            rotations += 1
            state = rotate_control_state(next_state)
            continue
        state = next_state
        exposure += observation.attack_risk
        if observation.attack_risk >= policy.attack_risk_threshold:
            high_risk_accepted += 1
    n = len(observations)
    return SecurityControlEvaluation(
        genome_id=genome.genome_id,
        generation=genome.generation,
        observations=n,
        mean_residual_exposure=exposure / n,
        accepted_high_risk_fraction=high_risk_accepted / n,
        rotation_fraction=rotations / n,
        quarantine_count=quarantines,
        decision_commitment=blake2b256(canonical_json_bytes(digests)),
    )
