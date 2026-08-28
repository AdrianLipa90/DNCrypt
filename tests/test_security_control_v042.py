from dncrypt.genome import initial_genome, mutate_genome
from dncrypt.security_control import (
    SecurityControlObservation, SecurityControlState, apply_security_control,
    derive_security_control_policy, evaluate_security_control, rotate_control_state,
)
from dncrypt.util import blake2b256


def obs(i: int, risk: float, **kwargs):
    return SecurityControlObservation(
        payload_bytes=1024, attack_risk=risk,
        nonce_domain_commitment=blake2b256(f"nonce-{i}".encode()), **kwargs,
    )


def test_policy_is_deterministic_and_fail_closed():
    genome = initial_genome(bytes(range(64)))
    policy = derive_security_control_policy(genome)
    assert policy == derive_security_control_policy(genome)
    state = SecurityControlState()
    state, first = apply_security_control(state, obs(0, 0.0), policy)
    _, reuse = apply_security_control(state, obs(0, 0.0), policy)
    assert first.action in {"ACCEPT", "ROTATE_REQUIRED"}
    assert reuse.action == "QUARANTINE" and reuse.reason == "nonce_domain_reuse"
    _, integ = apply_security_control(state, obs(1, 0.0, integrity_failures=1), policy)
    assert integ.action == "QUARANTINE"


def test_control_evaluation_is_causally_genome_dependent_and_receipted():
    parent = initial_genome(bytes(range(64)))
    child = mutate_genome(parent, bytes(range(64, 128)))
    observations = tuple(obs(i, 0.02 + 0.01 * (i % 5)) for i in range(32))
    a = evaluate_security_control(parent, observations)
    b = evaluate_security_control(child, observations)
    assert len(a.decision_commitment) == 64 and len(b.decision_commitment) == 64
    assert a.to_fitness_record().source == "security_control_policy_v0.4.2"
    assert derive_security_control_policy(parent).digest != derive_security_control_policy(child).digest


def test_rotation_resets_ephemeral_epoch_state():
    state = SecurityControlState(epoch=2, messages=10, bytes_processed=5000, risk_history=(0.1,), nonce_domains=frozenset({blake2b256(b"x")}))
    rotated = rotate_control_state(state)
    assert rotated.epoch == 3 and rotated.messages == 0 and rotated.bytes_processed == 0
    assert rotated.risk_history == () and not rotated.nonce_domains
