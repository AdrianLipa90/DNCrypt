from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import statistics
import time

import numpy as np

from dncrypt.causality import frozen_v02_causality_registry, select_generation_multifold_causal
from dncrypt.crypto import DNCryptEnvelope, decrypt, encrypt_deterministic_for_test
from dncrypt.fitness import FitnessRecord
from dncrypt.util import b64d, b64e, blake2b256, canonical_json_bytes

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("dncrypt_challenge_v02_base", ROOT / "tools" / "cryptanalysis_challenge_v02.py")
base = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(base)

REGISTRY = frozen_v02_causality_registry()


def paired_entropy(seed: bytes, messages: list[bytes], index: int) -> bytes:
    corpus_id = base.corpus_commitment(messages)
    return base.derive(seed, "paired-evaluation-entropy-v0.4.2", corpus_id, index, n=44)


def evaluate_genome_paired(master_key: bytes, genome, surface, messages: list[bytes], seed: bytes, label: str) -> FitnessRecord:
    """Evaluate genomes on an identical salt/nonce schedule for the same corpus.

    The label is retained only for the evaluator call contract. Entropy scheduling is
    derived from the corpus commitment and sample index, independent of genome id and
    parent/candidate role.
    """
    ciphertexts: list[bytes] = []
    avalanche: list[float] = []
    started = time.perf_counter()
    decrypt_failures = 0
    integrity_failures = 0
    for i, msg in enumerate(messages):
        entropy = paired_entropy(seed, messages, i)
        env = encrypt_deterministic_for_test(
            master_key,
            msg,
            genome,
            surface,
            user_aad=b"DNCrypt-Cryptanalysis-Challenge-v0.4.2",
            entropy=entropy,
        )
        raw_ct = b64d(env.ciphertext_b64)
        ciphertexts.append(raw_ct)
        try:
            if decrypt(master_key, env, genome, surface) != msg:
                decrypt_failures += 1
        except Exception:
            decrypt_failures += 1

        alt = bytearray(msg)
        alt[0] ^= 1
        env2 = encrypt_deterministic_for_test(
            master_key,
            bytes(alt),
            genome,
            surface,
            user_aad=b"DNCrypt-Cryptanalysis-Challenge-v0.4.2",
            entropy=entropy,
        )
        raw2 = b64d(env2.ciphertext_b64)
        m = min(len(raw_ct), len(raw2))
        if m:
            x = np.frombuffer(raw_ct[:m], dtype=np.uint8) ^ np.frombuffer(raw2[:m], dtype=np.uint8)
            avalanche.append(float(np.unpackbits(x).mean()))

        tampered = bytearray(raw_ct)
        tampered[0] ^= 1
        payload = asdict(env)
        payload["ciphertext_b64"] = b64e(bytes(tampered))
        try:
            decrypt(master_key, DNCryptEnvelope(**payload), genome, surface)
            integrity_failures += 1
        except Exception:
            pass

    elapsed = max(time.perf_counter() - started, 1e-12)
    throughput = sum(len(msg) for msg in messages) / elapsed
    bits = base.bits_from_ciphertexts(ciphertexts)
    if bits.size < 2:
        raise ValueError("insufficient ciphertext bits")
    bit_bias = abs(float(bits.mean()) - 0.5) * 2.0
    lag_agreement = float((bits[1:] == bits[:-1]).mean())
    predictability = abs(lag_agreement - 0.5) * 2.0

    raw = np.frombuffer(b"".join(ciphertexts), dtype=np.uint8)
    counts = np.bincount(raw, minlength=256).astype(np.float64)
    expected = max(raw.size / 256.0, 1e-12)
    chi2 = float(np.sum((counts - expected) ** 2 / expected))
    byte_structure = abs(chi2 - 255.0) / max(255.0, math.sqrt(max(raw.size, 1)))
    structural = bit_bias + byte_structure
    avalanche_bias = abs((statistics.fmean(avalanche) if avalanche else 0.5) - 0.5) * 2.0

    return FitnessRecord(
        genome_id=genome.genome_id,
        generation=genome.generation,
        structural_leakage=structural,
        predictability=predictability,
        delta_bits=0.0,
        delta_alpha=0.0,
        avalanche_bias=avalanche_bias,
        throughput=throughput,
        decrypt_failures=decrypt_failures,
        integrity_failures=integrity_failures,
        p_value=1.0,
        source="cryptanalysis_challenge_v0.4.2_paired_ciphertext_diagnostics",
    )


def _selector_adapter(*args, **kwargs):
    child, surface, receipt, scores, _security, _firewall = select_generation_multifold_causal(
        *args, **kwargs, registry=REGISTRY
    )
    return child, surface, receipt, scores


def _security_projection(value):
    if isinstance(value, dict):
        projected = {}
        for key, item in value.items():
            if key == "commitment_blake2b" or "throughput" in key:
                continue
            projected[key] = _security_projection(item)
        return projected
    if isinstance(value, list):
        return [_security_projection(item) for item in value]
    return value


def run(cfg: dict) -> dict:
    run_cfg = dict(cfg)
    run_cfg["performance_mode"] = "observe_only"
    original_selector = base.select_generation_multifold
    original_evaluator = base.evaluate_genome
    base.select_generation_multifold = _selector_adapter
    base.evaluate_genome = evaluate_genome_paired
    try:
        result = base.run(run_cfg)
    finally:
        base.select_generation_multifold = original_selector
        base.evaluate_genome = original_evaluator

    measurement_commitment = result.pop("commitment_blake2b")
    result["fitness_causality_firewall"] = {
        "schema": "dncrypt.fitness-causality-firewall/v0.4.2",
        "registry_digest": REGISTRY.digest,
        "admission_fields": list(REGISTRY.admission_fields),
        "diagnostic_fields": list(REGISTRY.diagnostic_fields),
        "paired_entropy_schedule": True,
        "paired_entropy_independent_of_genome_id": True,
    }
    projection = _security_projection(result)
    result["security_evidence_commitment_blake2b"] = blake2b256(canonical_json_bytes(projection))
    result["measurement_commitment_blake2b"] = measurement_commitment
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True)
    ap.add_argument("--replicates", type=int, default=12)
    ap.add_argument("--generations", type=int, default=3)
    ap.add_argument("--population-size", type=int, default=24)
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--fold-messages", type=int, default=48)
    ap.add_argument("--holdout-messages", type=int, default=192)
    ap.add_argument("--message-bytes", type=int, default=256)
    args = ap.parse_args()
    cfg = {
        "seed_hex": hashlib.sha256(b"DNCrypt Cryptanalysis Challenge v0.4.2 frozen seed").hexdigest(),
        "replicates": args.replicates,
        "generations": args.generations,
        "population_size": args.population_size,
        "folds": args.folds,
        "fold_messages": args.fold_messages,
        "holdout_messages": args.holdout_messages,
        "message_bytes": args.message_bytes,
        "minimum_winning_fraction": 0.60,
        "minimum_median_risk_improvement": 0.0,
        "maximum_worst_fold_regression": 0.02,
        "maximum_delta_stddev": 0.05,
        "minimum_throughput_ratio": 0.50,
    }
    out = run(cfg)
    Path(args.output).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "verdict": out["verdict"],
        **out["summary"],
        "security_commitment": out["security_evidence_commitment_blake2b"],
        "measurement_commitment": out["measurement_commitment_blake2b"],
        "causality_registry": REGISTRY.digest,
    }, indent=2))


if __name__ == "__main__":
    main()
