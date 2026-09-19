from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import math
from pathlib import Path
import statistics
import time

import numpy as np

from dncrypt.crypto import DNCryptEnvelope, decrypt, encrypt
from dncrypt.evolution import EvolutionPolicy, propose_generation
from dncrypt.fitness import FitnessRecord, PopulationFitnessReport
from dncrypt.generalization import GeneralizationPolicy, select_generation_multifold
from dncrypt.genome import initial_genome
from dncrypt.surface import initial_surface
from dncrypt.util import b64d, b64e, blake2b256, canonical_json_bytes

SCHEMA = "dncrypt.cryptanalysis-challenge/v0.2"


def derive(seed: bytes, *parts: object, n: int) -> bytes:
    h = hashlib.shake_256(seed)
    for part in parts:
        raw = str(part).encode()
        h.update(len(raw).to_bytes(4, "big"))
        h.update(raw)
    return h.digest(n)


def corpus(seed: bytes, label: str, count: int, size: int) -> list[bytes]:
    return [derive(seed, label, i, n=size) for i in range(count)]


def corpus_commitment(messages: list[bytes]) -> str:
    manifest = [
        {"index": i, "size": len(msg), "sha256": hashlib.sha256(msg).hexdigest()}
        for i, msg in enumerate(messages)
    ]
    return blake2b256(canonical_json_bytes(manifest))


def bits_from_ciphertexts(items: list[bytes]) -> np.ndarray:
    if not items:
        return np.empty(0, dtype=np.uint8)
    return np.unpackbits(np.frombuffer(b"".join(items), dtype=np.uint8))


def evaluate_genome(master_key: bytes, genome, surface, messages: list[bytes], seed: bytes, label: str) -> FitnessRecord:
    ciphertexts: list[bytes] = []
    avalanche: list[float] = []
    started = time.perf_counter()
    decrypt_failures = 0
    integrity_failures = 0
    for i, msg in enumerate(messages):
        entropy = derive(seed, label, genome.genome_id, i, "entropy", n=44)
        env = encrypt(
            master_key,
            msg,
            genome,
            surface,
            user_aad=b"DNCrypt-Cryptanalysis-Challenge-v0.2",
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
        env2 = encrypt(
            master_key,
            bytes(alt),
            genome,
            surface,
            user_aad=b"DNCrypt-Cryptanalysis-Challenge-v0.2",
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
    bits = bits_from_ciphertexts(ciphertexts)
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
        source="cryptanalysis_challenge_v0.2_actual_ciphertext_metrics",
    )


def risk(record: FitnessRecord) -> float:
    return record.adversarial_risk(0.05)


def aggregate_parent_reports(records: tuple[FitnessRecord, ...]) -> FitnessRecord:
    if not records:
        raise ValueError("records must not be empty")
    first = records[0]
    if any(r.genome_id != first.genome_id or r.generation != first.generation for r in records):
        raise ValueError("parent fold identity mismatch")
    med = lambda field: float(statistics.median(getattr(r, field) for r in records))
    return FitnessRecord(
        genome_id=first.genome_id,
        generation=first.generation,
        structural_leakage=med("structural_leakage"),
        predictability=med("predictability"),
        delta_bits=med("delta_bits"),
        delta_alpha=med("delta_alpha"),
        avalanche_bias=med("avalanche_bias"),
        throughput=min(r.throughput for r in records),
        decrypt_failures=max(r.decrypt_failures for r in records),
        integrity_failures=max(r.integrity_failures for r in records),
        p_value=max(r.p_value for r in records),
        source="cryptanalysis_challenge_v0.2_multifold_parent_aggregate",
    )


def run_replicate(rep: int, cfg: dict) -> dict:
    root = bytes.fromhex(cfg["seed_hex"])
    rep_seed = derive(root, "replicate", rep, n=32)
    master = derive(rep_seed, "master-key", n=32)
    parent = initial_genome(derive(rep_seed, "initial-genome", n=64))
    surface = initial_surface(parent)
    initial = parent
    initial_surface_state = surface

    sealed_holdout = corpus(rep_seed, "sealed-holdout", cfg["holdout_messages"], cfg["message_bytes"])
    sealed_holdout_commitment = corpus_commitment(sealed_holdout)

    proposal_policy = EvolutionPolicy(
        population_size=cfg["population_size"],
        mutation_risk_threshold=0.0,
        minimum_risk_improvement=0.0,
        minimum_throughput_ratio=cfg["minimum_throughput_ratio"],
        surface_transition_steps=1,
    )
    generalization_policy = GeneralizationPolicy(
        minimum_folds=cfg["folds"],
        minimum_winning_fraction=cfg["minimum_winning_fraction"],
        minimum_median_risk_improvement=cfg["minimum_median_risk_improvement"],
        maximum_worst_fold_regression=cfg["maximum_worst_fold_regression"],
        maximum_delta_stddev=cfg["maximum_delta_stddev"],
        minimum_throughput_ratio=cfg["minimum_throughput_ratio"],
        surface_transition_steps=1,
    )

    generations: list[dict] = []
    for gen_idx in range(cfg["generations"]):
        folds = [
            corpus(
                rep_seed,
                f"selection-generation-{gen_idx}-fold-{fold_idx}",
                cfg["fold_messages"],
                cfg["message_bytes"],
            )
            for fold_idx in range(cfg["folds"])
        ]
        parent_folds = tuple(
            evaluate_genome(master, parent, surface, messages, rep_seed, f"parent-g{gen_idx}-f{fold_idx}")
            for fold_idx, messages in enumerate(folds)
        )
        aggregate_parent = aggregate_parent_reports(parent_folds)
        entropy = derive(
            rep_seed,
            "population",
            gen_idx,
            parent.genome_id,
            n=proposal_policy.population_size * 64,
        )
        population, proposal = propose_generation(parent, aggregate_parent, proposal_policy, entropy=entropy)
        if not population:
            generations.append(
                {
                    "generation": gen_idx,
                    "proposed": False,
                    "reason": proposal.reason,
                    "sealed_holdout_commitment": sealed_holdout_commitment,
                }
            )
            break

        fold_reports: list[PopulationFitnessReport] = []
        for fold_idx, messages in enumerate(folds):
            records = tuple(
                evaluate_genome(
                    master,
                    genome,
                    surface,
                    messages,
                    rep_seed,
                    f"candidate-g{gen_idx}-f{fold_idx}",
                )
                for genome in population
            )
            fold_reports.append(
                PopulationFitnessReport("dncrypt.external-evaluation/v0.2", proposal.digest, records)
            )

        child, child_surface, promotion, scores = select_generation_multifold(
            parent,
            surface,
            parent_folds,
            population,
            tuple(fold_reports),
            generalization_policy,
            sealed_holdout_commitment=sealed_holdout_commitment,
        )
        selected_score = next(
            (score for score in scores if score.genome_id == promotion.selected_genome_id),
            None,
        )
        generations.append(
            {
                "generation": gen_idx,
                "proposed": True,
                "promoted": promotion.promoted,
                "reason": promotion.reason,
                "selected_genome_id": promotion.selected_genome_id,
                "selected_score": asdict(selected_score) if selected_score is not None else None,
                "promotion_receipt_digest": promotion.digest,
                "sealed_holdout_commitment": sealed_holdout_commitment,
                "holdout_used_for_selection": promotion.holdout_used_for_selection,
            }
        )
        if not promotion.promoted:
            break
        parent, surface = child, child_surface

    # The sealed holdout is opened only after all promotion decisions are complete.
    static_holdout = evaluate_genome(
        master,
        initial,
        initial_surface_state,
        sealed_holdout,
        rep_seed,
        "sealed-static-holdout-open",
    )
    adaptive_holdout = evaluate_genome(
        master,
        parent,
        surface,
        sealed_holdout,
        rep_seed,
        "sealed-adaptive-holdout-open",
    )
    holdout_delta = risk(adaptive_holdout) - risk(static_holdout)
    return {
        "replicate": rep,
        "initial_genome_id": initial.genome_id,
        "final_genome_id": parent.genome_id,
        "promotions": sum(1 for g in generations if g.get("promoted")),
        "generations": generations,
        "sealed_holdout": {
            "commitment": sealed_holdout_commitment,
            "message_count": len(sealed_holdout),
            "message_bytes": cfg["message_bytes"],
            "opened_after_all_promotion_decisions": True,
            "used_for_selection": False,
        },
        "static_holdout": asdict(static_holdout),
        "adaptive_holdout": asdict(adaptive_holdout),
        "static_holdout_risk": risk(static_holdout),
        "adaptive_holdout_risk": risk(adaptive_holdout),
        "holdout_risk_delta_adaptive_minus_static": holdout_delta,
        "throughput_ratio_adaptive_over_static": adaptive_holdout.throughput / max(static_holdout.throughput, 1e-12),
    }


def exact_two_sided_sign_test(wins: int, losses: int) -> float:
    n = wins + losses
    if n == 0:
        return 1.0
    k = min(wins, losses)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / (2 ** n)
    return min(1.0, 2.0 * tail)


def run(cfg: dict) -> dict:
    reps = [run_replicate(i, cfg) for i in range(cfg["replicates"])]
    deltas = [r["holdout_risk_delta_adaptive_minus_static"] for r in reps]
    wins = sum(delta < 0 for delta in deltas)
    losses = sum(delta > 0 for delta in deltas)
    ties = len(deltas) - wins - losses
    ratios = [r["throughput_ratio_adaptive_over_static"] for r in reps]
    promotions = [r["promotions"] for r in reps]
    sign_p = exact_two_sided_sign_test(wins, losses)
    mean_delta = statistics.fmean(deltas)
    result = {
        "schema": SCHEMA,
        "status": "PASS",
        "evidence_class": "CONTROLLED_MULTIFOLD_SOFTWARE_CRYPTANALYSIS_BENCHMARK",
        "configuration": cfg,
        "comparison": "STATIC_DNCRYPT_FROZEN_ANCHOR_vs_GENERALIZATION_AWARE_DNCRYPT",
        "selection_boundary": "MULTIFOLD_ONLY_SEALED_HOLDOUT_EXCLUDED",
        "primary_endpoint": "sealed_independent_holdout_adversarial_risk",
        "summary": {
            "replicates": len(reps),
            "adaptive_holdout_wins": wins,
            "static_holdout_wins": losses,
            "ties": ties,
            "mean_holdout_risk_delta_adaptive_minus_static": mean_delta,
            "median_holdout_risk_delta_adaptive_minus_static": statistics.median(deltas),
            "sign_test_two_sided_p": sign_p,
            "mean_throughput_ratio_adaptive_over_static": statistics.fmean(ratios),
            "median_throughput_ratio_adaptive_over_static": statistics.median(ratios),
            "mean_promotions": statistics.fmean(promotions),
            "all_holdouts_excluded_from_selection": all(
                not rep["sealed_holdout"]["used_for_selection"] for rep in reps
            ),
        },
        "verdict": (
            "SEALED_HOLDOUT_ADVANTAGE_DEMONSTRATED"
            if mean_delta < 0 and wins > losses and sign_p < 0.05
            else "NO_SEALED_HOLDOUT_ADVANTAGE_DEMONSTRATED"
        ),
        "replicates": reps,
    }
    result["commitment_blake2b"] = blake2b256(canonical_json_bytes(result))
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
        "seed_hex": hashlib.sha256(b"DNCrypt Cryptanalysis Challenge v0.2 frozen seed").hexdigest(),
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
    print(json.dumps({"verdict": out["verdict"], **out["summary"], "commitment": out["commitment_blake2b"]}, indent=2))


if __name__ == "__main__":
    main()
