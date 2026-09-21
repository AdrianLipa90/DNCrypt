from __future__ import annotations
import argparse, hashlib, json, math, statistics, time
from dataclasses import asdict
from pathlib import Path
import numpy as np

from dncrypt.crypto import encrypt, decrypt
from dncrypt.genome import initial_genome
from dncrypt.surface import initial_surface
from dncrypt.fitness import FitnessRecord, PopulationFitnessReport
from dncrypt.evolution import EvolutionPolicy, propose_generation, select_generation
from dncrypt.bus import make_evaluation_request
from dncrypt.util import canonical_json_bytes, blake2b256, b64d, b64e

SCHEMA = "dncrypt.cryptanalysis-challenge/v0.1"


def derive(seed: bytes, *parts: object, n: int) -> bytes:
    h = hashlib.shake_256(seed)
    for p in parts:
        b = str(p).encode()
        h.update(len(b).to_bytes(4, "big")); h.update(b)
    return h.digest(n)


def corpus(seed: bytes, label: str, count: int, size: int) -> list[bytes]:
    return [derive(seed, label, i, n=size) for i in range(count)]


def bits_from_ciphertexts(items: list[bytes]) -> np.ndarray:
    if not items:
        return np.empty(0, dtype=np.uint8)
    return np.unpackbits(np.frombuffer(b"".join(items), dtype=np.uint8))


def evaluate_genome(master_key: bytes, genome, surface, messages: list[bytes], seed: bytes, label: str) -> FitnessRecord:
    cts: list[bytes] = []
    avalanche: list[float] = []
    started = time.perf_counter()
    decrypt_failures = 0
    integrity_failures = 0
    for i, msg in enumerate(messages):
        entropy = derive(seed, label, genome.genome_id, i, "entropy", n=44)
        env = encrypt(master_key, msg, genome, surface, user_aad=b"DNCrypt-Cryptanalysis-Challenge-v0.1", entropy=entropy)
        raw_ct = b64d(env.ciphertext_b64)
        cts.append(raw_ct)
        try:
            if decrypt(master_key, env, genome, surface) != msg:
                decrypt_failures += 1
        except Exception:
            decrypt_failures += 1

        # Offline avalanche probe: same deterministic message entropy, one flipped plaintext bit.
        alt = bytearray(msg); alt[0] ^= 1
        env2 = encrypt(master_key, bytes(alt), genome, surface, user_aad=b"DNCrypt-Cryptanalysis-Challenge-v0.1", entropy=entropy)
        raw2 = b64d(env2.ciphertext_b64)
        m = min(len(raw_ct), len(raw2))
        if m:
            x = np.frombuffer(raw_ct[:m], dtype=np.uint8) ^ np.frombuffer(raw2[:m], dtype=np.uint8)
            avalanche.append(float(np.unpackbits(x).mean()))

        # One-bit ciphertext tamper must fail authentication.
        tampered = bytearray(raw_ct); tampered[0] ^= 1
        d = asdict(env); d['ciphertext_b64'] = b64e(bytes(tampered))
        # receipt also binds ciphertext, so this must fail before/at AEAD.
        from dncrypt.crypto import DNCryptEnvelope
        try:
            decrypt(master_key, DNCryptEnvelope(**d), genome, surface)
            integrity_failures += 1
        except Exception:
            pass

    elapsed = max(time.perf_counter() - started, 1e-12)
    total_bytes = sum(len(m) for m in messages)
    throughput = total_bytes / elapsed
    bits = bits_from_ciphertexts(cts)
    if bits.size < 2:
        raise ValueError("insufficient ciphertext bits")
    bit_bias = abs(float(bits.mean()) - 0.5) * 2.0
    lag_agreement = float((bits[1:] == bits[:-1]).mean())
    predictability = abs(lag_agreement - 0.5) * 2.0

    raw = np.frombuffer(b"".join(cts), dtype=np.uint8)
    counts = np.bincount(raw, minlength=256).astype(np.float64)
    expected = max(raw.size / 256.0, 1e-12)
    chi2 = float(np.sum((counts - expected) ** 2 / expected))
    # dimensionless excess above df, scaled by sample size; low is better.
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
        source="cryptanalysis_challenge_v0.1_actual_ciphertext_metrics",
    )


def risk(r: FitnessRecord) -> float:
    return r.adversarial_risk(0.05)


def run_replicate(rep: int, cfg: dict) -> dict:
    root = bytes.fromhex(cfg['seed_hex'])
    rep_seed = derive(root, "replicate", rep, n=32)
    master = derive(rep_seed, "master-key", n=32)
    parent = initial_genome(derive(rep_seed, "initial-genome", n=64))
    surface = initial_surface(parent)
    initial = parent
    initial_surface_state = surface
    train = corpus(rep_seed, "train", cfg['train_messages'], cfg['message_bytes'])
    holdout = corpus(rep_seed, "holdout", cfg['holdout_messages'], cfg['message_bytes'])

    static_holdout = evaluate_genome(master, initial, initial_surface_state, holdout, rep_seed, "static-holdout")
    generations = []
    policy = EvolutionPolicy(
        population_size=cfg['population_size'], mutation_risk_threshold=0.0,
        minimum_risk_improvement=0.0, minimum_throughput_ratio=cfg['minimum_throughput_ratio'],
        surface_transition_steps=1,
    )

    for gen_idx in range(cfg['generations']):
        parent_train = evaluate_genome(master, parent, surface, train, rep_seed, f"train-parent-{gen_idx}")
        entropy = derive(rep_seed, "population", gen_idx, parent.genome_id, n=policy.population_size * 64)
        pop, proposal = propose_generation(parent, parent_train, policy, entropy=entropy)
        if not pop:
            generations.append({"generation": gen_idx, "proposed": False, "reason": proposal.reason})
            break
        records = tuple(evaluate_genome(master, g, surface, train, rep_seed, f"train-candidate-{gen_idx}") for g in pop)
        request = make_evaluation_request(parent, pop)
        report = PopulationFitnessReport("dncrypt.external-evaluation/v0.2", request.request_id, records)
        child, child_surface, promotion = select_generation(parent, surface, parent_train, pop, report, policy)
        generations.append({
            "generation": gen_idx,
            "parent_train_risk": risk(parent_train),
            "best_population_train_risk": min(risk(r) for r in records),
            "promoted": promotion.promoted,
            "reason": promotion.reason,
            "selected_genome_id": promotion.selected_genome_id,
        })
        if not promotion.promoted:
            break
        parent, surface = child, child_surface

    adaptive_holdout = evaluate_genome(master, parent, surface, holdout, rep_seed, "adaptive-holdout")
    static_train = evaluate_genome(master, initial, initial_surface_state, train, rep_seed, "static-train-final-audit")
    adaptive_train = evaluate_genome(master, parent, surface, train, rep_seed, "adaptive-train-final-audit")
    return {
        "replicate": rep,
        "initial_genome_id": initial.genome_id,
        "final_genome_id": parent.genome_id,
        "promotions": sum(1 for g in generations if g.get('promoted')),
        "generations": generations,
        "static_holdout": asdict(static_holdout),
        "adaptive_holdout": asdict(adaptive_holdout),
        "static_train_risk": risk(static_train),
        "adaptive_train_risk": risk(adaptive_train),
        "train_risk_delta_adaptive_minus_static": risk(adaptive_train) - risk(static_train),
        "static_holdout_risk": risk(static_holdout),
        "adaptive_holdout_risk": risk(adaptive_holdout),
        "holdout_risk_delta_adaptive_minus_static": risk(adaptive_holdout) - risk(static_holdout),
        "throughput_ratio_adaptive_over_static": adaptive_holdout.throughput / max(static_holdout.throughput, 1e-12),
    }


def exact_two_sided_sign_test(wins: int, losses: int) -> float:
    n = wins + losses
    if n == 0: return 1.0
    k = min(wins, losses)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / (2 ** n)
    return min(1.0, 2.0 * tail)


def run(cfg: dict) -> dict:
    reps = [run_replicate(i, cfg) for i in range(cfg['replicates'])]
    deltas = [r['holdout_risk_delta_adaptive_minus_static'] for r in reps]
    wins = sum(d < 0 for d in deltas); losses = sum(d > 0 for d in deltas); ties = len(deltas) - wins - losses
    train_deltas = [r['train_risk_delta_adaptive_minus_static'] for r in reps]
    ratios = [r['throughput_ratio_adaptive_over_static'] for r in reps]
    promotions = [r['promotions'] for r in reps]
    mean_delta = statistics.fmean(deltas)
    median_delta = statistics.median(deltas)
    result = {
        "schema": SCHEMA,
        "status": "PASS",
        "evidence_class": "CONTROLLED_SOFTWARE_CRYPTANALYSIS_BENCHMARK",
        "configuration": cfg,
        "comparison": "STATIC_DNCRYPT_FROZEN_ANCHOR_vs_ADAPTIVE_DNCRYPT",
        "primary_endpoint": "independent_holdout_adversarial_risk",
        "summary": {
            "replicates": len(reps),
            "adaptive_holdout_wins": wins,
            "static_holdout_wins": losses,
            "ties": ties,
            "mean_train_risk_delta_adaptive_minus_static": statistics.fmean(train_deltas),
            "median_train_risk_delta_adaptive_minus_static": statistics.median(train_deltas),
            "mean_generalization_gap_holdout_minus_train_delta": mean_delta - statistics.fmean(train_deltas),
            "mean_holdout_risk_delta_adaptive_minus_static": mean_delta,
            "median_holdout_risk_delta_adaptive_minus_static": median_delta,
            "sign_test_two_sided_p": exact_two_sided_sign_test(wins, losses),
            "mean_throughput_ratio_adaptive_over_static": statistics.fmean(ratios),
            "median_throughput_ratio_adaptive_over_static": statistics.median(ratios),
            "mean_promotions": statistics.fmean(promotions),
        },
        "verdict": (
            "HOLDOUT_ADVANTAGE_DEMONSTRATED" if mean_delta < 0 and wins > losses and exact_two_sided_sign_test(wins, losses) < 0.05
            else "NO_HOLDOUT_ADVANTAGE_DEMONSTRATED"
        ),
        "replicates": reps,
    }
    result['commitment_blake2b'] = blake2b256(canonical_json_bytes(result))
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--output', required=True)
    ap.add_argument('--replicates', type=int, default=12)
    ap.add_argument('--generations', type=int, default=3)
    ap.add_argument('--population-size', type=int, default=24)
    ap.add_argument('--train-messages', type=int, default=64)
    ap.add_argument('--holdout-messages', type=int, default=192)
    ap.add_argument('--message-bytes', type=int, default=256)
    args = ap.parse_args()
    cfg = {
        "seed_hex": hashlib.sha256(b"DNCrypt Cryptanalysis Challenge v0.1 frozen seed").hexdigest(),
        "replicates": args.replicates,
        "generations": args.generations,
        "population_size": args.population_size,
        "train_messages": args.train_messages,
        "holdout_messages": args.holdout_messages,
        "message_bytes": args.message_bytes,
        "minimum_throughput_ratio": 0.50,
    }
    out = run(cfg)
    Path(args.output).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"verdict": out['verdict'], **out['summary'], "commitment": out['commitment_blake2b']}, indent=2))

if __name__ == '__main__': main()
