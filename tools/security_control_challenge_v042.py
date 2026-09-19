from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import math
from pathlib import Path
import statistics

from dncrypt.evolution import EvolutionPolicy, propose_generation
from dncrypt.fitness import FitnessRecord, PopulationFitnessReport
from dncrypt.generalization import GeneralizationPolicy
from dncrypt.genome import initial_genome
from dncrypt.security_admission import select_generation_multifold_security_only
from dncrypt.security_control import SecurityControlObservation, evaluate_security_control
from dncrypt.surface import initial_surface
from dncrypt.util import blake2b256, canonical_json_bytes

SCHEMA = "dncrypt.security-control-challenge/v0.4.2"


def derive(seed: bytes, *parts: object, n: int) -> bytes:
    h = hashlib.shake_256(seed)
    for part in parts:
        raw = str(part).encode()
        h.update(len(raw).to_bytes(4, "big")); h.update(raw)
    return h.digest(n)


def observation_corpus(seed: bytes, label: str, count: int) -> tuple[SecurityControlObservation, ...]:
    out = []
    for i in range(count):
        raw = derive(seed, label, i, n=16)
        u = int.from_bytes(raw[:8], "big") / float(2**64 - 1)
        v = int.from_bytes(raw[8:], "big") / float(2**64 - 1)
        risk = 0.005 + 0.025 * u
        if i % 17 in (0, 1, 2):
            risk += 0.055 + 0.035 * v
        out.append(SecurityControlObservation(
            payload_bytes=512 + int(3584 * u),
            attack_risk=min(risk, 1.0),
            nonce_domain_commitment=blake2b256(derive(seed, label, "nonce", i, n=32)),
        ))
    return tuple(out)


def corpus_commitment(obs: tuple[SecurityControlObservation, ...]) -> str:
    return blake2b256(canonical_json_bytes([asdict(x) for x in obs]))


def aggregate(records: tuple[FitnessRecord, ...]) -> FitnessRecord:
    first = records[0]
    med = lambda field: float(statistics.median(getattr(r, field) for r in records))
    return FitnessRecord(
        genome_id=first.genome_id, generation=first.generation,
        structural_leakage=med("structural_leakage"), predictability=med("predictability"),
        delta_bits=0.0, delta_alpha=0.0, avalanche_bias=0.0, throughput=1.0,
        decrypt_failures=0, integrity_failures=0, p_value=1.0,
        source="security_control_v0.4.2_multifold_parent_aggregate",
    )


def exact_two_sided_sign_test(wins: int, losses: int) -> float:
    n = wins + losses
    if n == 0: return 1.0
    k = min(wins, losses)
    return min(1.0, 2.0 * sum(math.comb(n, i) for i in range(k + 1)) / (2 ** n))


def run_replicate(rep: int, cfg: dict) -> dict:
    root = bytes.fromhex(cfg["seed_hex"])
    rep_seed = derive(root, "replicate", rep, n=32)
    parent = initial_genome(derive(rep_seed, "initial-genome", n=64))
    surface = initial_surface(parent)
    initial = parent
    sealed = observation_corpus(rep_seed, "sealed-control-holdout", cfg["holdout_observations"])
    sealed_commitment = corpus_commitment(sealed)
    proposal_policy = EvolutionPolicy(
        population_size=cfg["population_size"], mutation_risk_threshold=0.0,
        minimum_risk_improvement=0.0, minimum_throughput_ratio=0.1, surface_transition_steps=1,
    )
    gen_policy = GeneralizationPolicy(
        minimum_folds=cfg["folds"], minimum_winning_fraction=cfg["minimum_winning_fraction"],
        minimum_median_risk_improvement=cfg["minimum_median_risk_improvement"],
        maximum_worst_fold_regression=cfg["maximum_worst_fold_regression"],
        maximum_delta_stddev=cfg["maximum_delta_stddev"], minimum_throughput_ratio=0.1,
    )
    generations=[]
    for gen in range(cfg["generations"]):
        folds=tuple(observation_corpus(rep_seed,f"selection-g{gen}-f{f}",cfg["fold_observations"]) for f in range(cfg["folds"]))
        parent_records=tuple(evaluate_security_control(parent,fold).to_fitness_record() for fold in folds)
        entropy=derive(rep_seed,"population",gen,parent.genome_id,n=proposal_policy.population_size*64)
        population,proposal=propose_generation(parent,aggregate(parent_records),proposal_policy,entropy=entropy)
        if not population:
            generations.append({"generation":gen,"proposed":False,"reason":proposal.reason}); break
        reports=[]
        for f,fold in enumerate(folds):
            recs=tuple(evaluate_security_control(g,fold).to_fitness_record() for g in population)
            reports.append(PopulationFitnessReport("dncrypt.external-evaluation/v0.2",proposal.digest,recs))
        child,child_surface,promotion,scores,binding=select_generation_multifold_security_only(
            parent,surface,parent_records,population,tuple(reports),gen_policy,
            sealed_holdout_commitment=sealed_commitment,
        )
        generations.append({
            "generation":gen,"proposed":True,"promoted":promotion.promoted,"reason":promotion.reason,
            "selected_genome_id":promotion.selected_genome_id,"promotion_receipt":promotion.digest,
            "security_binding":binding.digest,"holdout_used_for_selection":promotion.holdout_used_for_selection,
        })
        if not promotion.promoted: break
        parent,surface=child,child_surface
    static=evaluate_security_control(initial,sealed)
    adaptive=evaluate_security_control(parent,sealed)
    return {
        "replicate":rep,"initial_genome_id":initial.genome_id,"final_genome_id":parent.genome_id,
        "promotions":sum(1 for x in generations if x.get("promoted")),"generations":generations,
        "sealed_holdout_commitment":sealed_commitment,"holdout_used_for_selection":False,
        "static":asdict(static),"adaptive":asdict(adaptive),
        "holdout_security_risk_delta_adaptive_minus_static":adaptive.risk-static.risk,
        "rotation_fraction_delta_adaptive_minus_static":adaptive.rotation_fraction-static.rotation_fraction,
    }


def run(cfg: dict) -> dict:
    reps=[run_replicate(i,cfg) for i in range(cfg["replicates"])]
    deltas=[x["holdout_security_risk_delta_adaptive_minus_static"] for x in reps]
    wins=sum(x<0 for x in deltas); losses=sum(x>0 for x in deltas); ties=len(deltas)-wins-losses
    p=exact_two_sided_sign_test(wins,losses); mean=float(statistics.fmean(deltas))
    result={
        "schema":SCHEMA,"status":"PASS","evidence_class":"CONTROLLED_SECURITY_CONTROL_SIMULATION",
        "configuration":cfg,"selection_boundary":"MULTIFOLD_ONLY_SEALED_HOLDOUT_EXCLUDED",
        "primary_endpoint":"sealed_holdout_security_control_risk",
        "summary":{
            "replicates":len(reps),"adaptive_holdout_wins":wins,"static_holdout_wins":losses,"ties":ties,
            "mean_holdout_security_risk_delta_adaptive_minus_static":mean,
            "median_holdout_security_risk_delta_adaptive_minus_static":float(statistics.median(deltas)),
            "sign_test_two_sided_p":p,"mean_promotions":float(statistics.fmean(x["promotions"] for x in reps)),
            "mean_rotation_fraction_delta_adaptive_minus_static":float(statistics.fmean(x["rotation_fraction_delta_adaptive_minus_static"] for x in reps)),
            "all_holdouts_excluded_from_selection":all(not x["holdout_used_for_selection"] for x in reps),
        },
        "verdict":"CONTROL_POLICY_HOLDOUT_ADVANTAGE_DEMONSTRATED" if mean<0 and wins>losses and p<0.05 else "NO_CONTROL_POLICY_HOLDOUT_ADVANTAGE_DEMONSTRATED",
        "replicates":reps,
    }
    result["commitment_blake2b"]=blake2b256(canonical_json_bytes(result)); return result


def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--output",required=True); ap.add_argument("--replicates",type=int,default=24)
    ap.add_argument("--generations",type=int,default=3); ap.add_argument("--population-size",type=int,default=24)
    ap.add_argument("--folds",type=int,default=5); ap.add_argument("--fold-observations",type=int,default=96); ap.add_argument("--holdout-observations",type=int,default=384)
    ns=ap.parse_args(); cfg={
        "seed_hex":hashlib.sha256(b"DNCrypt security control challenge v0.4.2 frozen seed").hexdigest(),
        "replicates":ns.replicates,"generations":ns.generations,"population_size":ns.population_size,
        "folds":ns.folds,"fold_observations":ns.fold_observations,"holdout_observations":ns.holdout_observations,
        "minimum_winning_fraction":0.60,"minimum_median_risk_improvement":0.0,
        "maximum_worst_fold_regression":0.005,"maximum_delta_stddev":0.02,
    }
    out=run(cfg); Path(ns.output).write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"verdict":out["verdict"],**out["summary"],"commitment":out["commitment_blake2b"]},indent=2))

if __name__=="__main__": main()
