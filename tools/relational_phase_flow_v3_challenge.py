from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, replace
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import statistics
from typing import Iterable

from dncrypt.evolution import EvolutionPolicy, ProposalReceipt
from dncrypt.fitness import FitnessRecord, PopulationFitnessReport
from dncrypt.generalization import GeneralizationPolicy
from dncrypt.genetic_compiler import compile_genetic_program
from dncrypt.genome import CipherGenome, DIM, mutate_genome, population_commitment
from dncrypt.statistical_gate import StatisticalAdmissionPolicy, select_generation_multifold_statistically_hardened
from dncrypt.surface import initial_surface
from dncrypt.util import blake2b256, canonical_json_bytes

ROOT = Path(__file__).resolve().parents[1]
SPEC_ABCD = importlib.util.spec_from_file_location(
    "dncrypt_noema_abcd_v01",
    ROOT / "tools" / "prime_phase_abcd_challenge_v01.py",
)
ab = importlib.util.module_from_spec(SPEC_ABCD)
assert SPEC_ABCD.loader is not None
SPEC_ABCD.loader.exec_module(ab)
challenge = ab.challenge
base = ab.base

SPEC_CORE = importlib.util.spec_from_file_location(
    "dncrypt_noema_relflow_core_v3",
    ROOT / "tools" / "relational_phase_flow_core_v3.py",
)
core = importlib.util.module_from_spec(SPEC_CORE)
assert SPEC_CORE.loader is not None
SPEC_CORE.loader.exec_module(core)

SCHEMA = "dncrypt.noema-relational-phase-flow-v3/v0.1"
BINDING_SCHEMA = "dncrypt.noema-relational-phase-flow-candidate-binding/v0.1"
STRATEGIES = ("B_RANDOM_LOCUS_NULL", "E_RELATIONAL_PHASE_FLOW_V3")
SHELLS = (6, 30, 210, 2310)
OBSERVABLES = ("prime_gap", "twin_start_gap", "v2_p_plus_1")
FLAVOURS = ("nu_e", "nu_mu", "nu_tau")
TAU = 2.0 * math.pi


@dataclass(frozen=True, slots=True)
class RelationalCandidateBinding:
    schema: str
    strategy: str
    parent_genome_id: str
    child_genome_id: str
    phenotype_commitment: str
    fresh_entropy_commitment: str
    relational_source_commitment: str | None
    changed_loci: tuple[int, ...]
    allowed_loci: tuple[int, ...]
    mutation_budget: int
    frozen_aead_changed: bool = False
    cryptographic_entropy_authority: bool = False
    security_admission_authority: bool = False

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))


RelationalSourceTriple = core.RelationalSourceTriple
relational_source_triple = core.relational_source_triple


def _rank_relational_v3(
    loci: Iterable[int], fresh_entropy: bytes, source: RelationalSourceTriple, mutation_tick: int
) -> list[int]:
    del mutation_tick
    return core.rank_loci(source, loci, fresh_entropy)


def _strategy_ranking(
    strategy: str,
    loci: Iterable[int],
    fresh_entropy: bytes,
    source: RelationalSourceTriple,
    mutation_tick: int,
) -> list[int]:
    if strategy == "B_RANDOM_LOCUS_NULL":
        return ab._rank_null(loci, fresh_entropy)
    if strategy == "E_RELATIONAL_PHASE_FLOW_V3":
        return _rank_relational_v3(loci, fresh_entropy, source, mutation_tick)
    raise ValueError(f"unsupported strategy {strategy!r}")


def mutate_with_strategy(
    parent: CipherGenome,
    program,
    *,
    fresh_entropy: bytes,
    strategy: str,
    mutation_tick: int,
) -> tuple[CipherGenome, RelationalCandidateBinding]:
    raw_entropy = bytes(fresh_entropy)
    if len(raw_entropy) < 32:
        raise ValueError("fresh mutation entropy must contain at least 32 bytes")
    phenotype = compile_genetic_program(program)

    bound_entropy = hashlib.shake_256(
        b"DNCrypt/v0.6.1/genetic-mutation/fresh|"
        + raw_entropy
        + bytes.fromhex(phenotype.commitment)
    ).digest(max(64, len(raw_entropy)))
    unconstrained = mutate_genome(parent, bound_entropy)

    allowed = tuple(phenotype.allowed_loci)
    changed = tuple(
        i for i in allowed
        if unconstrained.operator_vector[i] != parent.operator_vector[i]
    )
    source = relational_source_triple(raw_entropy)
    ranking = _strategy_ranking(strategy, allowed, raw_entropy, source, mutation_tick)
    changed_set = set(changed)
    keep = [i for i in ranking if i in changed_set][: phenotype.mutation_budget]
    if not keep:
        keep = [ranking[0]]

    operator = list(parent.operator_vector)
    native_seed = ab._native_order_seed(raw_entropy)
    for index in keep:
        candidate_value = unconstrained.operator_vector[index]
        if candidate_value == parent.operator_vector[index]:
            delta = 1 + (native_seed[index] % 255)
            candidate_value = (parent.operator_vector[index] + delta) & 0xFF
        operator[index] = candidate_value

    route = list(unconstrained.route)
    shift = (phenotype.route_direction * phenotype.route_stride) % DIM
    route = route[shift:] + route[:shift]
    child = CipherGenome(
        version=unconstrained.version,
        generation=unconstrained.generation,
        parent_id=unconstrained.parent_id,
        operator_vector=tuple(operator),
        route=tuple(route),
        phase_seed_hex=unconstrained.phase_seed_hex,
        mutation_nonce_hex=unconstrained.mutation_nonce_hex,
    )
    changed_loci = tuple(i for i in range(DIM) if child.operator_vector[i] != parent.operator_vector[i])
    if not changed_loci or not set(changed_loci).issubset(set(allowed)):
        raise RuntimeError("strategy escaped or produced no native Genetic IR mutation")
    if len(changed_loci) > phenotype.mutation_budget:
        raise RuntimeError("strategy exceeded native Genetic IR mutation budget")

    binding = RelationalCandidateBinding(
        schema=BINDING_SCHEMA,
        strategy=strategy,
        parent_genome_id=parent.genome_id,
        child_genome_id=child.genome_id,
        phenotype_commitment=phenotype.commitment,
        fresh_entropy_commitment=blake2b256(raw_entropy),
        relational_source_commitment=(source.commitment if strategy == "E_RELATIONAL_PHASE_FLOW_V3" else None),
        changed_loci=changed_loci,
        allowed_loci=allowed,
        mutation_budget=phenotype.mutation_budget,
    )
    return child, binding


def strategy_population(parent, program, population_size: int, *, entropy: bytes, strategy: str):
    raw = bytes(entropy)
    if len(raw) != population_size * 64:
        raise ValueError("population entropy must be exactly population_size*64 bytes")
    genomes=[]; bindings=[]
    for index in range(population_size):
        child_entropy = hashlib.shake_256(
            b"DNCrypt/v0.6.1/genetic-population|" + raw + index.to_bytes(8,"big")
        ).digest(64)
        child,binding=mutate_with_strategy(parent,program,fresh_entropy=child_entropy,strategy=strategy,mutation_tick=index)
        genomes.append(child); bindings.append(binding)
    population=tuple(genomes)
    if len({g.genome_id for g in population}) != len(population):
        raise RuntimeError("strategy population produced duplicate genome ids")
    return population,tuple(bindings),population_commitment(population)


def _single_report_digest(report: FitnessRecord) -> str:
    return blake2b256(canonical_json_bytes(asdict(report)))


def proposal_receipt(parent, parent_report, policy, population, entropy, *, strategy):
    return ProposalReceipt(
        "dncrypt.proposal-receipt/v0.2", parent.genome_id,
        _single_report_digest(parent_report), policy.digest,
        population_commitment(population), blake2b256(bytes(entropy)), True,
        f"relflow_v3_observation_only:{strategy}",
    )


def _normalized_record(record: FitnessRecord) -> FitnessRecord:
    return replace(record, throughput=1.0)


def _normalized_report(report: PopulationFitnessReport) -> PopulationFitnessReport:
    return PopulationFitnessReport(report.schema, report.request_id, tuple(_normalized_record(r) for r in report.records))


def _risk(record: FitnessRecord) -> float:
    return record.adversarial_risk(0.05)


def _summary(values: list[float]) -> dict[str,float]:
    return {"mean":float(statistics.fmean(values)),"median":float(statistics.median(values)),"min":float(min(values)),"max":float(max(values))}


def run_replicate(rep: int, cfg: dict) -> dict:
    root=bytes.fromhex(cfg["seed_hex"]); rep_seed=base.derive(root,"replicate",rep,n=32)
    master=base.derive(rep_seed,"master-key",n=32)
    parent=base.initial_genome(base.derive(rep_seed,"initial-genome",n=64)); surface=initial_surface(parent)
    program=ab.fixed_program(); phenotype=compile_genetic_program(program)
    folds=[base.corpus(rep_seed,f"selection-generation-0-fold-{i}",cfg["fold_messages"],cfg["message_bytes"]) for i in range(cfg["folds"])]
    holdout=base.corpus(rep_seed,"sealed-holdout",cfg["holdout_messages"],cfg["message_bytes"]); holdout_commit=base.corpus_commitment(holdout)
    parent_folds_raw=tuple(challenge.evaluate_genome_paired(master,parent,surface,m,rep_seed,f"parent-f{i}") for i,m in enumerate(folds))
    parent_folds=tuple(_normalized_record(r) for r in parent_folds_raw)
    parent_holdout=challenge.evaluate_genome_paired(master,parent,surface,holdout,rep_seed,"sealed-parent")
    aggregate_parent=base.aggregate_parent_reports(parent_folds_raw)
    proposal_policy=EvolutionPolicy(population_size=cfg["population_size"],mutation_risk_threshold=0.0,minimum_risk_improvement=0.0,minimum_throughput_ratio=1.0,surface_transition_steps=1)
    gp=GeneralizationPolicy(minimum_folds=cfg["folds"],minimum_winning_fraction=cfg["minimum_winning_fraction"],minimum_median_risk_improvement=cfg["minimum_median_risk_improvement"],maximum_worst_fold_regression=cfg["maximum_worst_fold_regression"],maximum_delta_stddev=cfg["maximum_delta_stddev"],minimum_throughput_ratio=1.0,surface_transition_steps=1)
    sp=StatisticalAdmissionPolicy(fdr_alpha=cfg["fdr_alpha"],minimum_effect_improvement=cfg["minimum_effect_improvement"],minimum_non_tie_folds=cfg["folds"])
    population_entropy=base.derive(rep_seed,"relflow-v3-matched-population",parent.genome_id,n=cfg["population_size"]*64)
    strategies={}; substrate={}
    for strategy in STRATEGIES:
        population,bindings,pop_commit=strategy_population(parent,program,cfg["population_size"],entropy=population_entropy,strategy=strategy)
        proposal=proposal_receipt(parent,aggregate_parent,proposal_policy,population,population_entropy,strategy=strategy)
        for i,g in enumerate(population):
            sig=(g.route,g.phase_seed_hex,g.mutation_nonce_hex,g.parent_id,g.generation)
            substrate.setdefault(i,{})[strategy]=sig
        fold_reports=[]
        for fi,messages in enumerate(folds):
            records=tuple(challenge.evaluate_genome_paired(master,g,surface,messages,rep_seed,f"{strategy}-candidate-f{fi}") for g in population)
            request_id=blake2b256(canonical_json_bytes({"schema":"dncrypt.relflow-v3-observation-request/v0.1","replicate":rep,"strategy":strategy,"fold":fi,"population_commitment":pop_commit,"proposal_receipt":proposal.digest}))
            fold_reports.append(PopulationFitnessReport("dncrypt.external-evaluation/v0.2",request_id,records))
        norm=tuple(_normalized_report(r) for r in fold_reports)
        child,child_surface,admission,scores,statistical=select_generation_multifold_statistically_hardened(parent,surface,parent_folds,population,norm,gp,sp,sealed_holdout_commitment=holdout_commit)
        def rank(i):
            s=scores[i]; return (s.median_risk_delta,s.worst_fold_risk_delta,s.delta_stddev,s.genome_id)
        idx=min(range(len(population)),key=rank); exploratory=population[idx]
        exploratory_holdout=challenge.evaluate_genome_paired(master,exploratory,surface,holdout,rep_seed,f"{strategy}-sealed-exploratory")
        strategies[strategy]={
          "population_commitment":pop_commit,
          "phenotype_commitment":phenotype.commitment,
          "binding_commitment":blake2b256(canonical_json_bytes([asdict(x) for x in bindings])),
          "admission":{"promoted":admission.promoted,"reason":admission.reason,"receipt":admission.digest,"note":"DIAGNOSTIC_SELECTOR_ONLY"},
          "exploratory":{"selected_index":idx,"selected_genome_id":exploratory.genome_id,"selection_score":asdict(scores[idx]),"statistical_evidence":asdict(statistical[idx]),"holdout_risk":_risk(exploratory_holdout),"holdout_risk_delta_vs_parent":_risk(exploratory_holdout)-_risk(parent_holdout)}
        }
    substrate_match=all(len(set(x.values()))==1 for x in substrate.values())
    if not substrate_match: raise RuntimeError("B/E substrate mismatch")
    return {"replicate":rep,"paired_substrate_match":True,"sealed_holdout":{"commitment":holdout_commit,"used_for_selection":False,"opened_after_selection":True},"parent_holdout_risk":_risk(parent_holdout),"strategies":strategies}


def run(cfg: dict) -> dict:
    reps=[run_replicate(i,cfg) for i in range(cfg["replicates"])]
    e="E_RELATIONAL_PHASE_FLOW_V3"; b="B_RANDOM_LOCUS_NULL"
    diffs=[r["strategies"][e]["exploratory"]["holdout_risk_delta_vs_parent"]-r["strategies"][b]["exploratory"]["holdout_risk_delta_vs_parent"] for r in reps]
    ew=sum(x<0 for x in diffs); bw=sum(x>0 for x in diffs); ties=len(diffs)-ew-bw
    p=ab._exact_two_sided_sign_test(ew,bw); mean=float(statistics.fmean(diffs))
    result={
      "schema":SCHEMA,"status":"PASS","evidence_class":"CONTROLLED_PAIRED_ACTUAL_CIPHERTEXT_OBSERVATION",
      "authority":{"security_admission":False,"cryptographic_entropy":False,"changes_frozen_aead":False,"physical_neutrino_carrier_verified":False},
      "configuration":cfg,"strategies":list(STRATEGIES),
      "matched_design":{"same_parent_per_replicate":True,"same_fresh_population_entropy_per_replicate":True,"same_native_genetic_ir_phenotype":True,"same_route_phase_seed_mutation_nonce_per_candidate_index":True,"same_selection_corpora":True,"same_paired_ciphertext_entropy_schedule":True,"same_sealed_holdout":True,"only_operator_locus_ordering_varies":True},
      "primary_endpoint":"sealed_holdout_diagnostic_adversarial_risk_of_selection_fold_exploratory_winner",
      "primary_comparison":"E_RELATIONAL_PHASE_FLOW_V3 minus B_RANDOM_LOCUS_NULL",
      "primary_result":{"paired_delta":_summary(diffs),"E_lower_risk_count":ew,"random_lower_risk_count":bw,"ties":ties,"paired_sign_test_two_sided_p":p,"success_rule":"mean(E-B)<0 AND paired two-sided sign-test p<0.05","success_rule_passed":bool(mean<0 and ew>bw and p<0.05)},
      "all_substrate_matches":all(r["paired_substrate_match"] for r in reps),
      "all_holdouts_excluded_from_selection":all(not r["sealed_holdout"]["used_for_selection"] for r in reps),
      "replicates":reps,
      "interpretation_boundary":"Observation-only test of relational mutation-search geometry under the paired DNCrypt ciphertext evaluator. No security-admission or physical-carrier promotion follows automatically."
    }
    result["commitment_blake2b"]=blake2b256(canonical_json_bytes(result)); return result


def main() -> None:
    ap=argparse.ArgumentParser(); ap.add_argument("--output",required=True)
    ap.add_argument("--replicates",type=int,default=24); ap.add_argument("--population-size",type=int,default=12)
    ap.add_argument("--folds",type=int,default=6); ap.add_argument("--fold-messages",type=int,default=16)
    ap.add_argument("--holdout-messages",type=int,default=64); ap.add_argument("--message-bytes",type=int,default=128)
    ns=ap.parse_args(); cfg={"seed_hex":hashlib.sha256(b"DNCrypt NOEMA relational phase-flow v3 preregistered seed").hexdigest(),"replicates":ns.replicates,"population_size":ns.population_size,"folds":ns.folds,"fold_messages":ns.fold_messages,"holdout_messages":ns.holdout_messages,"message_bytes":ns.message_bytes,"minimum_winning_fraction":2/3,"minimum_median_risk_improvement":0.0,"maximum_worst_fold_regression":0.02,"maximum_delta_stddev":0.05,"fdr_alpha":0.05,"minimum_effect_improvement":0.0}
    out=run(cfg); Path(ns.output).write_text(json.dumps(out,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"status":out["status"],"primary_result":out["primary_result"],"all_substrate_matches":out["all_substrate_matches"],"all_holdouts_excluded_from_selection":out["all_holdouts_excluded_from_selection"],"commitment_blake2b":out["commitment_blake2b"]},indent=2,sort_keys=True))


if __name__ == "__main__": main()