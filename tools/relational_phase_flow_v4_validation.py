from __future__ import annotations
import argparse, hashlib, importlib.util, json, statistics
from dataclasses import asdict, replace
from pathlib import Path

from dncrypt.evolution import EvolutionPolicy, ProposalReceipt
from dncrypt.fitness import FitnessRecord, PopulationFitnessReport
from dncrypt.generalization import GeneralizationPolicy
from dncrypt.genetic_compiler import compile_genetic_program
from dncrypt.genome import population_commitment
from dncrypt.statistical_gate import StatisticalAdmissionPolicy, select_generation_multifold_statistically_hardened
from dncrypt.surface import initial_surface
from dncrypt.util import blake2b256, canonical_json_bytes

ROOT=Path(__file__).resolve().parents[1]

def _load(name,path):
    spec=importlib.util.spec_from_file_location(name,path); mod=importlib.util.module_from_spec(spec); assert spec.loader is not None; spec.loader.exec_module(mod); return mod

ab=_load('dncrypt_noema_abcd_v01',ROOT/'tools/prime_phase_abcd_challenge_v01.py')
v4=_load('dncrypt_noema_relflow_v4_adapter',ROOT/'tools/relational_phase_flow_v4_challenge.py')
challenge=ab.challenge; base=ab.base

SCHEMA='dncrypt.noema-relational-phase-flow-v4-validation/v0.1'
STRATEGIES=v4.STRATEGIES

def _single_report_digest(r:FitnessRecord)->str: return blake2b256(canonical_json_bytes(asdict(r)))
def _normalized_record(r:FitnessRecord)->FitnessRecord: return replace(r,throughput=1.0)
def _normalized_report(r:PopulationFitnessReport)->PopulationFitnessReport: return PopulationFitnessReport(r.schema,r.request_id,tuple(_normalized_record(x) for x in r.records))
def _risk(r:FitnessRecord)->float: return r.adversarial_risk(0.05)
def _summary(xs): return {'mean':float(statistics.fmean(xs)),'median':float(statistics.median(xs)),'min':float(min(xs)),'max':float(max(xs))}

def proposal_receipt(parent,parent_report,policy,population,entropy,*,strategy):
    return ProposalReceipt('dncrypt.proposal-receipt/v0.2',parent.genome_id,_single_report_digest(parent_report),policy.digest,population_commitment(population),blake2b256(bytes(entropy)),True,f'relflow_v4_observation_only:{strategy}')

def run_replicate(rep:int,cfg:dict)->dict:
    root=bytes.fromhex(cfg['seed_hex']); rep_seed=base.derive(root,'replicate',rep,n=32); master=base.derive(rep_seed,'master-key',n=32)
    parent=base.initial_genome(base.derive(rep_seed,'initial-genome',n=64)); surface=initial_surface(parent)
    program=ab.fixed_program(); phenotype=compile_genetic_program(program)
    folds=[base.corpus(rep_seed,f'selection-generation-0-fold-{i}',cfg['fold_messages'],cfg['message_bytes']) for i in range(cfg['folds'])]
    holdout=base.corpus(rep_seed,'sealed-holdout',cfg['holdout_messages'],cfg['message_bytes']); holdout_commit=base.corpus_commitment(holdout)
    parent_raw=tuple(challenge.evaluate_genome_paired(master,parent,surface,m,rep_seed,f'parent-f{i}') for i,m in enumerate(folds)); parent_norm=tuple(_normalized_record(x) for x in parent_raw)
    parent_holdout=challenge.evaluate_genome_paired(master,parent,surface,holdout,rep_seed,'sealed-parent'); agg=base.aggregate_parent_reports(parent_raw)
    ep=EvolutionPolicy(population_size=cfg['population_size'],mutation_risk_threshold=0.0,minimum_risk_improvement=0.0,minimum_throughput_ratio=1.0,surface_transition_steps=1)
    gp=GeneralizationPolicy(minimum_folds=cfg['folds'],minimum_winning_fraction=cfg['minimum_winning_fraction'],minimum_median_risk_improvement=cfg['minimum_median_risk_improvement'],maximum_worst_fold_regression=cfg['maximum_worst_fold_regression'],maximum_delta_stddev=cfg['maximum_delta_stddev'],minimum_throughput_ratio=1.0,surface_transition_steps=1)
    sp=StatisticalAdmissionPolicy(fdr_alpha=cfg['fdr_alpha'],minimum_effect_improvement=cfg['minimum_effect_improvement'],minimum_non_tie_folds=cfg['folds'])
    pop_entropy=base.derive(rep_seed,'relflow-v4-matched-population',parent.genome_id,n=cfg['population_size']*64)
    strategies={}; substrate={}; nuisance={}
    for strategy in STRATEGIES:
        population,bindings,pop_commit=v4.strategy_population(parent,program,cfg['population_size'],entropy=pop_entropy,strategy=strategy)
        proposal=proposal_receipt(parent,agg,ep,population,pop_entropy,strategy=strategy)
        for i,(g,binding) in enumerate(zip(population,bindings)):
            substrate.setdefault(i,{})[strategy]=(g.route,g.phase_seed_hex,g.mutation_nonce_hex,g.parent_id,g.generation,tuple(binding.candidate_pool),binding.mutation_budget)
            nuisance.setdefault(i,{})[strategy]=tuple(tuple(x) for x in binding.nuisance_signature)
        reports=[]
        for fi,messages in enumerate(folds):
            records=tuple(challenge.evaluate_genome_paired(master,g,surface,messages,rep_seed,f'{strategy}-candidate-f{fi}') for g in population)
            rid=blake2b256(canonical_json_bytes({'schema':'dncrypt.relflow-v4-observation-request/v0.1','replicate':rep,'strategy':strategy,'fold':fi,'population_commitment':pop_commit,'proposal_receipt':proposal.digest}))
            reports.append(PopulationFitnessReport('dncrypt.external-evaluation/v0.2',rid,records))
        norm=tuple(_normalized_report(r) for r in reports)
        child,child_surface,admission,scores,statistical=select_generation_multifold_statistically_hardened(parent,surface,parent_norm,population,norm,gp,sp,sealed_holdout_commitment=holdout_commit)
        def rank(i):
            s=scores[i]; return (s.median_risk_delta,s.worst_fold_risk_delta,s.delta_stddev,s.genome_id)
        idx=min(range(len(population)),key=rank); exploratory=population[idx]
        opened=challenge.evaluate_genome_paired(master,exploratory,surface,holdout,rep_seed,f'{strategy}-sealed-exploratory')
        strategies[strategy]={'population_commitment':pop_commit,'binding_commitment':blake2b256(canonical_json_bytes([asdict(x) for x in bindings])),'admission':{'promoted':admission.promoted,'reason':admission.reason,'receipt':admission.digest,'note':'DIAGNOSTIC_SELECTOR_ONLY'},'exploratory':{'selected_index':idx,'selected_genome_id':exploratory.genome_id,'selection_score':asdict(scores[idx]),'statistical_evidence':asdict(statistical[idx]),'holdout_risk':_risk(opened),'holdout_risk_delta_vs_parent':_risk(opened)-_risk(parent_holdout)}}
    substrate_match=all(len(set(x.values()))==1 for x in substrate.values()); nuisance_match=all(len(set(x.values()))==1 for x in nuisance.values())
    if not substrate_match: raise RuntimeError('B/F substrate mismatch')
    if not nuisance_match: raise RuntimeError('B/F shell/flavour nuisance mismatch')
    return {'replicate':rep,'paired_substrate_match':True,'exact_nuisance_match':True,'sealed_holdout':{'commitment':holdout_commit,'used_for_selection':False,'opened_after_selection':True},'parent_holdout_risk':_risk(parent_holdout),'strategies':strategies}

def run(cfg:dict)->dict:
    reps=[run_replicate(i,cfg) for i in range(cfg['replicates'])]; f='F_RELATIONAL_MATCHED_NUISANCE_V4'; b='B_RANDOM_LOCUS_NULL'
    diffs=[r['strategies'][f]['exploratory']['holdout_risk_delta_vs_parent']-r['strategies'][b]['exploratory']['holdout_risk_delta_vs_parent'] for r in reps]
    fw=sum(x<0 for x in diffs); bw=sum(x>0 for x in diffs); ties=len(diffs)-fw-bw; p=ab._exact_two_sided_sign_test(fw,bw); mean=float(statistics.fmean(diffs))
    out={'schema':SCHEMA,'status':'PASS','evidence_class':'CONTROLLED_PAIRED_ACTUAL_CIPHERTEXT_OBSERVATION','authority':{'security_admission':False,'cryptographic_entropy':False,'changes_frozen_aead':False,'physical_neutrino_carrier_verified':False},'configuration':cfg,'strategies':list(STRATEGIES),'matched_design':{'same_parent':True,'same_fresh_population_entropy':True,'same_native_genetic_ir_phenotype':True,'same_unconstrained_candidate_pool':True,'same_route_phase_seed_mutation_nonce':True,'exact_same_shell_marginals':True,'exact_same_flavour_marginals':True,'same_selection_corpora':True,'same_paired_ciphertext_entropy_schedule':True,'same_sealed_holdout':True,'only_arithmetic_observable_pairing_may_vary':True},'primary_endpoint':'sealed_holdout_diagnostic_adversarial_risk_of_selection_fold_exploratory_winner','primary_comparison':'F_RELATIONAL_MATCHED_NUISANCE_V4 minus B_RANDOM_LOCUS_NULL','primary_result':{'paired_delta':_summary(diffs),'F_lower_risk_count':fw,'random_lower_risk_count':bw,'ties':ties,'paired_sign_test_two_sided_p':p,'success_rule':'mean(F-B)<0 AND paired two-sided sign-test p<0.05','success_rule_passed':bool(mean<0 and fw>bw and p<0.05)},'all_substrate_matches':all(r['paired_substrate_match'] for r in reps),'all_nuisance_matches':all(r['exact_nuisance_match'] for r in reps),'all_holdouts_excluded_from_selection':all(not r['sealed_holdout']['used_for_selection'] for r in reps),'replicates':reps,'interpretation_boundary':'Observation-only matched-nuisance test. No security-admission, theorem, or physical-carrier promotion follows automatically.'}
    out['commitment_blake2b']=blake2b256(canonical_json_bytes(out)); return out

def default_config(args):
    return {'seed_hex':hashlib.sha256(b'DNCrypt NOEMA relational phase-flow v4 preregistered seed 2026-09-26').hexdigest(),'replicates':args.replicates,'population_size':args.population_size,'folds':args.folds,'fold_messages':args.fold_messages,'holdout_messages':args.holdout_messages,'message_bytes':args.message_bytes,'minimum_winning_fraction':2/3,'minimum_median_risk_improvement':0.0,'maximum_worst_fold_regression':0.02,'maximum_delta_stddev':0.05,'fdr_alpha':0.05,'minimum_effect_improvement':0.0}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--output',required=True); ap.add_argument('--replicates',type=int,default=24); ap.add_argument('--population-size',type=int,default=12); ap.add_argument('--folds',type=int,default=6); ap.add_argument('--fold-messages',type=int,default=16); ap.add_argument('--holdout-messages',type=int,default=64); ap.add_argument('--message-bytes',type=int,default=128); ns=ap.parse_args()
    out=run(default_config(ns)); Path(ns.output).write_text(json.dumps(out,indent=2,sort_keys=True)+'\n',encoding='utf-8'); print(json.dumps({'status':out['status'],'primary_result':out['primary_result'],'all_substrate_matches':out['all_substrate_matches'],'all_nuisance_matches':out['all_nuisance_matches'],'all_holdouts_excluded_from_selection':out['all_holdouts_excluded_from_selection'],'commitment_blake2b':out['commitment_blake2b']},indent=2,sort_keys=True))
if __name__=='__main__': main()