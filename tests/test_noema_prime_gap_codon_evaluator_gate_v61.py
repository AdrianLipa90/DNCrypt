from __future__ import annotations
import importlib.util,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
S=importlib.util.spec_from_file_location('gate',ROOT/'tools/noema_prime_gap_codon_evaluator_gate_v61.py'); g=importlib.util.module_from_spec(S); assert S.loader; S.loader.exec_module(g)
def _receipt():
 x={'schema':g.SCHEMA,'status':'PASS_NATIVE_PAIR_CLOSURE','implementation_commit':g.EXPECTED_IMPLEMENTATION,'noema_source_commit':g.EXPECTED_NOEMA,'fixture_sha256':'a'*64,'relational':{'word_sha256':'b'*64,'final_program_semantic_id':'c'*64,'candidate_genome_id':'d'*64,'phenotype_commitment':'e'*64},'matched_null':{'word_sha256':'f'*64,'final_program_semantic_id':'1'*64,'candidate_genome_id':'2'*64,'phenotype_commitment':'3'*64},'pair_different_program':True,'pair_different_candidate_genome':True,'authority':g.AUTH}
 x['receipt_sha256']=g.sha(x); return x
def test_valid_receipt_allows_only_preregistration_not_holdout():
 out=g.validate_native_pair_receipt(_receipt()); assert out['status']=='ALLOW_PRE_REGISTRATION_ONLY'; assert out['ciphertext_holdout_authorized'] is False
def test_source_drift_fails_closed():
 x=_receipt(); x['implementation_commit']='0'*64
 try:g.validate_native_pair_receipt(x)
 except g.EvaluatorGateError:pass
 else:raise AssertionError('source drift admitted')
def test_receipt_tamper_fails_closed():
 x=_receipt(); x['relational']['candidate_genome_id']='4'*64
 try:g.validate_native_pair_receipt(x)
 except g.EvaluatorGateError:pass
 else:raise AssertionError('tamper admitted')