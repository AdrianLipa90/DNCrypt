from __future__ import annotations
import hashlib,json
from typing import Mapping
SCHEMA='DNCRYPT_NOEMA_PRIME_GAP_CODON_NATIVE_PAIR_RECEIPT_V6_1'
EXPECTED_IMPLEMENTATION='5099af2fe59f38ead4956ad8b1570946b5a48dca'
EXPECTED_NOEMA='69b5fbcdcc37094831d04061ea88a876fe6b84af'
AUTH={'candidate_only':True,'security_admission':False,'cryptographic_entropy':False,'changes_frozen_aead':False}
class EvaluatorGateError(ValueError): pass
def canon(v): return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def sha(v): return hashlib.sha256(canon(v)).hexdigest()
def hex64(x): return isinstance(x,str) and len(x)==64 and all(c in '0123456789abcdef' for c in x)
def validate_native_pair_receipt(v:Mapping[str,object])->dict:
    x=dict(v)
    if x.get('schema')!=SCHEMA or x.get('status')!='PASS_NATIVE_PAIR_CLOSURE': raise EvaluatorGateError('native receipt schema/status')
    if x.get('implementation_commit')!=EXPECTED_IMPLEMENTATION or x.get('noema_source_commit')!=EXPECTED_NOEMA: raise EvaluatorGateError('source binding')
    if x.get('authority')!=AUTH: raise EvaluatorGateError('authority drift')
    if x.get('pair_different_program') is not True or x.get('pair_different_candidate_genome') is not True: raise EvaluatorGateError('pair closure/diversity')
    if not hex64(x.get('fixture_sha256')): raise EvaluatorGateError('fixture hash')
    for arm in ('relational','matched_null'):
        a=x.get(arm)
        if not isinstance(a,dict): raise EvaluatorGateError(arm)
        for k in ('word_sha256','final_program_semantic_id','candidate_genome_id','phenotype_commitment'):
            if not hex64(a.get(k)): raise EvaluatorGateError(f'{arm}.{k}')
    declared=x.get('receipt_sha256')
    if not hex64(declared): raise EvaluatorGateError('receipt hash')
    body=dict(x); body.pop('receipt_sha256')
    if sha(body)!=declared: raise EvaluatorGateError('receipt hash mismatch')
    return {'schema':'DNCRYPT_NOEMA_CODON_EVALUATOR_GATE_V6_1','status':'ALLOW_PRE_REGISTRATION_ONLY','ciphertext_holdout_authorized':False,'security_admission':False,'native_receipt_sha256':declared}