from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
from tools.noema_prime_gap_codon_native_v61 import execute_native_word

SCHEMA='DNCRYPT_NOEMA_PRIME_GAP_CODON_NATIVE_PAIR_RECEIPT_V6_1'
IMPLEMENTATION_COMMIT='5099af2fe59f38ead4956ad8b1570946b5a48dca'
NOEMA_SOURCE_COMMIT='69b5fbcdcc37094831d04061ea88a876fe6b84af'

def canon(v): return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def sha(v): return hashlib.sha256(canon(v)).hexdigest()

def build_receipt(fixture:dict)->dict:
    entropy=hashlib.sha512(b'DNCrypt/NOEMA/codon-v6.1/native-conformance/frozen-test-entropy').digest()
    a=execute_native_word(fixture['relational'],mutation_entropy=entropy)
    b=execute_native_word(fixture['matched_null'],mutation_entropy=entropy)
    if a['status']!='PASS_NATIVE_STRUCTURAL_CLOSURE' or b['status']!='PASS_NATIVE_STRUCTURAL_CLOSURE':
        raise RuntimeError('native structural closure failed')
    if a['final_program_semantic_id']==b['final_program_semantic_id']:
        raise RuntimeError('paired words collapsed to same final program')
    if a['candidate_genome_id']==b['candidate_genome_id']:
        raise RuntimeError('paired words collapsed to same candidate genome')
    body={
      'schema':SCHEMA,'status':'PASS_NATIVE_PAIR_CLOSURE','implementation_commit':IMPLEMENTATION_COMMIT,
      'noema_source_commit':NOEMA_SOURCE_COMMIT,'fixture_sha256':fixture['fixture_sha256'],
      'relational':{'word_sha256':a['word_sha256'],'final_program_semantic_id':a['final_program_semantic_id'],'candidate_genome_id':a['candidate_genome_id'],'phenotype_commitment':a['phenotype_commitment']},
      'matched_null':{'word_sha256':b['word_sha256'],'final_program_semantic_id':b['final_program_semantic_id'],'candidate_genome_id':b['candidate_genome_id'],'phenotype_commitment':b['phenotype_commitment']},
      'pair_different_program':True,'pair_different_candidate_genome':True,
      'authority':{'candidate_only':True,'security_admission':False,'cryptographic_entropy':False,'changes_frozen_aead':False}
    }
    body['receipt_sha256']=sha(body)
    return body

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--fixture',required=True); ap.add_argument('--output',required=True); ns=ap.parse_args()
    fixture=json.loads(Path(ns.fixture).read_text()); out=build_receipt(fixture)
    Path(ns.output).write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'status':out['status'],'receipt_sha256':out['receipt_sha256']},sort_keys=True))
if __name__=='__main__': main()