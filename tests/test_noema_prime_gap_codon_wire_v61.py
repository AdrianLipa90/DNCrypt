from __future__ import annotations
import importlib.util,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
S=importlib.util.spec_from_file_location('wire',ROOT/'tools/noema_prime_gap_codon_wire_v61.py'); w=importlib.util.module_from_spec(S); assert S.loader; S.loader.exec_module(w)
F=json.loads((ROOT/'tests/fixtures/noema_prime_gap_codon_v6_1_pair.json').read_text())
def test_cross_repo_fixture_words_validate_and_match_exact_tokens():
 a=w.validate_word_payload(F['relational']); b=w.validate_word_payload(F['matched_null']); assert a['status']==b['status']=='PASS'; assert w.exact_token_multiset_match(F['relational'],F['matched_null']); assert F['relational']['word_sha256']!=F['matched_null']['word_sha256']
def test_authority_drift_fails_closed():
 x=json.loads(json.dumps(F['relational'])); x['authority']['security_admission']=True
 try:w.validate_word_payload(x)
 except w.WireError:pass
 else:raise AssertionError('authority drift admitted')
def test_word_hash_drift_fails_closed():
 x=json.loads(json.dumps(F['relational'])); x['tokens'][0]['activity']+=0.001
 try:w.validate_word_payload(x)
 except w.WireError:pass
 else:raise AssertionError('hash drift admitted')