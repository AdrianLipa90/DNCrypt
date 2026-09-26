from __future__ import annotations
import json
from pathlib import Path
from tools.noema_prime_gap_codon_native_v61 import execute_native_word
ROOT=Path(__file__).resolve().parents[1]; F=json.loads((ROOT/'tests/fixtures/noema_prime_gap_codon_v6_1_pair.json').read_text())
def test_both_cross_repo_words_close_on_native_dncrypt_and_compile():
 a=execute_native_word(F['relational'],mutation_entropy=b'R'*64); b=execute_native_word(F['matched_null'],mutation_entropy=b'R'*64)
 for x in (a,b): assert x['status']=='PASS_NATIVE_STRUCTURAL_CLOSURE'; assert len(x['operator_trace'])==12; assert x['authority']['security_admission'] is False; assert len(x['candidate_genome_id'])==64
 assert a['final_program_semantic_id']!=b['final_program_semantic_id']
 assert a['candidate_genome_id']!=b['candidate_genome_id']