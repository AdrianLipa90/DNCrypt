from __future__ import annotations
import importlib.util
from itertools import permutations
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
S=importlib.util.spec_from_file_location("mw",ROOT/"tools/noema_mutation_word_native_v1.py"); mw=importlib.util.module_from_spec(S); assert S.loader; S.loader.exec_module(mw)

def test_all_24_native_words_close_and_noncommute():
 r=mw.all_permutation_receipt(); assert r["orders_tested"]==24; assert r["all_closed"] is True; assert r["noncommutative"] is True; assert r["unique_final_semantic_states"]>1

def test_each_word_preserves_typed_ir():
 for order in permutations(mw.OPERATORS):
  x=mw.execute_word(order); assert x.level.name=="CONCEPT"; assert x.semantic_id; assert len({c.unit_id for c in x.children})==len(x.children)