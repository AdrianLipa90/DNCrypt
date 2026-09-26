from __future__ import annotations
import hashlib, sys
from itertools import permutations
sys.path.insert(0,'/mnt/data/dncrypt_native_exact/src')
sys.path.insert(0,'/mnt/data/noema_mutword_v5/src')
sys.path.insert(0,'/mnt/data/dncrypt_mutword_native')
sys.path.insert(0,'/mnt/data/dncrypt_mutword_native/tools')

from noema_telekom.relational_phase_flow import RelationalPhaseFlow36D
from noema_telekom.mutation_word_v5 import relational_word, MutationWord
from noema_telekom.mutation_word_v5_1 import build_matched_word_batch
import noema_mutation_word_native_v1 as fixture
from noema_mutation_word_native_v5_3 import execute_native_word_v5_3, semantic_parameter_map


def state():
    return RelationalPhaseFlow36D.encode((2,6,2),(4,12,1),(2,18,3))


def test_all_24_orders_close_with_variable_semantic_parameters():
    w=relational_word(state(),fresh_entropy_commitment=hashlib.sha256(b'v53').hexdigest())
    by={t.operation:t for t in w.tokens}
    ids=set()
    for order in permutations(by):
        ww=MutationWord(w.strategy,tuple(by[op] for op in order),w.source_state_sha256,w.fresh_entropy_commitment)
        child, receipt=execute_native_word_v5_3(ww,initial_program=fixture.fixture_program(),donor_program=fixture.fixture_program(donor=True))
        assert child.semantic_id==receipt.final_semantic_id
        assert len(receipt.steps)==4
        ids.add(child.semantic_id)
    assert len(ids)>1


def test_matched_null_preserves_semantic_parameter_map():
    states=[
      RelationalPhaseFlow36D.encode((2+i,6+i,1),(4+i,8+i,2),(6+i,10+i,3))
      for i in range(8)
    ]
    es=[hashlib.sha256(f'e{i}'.encode()).hexdigest() for i in range(8)]
    batch=build_matched_word_batch(states,fresh_entropy_commitments=es)
    for a,b in zip(batch.relational,batch.matched_null):
        assert semantic_parameter_map(a)==semantic_parameter_map(b)
        ca,ra=execute_native_word_v5_3(a,initial_program=fixture.fixture_program(),donor_program=fixture.fixture_program(donor=True))
        cb,rb=execute_native_word_v5_3(b,initial_program=fixture.fixture_program(),donor_program=fixture.fixture_program(donor=True))
        assert ca.semantic_id==ra.final_semantic_id
        assert cb.semantic_id==rb.final_semantic_id