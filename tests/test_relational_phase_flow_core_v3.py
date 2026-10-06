from __future__ import annotations
import hashlib, math, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import relational_phase_flow_core_v3 as core


def test_byte_exact_noema_fixture_hash():
    s=core.RelationalSourceTriple((2,6,1),(4,12,2),(8,18,3))
    assert core.state_dict(s)['state_sha256']=='09d6d2059bfaae9d3825827b8f5fcff9aca9846912d864d8c23152e44d80a4e1'


def test_byte_exact_noema_fixture_ranking():
    s=core.RelationalSourceTriple((2,6,1),(4,12,2),(8,18,3))
    rank=core.rank_loci(s,range(36),b'fixture')
    assert rank[:12]==[2,9,13,10,7,6,12,1,0,15,18,21]
    assert sorted(rank)==list(range(36))


def test_stationary_has_zero_flow_curvature_strength():
    s=core.RelationalSourceTriple((6,30,2),(6,30,2),(6,30,2))
    flow,kappa,strength,values,scores=core.components(s)
    assert max(map(abs,flow))<1e-15
    assert max(map(abs,kappa))<1e-15
    assert max(map(abs,strength))<1e-15
    assert max(map(abs,scores))<1e-15


def test_history_change_changes_state_hash():
    a=core.RelationalSourceTriple((2,6,1),(4,12,2),(8,18,3))
    b=core.RelationalSourceTriple((2,6,1),(6,12,2),(8,18,3))
    assert core.state_dict(a)['state_sha256']!=core.state_dict(b)['state_sha256']


def test_three_streams_are_independent_but_ordered():
    s=core.relational_source_triple(hashlib.shake_256(b'independent').digest(64))
    assert len(s.previous_previous)==len(s.previous)==len(s.current)==3
    assert s.previous_previous!=s.previous or s.previous!=s.current


def test_z3_balance_is_numerically_closed():
    s=core.RelationalSourceTriple((2,6,1),(4,12,2),(8,18,3))
    state=core.state_dict(s)
    assert float(state['max_flavour_balance_residual'])<1e-12