import hashlib,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import relational_phase_flow_core_v4 as v4

ALLOWED=(0,1,2,3,5,6,7,9,17,19,20,23,28,30,32,34,35)

def test_nuisance_signature_ignores_observable():
    assert v4.nuisance_signature((0,5))==v4.nuisance_signature((3,2))

def test_selector_matches_skeleton_shell_flavour():
    e=hashlib.shake_256(b'fixture').digest(64);s=v4.v3.relational_source_triple(e);sk=(0,23)
    out=v4.select_subset(s,ALLOWED,sk,e)
    assert v4.nuisance_signature(out)==v4.nuisance_signature(sk)

def test_selector_deterministic():
    e=hashlib.shake_256(b'deterministic').digest(64);s=v4.v3.relational_source_triple(e);sk=(1,28)
    assert v4.select_subset(s,ALLOWED,sk,e)==v4.select_subset(s,ALLOWED,sk,e)

def test_stationary_group_scores_zero():
    s=v4.v3.RelationalSourceTriple((6,30,2),(6,30,2),(6,30,2))
    assert v4.group_scores(s)==(0.0,)*12