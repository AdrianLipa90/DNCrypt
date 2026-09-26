import hashlib,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import exact_dncrypt_v061_harness as h
import relational_phase_flow_core_v4 as v4

EXPECTED=(0,1,2,3,5,6,7,9,17,19,20,23,28,30,32,34,35)

def test_fixed_phenotype_matches_frozen_prehholdout_receipt():
    p,c=h.phenotype()
    assert tuple(p['allowed_loci'])==EXPECTED
    assert p['mutation_budget']==2
    assert len(c)==64

def test_candidate_pair_exact_nuisance_match_over_4096_cases():
    parent=h.initial_genome(bytes(range(64))); p,commit=h.phenotype(); allowed=tuple(p['allowed_loci']); changed_count=0; exact=0
    for i in range(4096):
        e=hashlib.shake_256(b'v4-candidate'+i.to_bytes(8,'big')).digest(64)
        _,_,u=h.bound_unconstrained(parent,e)
        changed=tuple(j for j in allowed if u.operator_vector[j]!=parent.operator_vector[j]); pool=changed if changed else allowed
        sk=tuple(h.null_order(pool,e)[:min(p['mutation_budget'],len(pool))])
        s=v4.v3.relational_source_triple(e); f=v4.select_subset(s,pool,sk,e)
        assert v4.nuisance_signature(f)==v4.nuisance_signature(sk)
        exact+=1; changed_count+=int(set(f)!=set(sk))
    assert exact==4096
    assert changed_count>0