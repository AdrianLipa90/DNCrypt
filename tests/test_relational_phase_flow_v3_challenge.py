from __future__ import annotations
import hashlib
import importlib.util
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("relflow",ROOT/"tools/relational_phase_flow_v3_challenge.py")
rel=importlib.util.module_from_spec(SPEC); assert SPEC.loader is not None; SPEC.loader.exec_module(rel)


def entropy(label: bytes=b"x") -> bytes:
    return hashlib.shake_256(label).digest(64)


def test_relational_source_uses_three_independent_ordered_streams():
    s=rel.relational_source_pair(entropy())
    assert len(s.deltas)==3
    assert len(s.commitment)==64


def test_zero_relation_has_zero_scores_and_energy():
    s=rel.RelationalSourcePair(6,6,30,30,4,4)
    assert rel.relational_orbit_scores(s)==(0.0,)*12
    assert rel.relational_observable_energies(s)==(0.0,0.0,0.0)


def test_swapping_source_reverses_link_but_preserves_chord_score():
    a=rel.RelationalSourcePair(6,10,30,42,4,2)
    b=rel.RelationalSourcePair(10,6,42,30,2,4)
    assert b.deltas==tuple(-x for x in a.deltas)
    assert rel.relational_orbit_scores(a)==rel.relational_orbit_scores(b)


def test_rank_is_deterministic_and_permutation_of_allowed_loci():
    e=entropy(); s=rel.relational_source_pair(e); loci=tuple(range(36))
    a=rel._rank_relational_v3(loci,e,s,0); b=rel._rank_relational_v3(loci,e,s,0)
    assert a==b
    assert sorted(a)==list(loci)


def test_relational_ranking_interleaves_observables_in_first_orbits():
    e=entropy(b"interleave"); s=rel.relational_source_pair(e); loci=tuple(range(36))
    rank=rel._rank_relational_v3(loci,e,s,0)
    first_orbits=[]
    for locus in rank:
        orbit=locus//3
        if orbit not in first_orbits: first_orbits.append(orbit)
        if len(first_orbits)==3: break
    assert {o%3 for o in first_orbits}=={0,1,2}


def test_null_and_relational_share_native_mutation_substrate():
    parent=rel.base.initial_genome(bytes(range(64))); program=rel.ab.fixed_program(); e=entropy(b"substrate")
    b,_=rel.mutate_with_strategy(parent,program,fresh_entropy=e,strategy="B_RANDOM_LOCUS_NULL",mutation_tick=0)
    v,_=rel.mutate_with_strategy(parent,program,fresh_entropy=e,strategy="E_RELATIONAL_PHASE_FLOW_V3",mutation_tick=0)
    assert b.route==v.route
    assert b.phase_seed_hex==v.phase_seed_hex
    assert b.mutation_nonce_hex==v.mutation_nonce_hex
    assert b.parent_id==v.parent_id and b.generation==v.generation


def test_binding_has_no_crypto_or_security_authority():
    parent=rel.base.initial_genome(bytes(range(64))); program=rel.ab.fixed_program(); e=entropy(b"authority")
    _,binding=rel.mutate_with_strategy(parent,program,fresh_entropy=e,strategy="E_RELATIONAL_PHASE_FLOW_V3",mutation_tick=0)
    assert binding.frozen_aead_changed is False
    assert binding.cryptographic_entropy_authority is False
    assert binding.security_admission_authority is False