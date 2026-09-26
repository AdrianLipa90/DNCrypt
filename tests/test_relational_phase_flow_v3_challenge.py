from __future__ import annotations
import hashlib
import importlib.util
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("relflow",ROOT/"tools/relational_phase_flow_v3_challenge.py")
rel=importlib.util.module_from_spec(SPEC); assert SPEC.loader is not None; SPEC.loader.exec_module(rel)


def entropy(label: bytes=b"x") -> bytes:
    return hashlib.shake_256(label).digest(64)


def test_core_fixture_is_byte_exact_with_noema():
    s=rel.core.RelationalSourceTriple((2,6,1),(4,12,2),(8,18,3))
    assert rel.core.state_dict(s)["state_sha256"]=="09d6d2059bfaae9d3825827b8f5fcff9aca9846912d864d8c23152e44d80a4e1"
    assert rel.core.rank_loci(s,range(36),b"fixture")[:12]==[2,9,13,10,7,6,12,1,0,15,18,21]


def test_relational_source_uses_three_independent_ordered_streams():
    s=rel.relational_source_triple(entropy())
    assert len(s.previous_previous)==3 and len(s.previous)==3 and len(s.current)==3
    assert len(s.commitment)==64


def test_rank_is_deterministic_and_permutation_of_allowed_loci():
    e=entropy(); s=rel.relational_source_triple(e); loci=tuple(range(36))
    a=rel._rank_relational_v3(loci,e,s,0); b=rel._rank_relational_v3(loci,e,s,0)
    assert a==b
    assert sorted(a)==list(loci)


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
    assert binding.relational_source_commitment is not None


def test_strategy_surface_contains_only_null_and_v3():
    assert rel.STRATEGIES == ("B_RANDOM_LOCUS_NULL","E_RELATIONAL_PHASE_FLOW_V3")