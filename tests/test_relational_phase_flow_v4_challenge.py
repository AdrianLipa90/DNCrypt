from __future__ import annotations
import hashlib
import importlib.util
from pathlib import Path

from dncrypt.genome import initial_genome

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("v4challenge",ROOT/"tools/relational_phase_flow_v4_challenge.py")
v4c=importlib.util.module_from_spec(SPEC); assert SPEC.loader is not None; SPEC.loader.exec_module(v4c)


def fixture(label: bytes=b"v4"):
    parent=initial_genome(bytes(range(64)))
    program=v4c.ab.fixed_program()
    entropy=hashlib.shake_256(label).digest(64)
    return parent,program,entropy


def test_B_and_F_share_exact_native_substrate_and_nuisance_signature():
    parent,program,e=fixture(b"pair")
    pair=v4c.compare_candidate_pair(parent,program,fresh_entropy=e)
    assert pair["same_substrate"] is True
    assert pair["exact_nuisance_match"] is True


def test_F_has_no_crypto_or_security_authority():
    parent,program,e=fixture(b"authority")
    _,binding=v4c.mutate_with_strategy(parent,program,fresh_entropy=e,strategy="F_RELATIONAL_MATCHED_NUISANCE_V4")
    assert binding.frozen_aead_changed is False
    assert binding.cryptographic_entropy_authority is False
    assert binding.security_admission_authority is False
    assert binding.relational_source_commitment is not None


def test_F_never_expands_native_allowed_loci_or_budget():
    parent,program,e=fixture(b"bounds")
    _,binding=v4c.mutate_with_strategy(parent,program,fresh_entropy=e,strategy="F_RELATIONAL_MATCHED_NUISANCE_V4")
    assert set(binding.selected_loci).issubset(binding.allowed_loci)
    assert set(binding.selected_loci).issubset(binding.candidate_pool)
    assert len(binding.selected_loci) <= binding.mutation_budget


def test_many_candidates_preserve_exact_nuisance_matching():
    parent=initial_genome(bytes(range(64))); program=v4c.ab.fixed_program()
    changed=0
    for i in range(256):
        e=hashlib.shake_256(b"candidate"+i.to_bytes(4,"big")).digest(64)
        pair=v4c.compare_candidate_pair(parent,program,fresh_entropy=e)
        assert pair["same_substrate"] is True
        assert pair["exact_nuisance_match"] is True
        changed += int(pair["selection_changed"])
    assert changed > 0