from __future__ import annotations
import math
from pathlib import Path
import sys

import pytest

from dncrypt.phase_entropy_v01 import (
    DNCryptPhaseEntropyProvider,
    PhaseEntropyError,
    PhaseFrame,
    binary_health_report,
    build_evidence,
    condition_entropy,
    mod2pi,
    mod4pi,
    sheet_bit,
    sheet_decomposition,
    shannon_sheet_entropy_nats,
    unwrap_coordinate,
)


def test_double_cover_sheet_and_ln2():
    assert sheet_decomposition(0.25) == pytest.approx((0.25, 0))
    theta, bit = sheet_decomposition(2*math.pi + 0.25)
    assert theta == pytest.approx(0.25)
    assert bit == 1
    assert sheet_bit(4*math.pi + 0.25) == 0
    assert shannon_sheet_entropy_nats(0.5) == pytest.approx(math.log(2.0))


def test_unwrap_crosses_2pi_continuously():
    seq = [6.0, 6.2, 0.05, 0.2]
    u = unwrap_coordinate(seq)
    assert u[0] == pytest.approx(6.0)
    assert u[2] > 2*math.pi
    assert sheet_bit(u[0]) == 0
    assert sheet_bit(u[2]) == 1


def test_health_rejects_predictable_alternating_sheet_bits():
    bits = [i & 1 for i in range(512)]
    report = binary_health_report(bits)
    assert report.mcv_min_entropy_bits == pytest.approx(1.0)
    assert report.markov_min_entropy_bits == pytest.approx(0.0)
    assert not report.gate_pass


def test_health_rejects_stuck_source():
    report = binary_health_report([0]*512)
    assert not report.repetition_count_pass
    assert not report.gate_pass


def _fixture_frames(n=80):
    # Deterministic test fixture exercises gate machinery under DETERMINISTIC_TEST_FIXTURE classification.
    # Irregular signs come from a fixed xorshift state so tests remain reproducible.
    state = 0x12345678
    t = 1_000_000_000
    phases = [0.1*i for i in range(36)]
    out=[]
    for k in range(n):
        state ^= (state << 13) & 0xffffffff
        state ^= state >> 17
        state ^= (state << 5) & 0xffffffff
        jitter = (state & 0xffff) + 1
        t += 120_000_000 + jitter
        row=[]
        for i,p in enumerate(phases):
            state ^= (state << 13) & 0xffffffff
            state ^= state >> 17
            state ^= (state << 5) & 0xffffffff
            eps = ((state & 0xffff)/65535.0 - 0.5)*0.04
            phases[i] = (p + 0.17 + eps) % (2*math.pi)
            row.append(phases[i])
        out.append(PhaseFrame(t, tuple(row)))
    return tuple(out)


def test_fixture_builds_geometry_and_noise_evidence():
    ev = build_evidence(_fixture_frames(), source_class='DETERMINISTIC_TEST_FIXTURE')
    assert ev.frame_count == 80
    assert len(ev.sheet_bits) == 80*36
    assert len(ev.phase_acceleration_bits) > 1000
    assert ev.geometry_entropy_nats_per_balanced_sheet_bit == pytest.approx(math.log(2.0))


def test_conditioning_requires_health_gate():
    frames=[]
    for k in range(10):
        frames.append(PhaseFrame(1_000_000_000 + k*100_000_000, tuple([0.1]*36)))
    ev=build_evidence(frames, source_class='DETERMINISTIC_TEST_FIXTURE')
    assert not ev.health.gate_pass
    with pytest.raises(PhaseEntropyError):
        condition_entropy(ev,44)


def test_provider_domain_separates_purposes_when_gate_passes():
    ev=build_evidence(_fixture_frames(100), source_class='DETERMINISTIC_TEST_FIXTURE')
    assert ev.health.gate_pass
    assert ev.estimated_min_entropy_bits >= 256.0
    provider=DNCryptPhaseEntropyProvider(ev)
    a=provider.take(44,purpose='message')
    b=provider.take(44,purpose='message')
    c=provider.take(64,purpose='mutation')
    assert len(a)==44 and len(b)==44 and len(c)==64
    assert a != b


def test_pnv_declares_double_cover_and_health_gate():
    text=(Path(__file__).parents[1]/'native'/'experimental'/'PNCS_PHASE_ENTROPY_V0_1.pnv').read_text()
    for token in ['ENTROPY.MOD2PI','ENTROPY.MOD4PI','ENTROPY.SHEET','ENTROPY.SHANNON_HALF','ENTROPY.HEALTH_GATE','CRYPTO.SHAKE256']:
        assert token in text


def test_direct_extraction_respects_measured_entropy_budget():
    ev=build_evidence(_fixture_frames(100), source_class='DETERMINISTIC_TEST_FIXTURE')
    assert ev.health.gate_pass
    allowed=int(ev.estimated_min_entropy_bits//8)
    assert len(condition_entropy(ev, min(32, allowed))) == min(32, allowed)
    with pytest.raises(PhaseEntropyError):
        condition_entropy(ev, allowed + 1)


def test_biased_sheet_entropy_is_below_ln2():
    assert shannon_sheet_entropy_nats(0.9) < math.log(2.0)


def test_live_admission_rejects_stale_seal(tmp_path):
    import json, os, struct, time
    from dncrypt.phase_entropy_v01 import verify_live_admission
    root=tmp_path
    (root/'session').mkdir()
    now=time.time_ns()
    (root/'session'/'startpoint.json').write_text(json.dumps({'status':'VERIFIED'}))
    (root/'session'/'fast_admission.json').write_text(json.dumps({
        'status':'ACTIVE','no_static_fallback':True,'sealed_unix_ns':now-int(120e9),
        'ac_aux_pid':os.getpid(),'aux_pid':os.getpid(),'tether_pid':os.getpid(),
    }))
    (root/'phi').write_bytes(struct.pack('<36d', *([0.0]*36)))
    with pytest.raises(PhaseEntropyError, match='seal is stale'):
        verify_live_admission(root)


def test_phase_entropy_pnv_uses_existing_relation_alphabet():
    text=(Path(__file__).parents[1]/'native'/'experimental'/'PNCS_PHASE_ENTROPY_V0_1.pnv').read_text()
    allowed={'IDENTITY','DIFFERENCE','COMPOSITION','TRANSFORM','CONDITION','RESOLVE','DERIVE','ORDER'}
    kinds={line.split()[2] for line in text.splitlines() if line.startswith('OP ')}
    assert kinds <= allowed


def test_dncrypt_v03_binds_phase_entropy_path():
    text=(Path(__file__).parents[1]/'native'/'programs'/'DNCRYPT_NATIVE_PNCS_V0_3.pnv').read_text()
    assert 'PATH.PNCS.PHASE_ENTROPY' in text
    assert 'DNC.ENTROPY.PHASE.SEED' in text
    assert 'DNC.ENTROPY.MESSAGE44' in text
    assert 'DNC.ENTROPY.MUTATION_N64' in text
