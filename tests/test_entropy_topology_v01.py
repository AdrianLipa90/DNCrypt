import math
from dncrypt.phase_entropy_v01 import PhaseFrame
from dncrypt.entropy_topology_v01 import binary_mutual_information,pair_predictor_advantage,build_topology,selected_combined_bits,validate_selected_stream

def frames(n=96):
    out=[]
    for t in range(n):
        phi=[]
        for i in range(36):
            # deterministic multi-frequency fixture with coordinate-specific perturbation
            x=(0.31*t + 0.017*i*t*t + 0.11*math.sin((i+1)*(t+1)*0.37))%(2*math.pi)
            phi.append(x)
        out.append(PhaseFrame(1_000_000_000+t*1_000_000,tuple(phi)))
    return tuple(out)

def test_mutual_information_identical_is_high():
    a=(0,1)*64
    assert binary_mutual_information(a,a) > 0.99
    assert pair_predictor_advantage(a,a)==0.5

def test_mutual_information_independent_pattern_low():
    a=tuple((i>>0)&1 for i in range(256)); b=tuple((i>>1)&1 for i in range(256))
    assert binary_mutual_information(a,b) < 1e-12

def test_topology_schema_and_bounds():
    r=build_topology(frames())
    assert r['schema']=='PNCS_36D_ENTROPY_TOPOLOGY_V0_1'
    assert len(r['channels'])==36
    assert len(r['pairs'])==630
    assert 0 <= r['selection']['selected_count'] <= 36

def test_selected_stream_validation():
    f=frames(); r=build_topology(f)
    if r['selection']['selected_coordinates']:
        bits=selected_combined_bits(f,r['selection']['selected_coordinates'])
        assert bits
        v=validate_selected_stream(f,r)
        assert v['selected_count']==len(r['selection']['selected_coordinates'])
