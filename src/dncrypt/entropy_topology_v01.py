from __future__ import annotations
from dataclasses import dataclass
import math
from typing import Sequence
from .phase_entropy_v01 import PhaseFrame, unwrap_frames, binary_health_report, PhaseEntropyError

DIM=36

@dataclass(frozen=True, slots=True)
class ChannelEntropy:
    index:int; sample_count:int; hmin_per_bit:float; estimated_bits:float; bias:float; predictor_advantage:float; gate_pass:bool
    @property
    def payload(self): return self.__dict__ if hasattr(self,'__dict__') else {'index':self.index,'sample_count':self.sample_count,'hmin_per_bit':self.hmin_per_bit,'estimated_bits':self.estimated_bits,'bias':self.bias,'predictor_advantage':self.predictor_advantage,'gate_pass':self.gate_pass}

def coordinate_accel_bits(frames:Sequence[PhaseFrame], coord:int)->tuple[int,...]:
    if not 0<=coord<DIM: raise PhaseEntropyError('coordinate out of range')
    if len(frames)<3: return tuple()
    lifted=unwrap_frames(frames)
    v=[lifted[t+1][coord]-lifted[t][coord] for t in range(len(lifted)-1)]
    out=[]
    for a,b in zip(v,v[1:]):
        x=b-a
        if x!=0.0: out.append(1 if x>0 else 0)
    return tuple(out)

def binary_mutual_information(a:Sequence[int],b:Sequence[int])->float:
    n=min(len(a),len(b))
    if n==0:return 0.0
    a=tuple(a[:n]); b=tuple(b[:n])
    joint={(x,y):0 for x in (0,1) for y in (0,1)}
    for x,y in zip(a,b): joint[(int(x),int(y))]+=1
    ca=[a.count(0),a.count(1)]; cb=[b.count(0),b.count(1)]
    mi=0.0
    for x in (0,1):
      for y in (0,1):
        c=joint[(x,y)]
        if c:
          p=c/n; px=ca[x]/n; py=cb[y]/n
          mi+=p*math.log2(p/(px*py))
    return mi

def pair_predictor_advantage(a:Sequence[int],b:Sequence[int])->float:
    n=min(len(a),len(b))
    if not n:return 0.5
    same=sum(x==y for x,y in zip(a[:n],b[:n]))/n
    return max(same,1-same)-0.5

def build_topology(frames:Sequence[PhaseFrame], *, mi_cutoff:float=0.08, pair_adv_cutoff:float=0.12, min_hmin:float=0.50):
    streams=[coordinate_accel_bits(frames,i) for i in range(DIM)]
    channels=[]
    for i,s in enumerate(streams):
        h=binary_health_report(s,minimum_samples=max(32,min(64,len(s))),minimum_hmin_per_bit=min_hmin,maximum_predictor_advantage=0.20,repetition_cutoff=24)
        channels.append(ChannelEntropy(i,h.sample_count,h.estimated_min_entropy_per_bit,h.sample_count*h.estimated_min_entropy_per_bit,h.bias,h.predictor_advantage,h.gate_pass))
    pairs=[]
    for i in range(DIM):
      for j in range(i+1,DIM):
        mi=binary_mutual_information(streams[i],streams[j]); adv=pair_predictor_advantage(streams[i],streams[j])
        pairs.append({'i':i,'j':j,'mutual_information_bits':mi,'pair_predictor_advantage':adv})
    eligible=sorted([c for c in channels if c.gate_pass],key=lambda c:(-c.hmin_per_bit,-c.estimated_bits,c.index))
    selected=[]
    pairmap={(p['i'],p['j']):p for p in pairs}
    for c in eligible:
      ok=True
      for s in selected:
        p=pairmap[(min(c.index,s.index),max(c.index,s.index))]
        if p['mutual_information_bits']>mi_cutoff or p['pair_predictor_advantage']>pair_adv_cutoff: ok=False; break
      if ok:selected.append(c)
    budget=sum(c.estimated_bits for c in selected)
    return {'schema':'PNCS_36D_ENTROPY_TOPOLOGY_V0_1','frame_count':len(frames),'channels':[c.payload for c in channels], 'pairs':pairs, 'selection':{'mi_cutoff':mi_cutoff,'pair_predictor_advantage_cutoff':pair_adv_cutoff,'selected_coordinates':[c.index for c in selected],'selected_count':len(selected),'conservative_selected_budget_bits':budget}, 'max_pair_mi_bits':max((p['mutual_information_bits'] for p in pairs),default=0.0),'max_pair_predictor_advantage':max((p['pair_predictor_advantage'] for p in pairs),default=0.0)}


def selected_combined_bits(frames:Sequence[PhaseFrame], selected_coordinates:Sequence[int])->tuple[int,...]:
    coords=tuple(int(i) for i in selected_coordinates)
    if not coords or len(set(coords))!=len(coords) or any(i<0 or i>=DIM for i in coords):
        raise PhaseEntropyError('selected coordinates must be unique valid 36D indices')
    streams=[coordinate_accel_bits(frames,i) for i in coords]
    n=min(map(len,streams),default=0)
    if n<=0:return tuple()
    return tuple(bit for row in zip(*(s[:n] for s in streams)) for bit in row)

def validate_selected_stream(frames:Sequence[PhaseFrame], topology:dict[str,object]):
    sel=tuple(int(i) for i in topology['selection']['selected_coordinates'])
    bits=selected_combined_bits(frames,sel)
    health=binary_health_report(bits,minimum_samples=256,minimum_hmin_per_bit=0.50,maximum_predictor_advantage=0.20,repetition_cutoff=32)
    return {'schema':'PNCS_36D_ENTROPY_SELECTED_STREAM_VALIDATION_V0_1','selected_coordinates':list(sel),'selected_count':len(sel),'sample_count':len(bits),'health':health.payload,'estimated_min_entropy_bits':len(bits)*health.estimated_min_entropy_per_bit}
