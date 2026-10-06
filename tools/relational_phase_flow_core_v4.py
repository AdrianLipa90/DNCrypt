from __future__ import annotations
import hashlib,itertools,importlib.util,math,sys
from pathlib import Path
from typing import Sequence

ROOT=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location('relflow_v3_core',ROOT/'relational_phase_flow_core_v3.py')
v3=importlib.util.module_from_spec(SPEC); assert SPEC.loader is not None; sys.modules[SPEC.name]=v3; SPEC.loader.exec_module(v3)
DIM=36


def center_mod(n:int,modulus:int)->int:
    r=int(n)%int(modulus)
    if r>=modulus/2:r-=modulus
    return int(r)


def squash(x:float)->float:
    x=abs(float(x)); return x/(1.0+x)


def group_scores(source:v3.RelationalSourceTriple)->tuple[float,...]:
    pp,p,c=source.previous_previous,source.previous,source.current
    out=[]
    for shell in v3.SHELLS:
        for o in range(3):
            dprev=center_mod(p[o]-pp[o],shell)
            dnow=center_mod(c[o]-p[o],shell)
            kappa=center_mod(dnow-dprev,shell)
            out.append(0.5*squash(dnow)+0.5*squash(kappa))
    return tuple(out)


def nuisance_signature(loci:Sequence[int]):
    xs=tuple(int(i) for i in loci)
    shells=tuple(sum(i//9==s for i in xs) for s in range(4))
    flavours=tuple(sum(i%3==f for i in xs) for f in range(3))
    return shells,flavours


def select_subset(source:v3.RelationalSourceTriple,pool:Sequence[int],skeleton:Sequence[int],fresh_entropy:bytes)->tuple[int,...]:
    pool_t=tuple(sorted(set(int(i) for i in pool))); sk=tuple(int(i) for i in skeleton)
    if not pool_t or not sk or not set(sk).issubset(pool_t):raise ValueError('invalid pool/skeleton')
    if any(i<0 or i>=DIM for i in pool_t):raise ValueError('locus outside 0..35')
    k=len(sk)
    if math.comb(len(pool_t),k)>100_000:raise ValueError('bounded selector combinatorics exceeded')
    target=nuisance_signature(sk); scores=group_scores(source)
    state_hash=str(v3.state_dict(source)['state_sha256'])
    seed=hashlib.sha256(bytes(fresh_entropy)).digest()+bytes.fromhex(state_hash)
    best=None
    for comb in itertools.combinations(pool_t,k):
        if nuisance_signature(comb)!=target:continue
        geometry=sum(scores[i//3] for i in comb)
        tie=hashlib.shake_256(seed+b'|NOEMA-DNCRYPT/RELATIONAL-V4/COMBO|'+bytes(comb)).digest(16)
        key=(-geometry,tie,comb)
        if best is None or key<best[0]:best=(key,comb)
    if best is None:raise RuntimeError('no nuisance-matched subset')
    chosen=list(best[1])
    chosen.sort(key=lambda i:(-scores[i//3],hashlib.shake_256(seed+b'|ORDER|'+int(i).to_bytes(2,'big')).digest(8),i))
    return tuple(chosen)