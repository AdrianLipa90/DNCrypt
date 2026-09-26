from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from typing import Iterable, Mapping

SHELLS=(6,30,210,2310)
OBSERVABLES=("prime_gap","twin_start_gap","dyadic_k")
FLAVOURS=("nu_e","nu_mu","nu_tau")
TAU=2.0*math.pi
DIM=36
SCHEMA="NOEMA_TELEKOM_RELATIONAL_PRIME_PHASE_FLOW_36D_V3"


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode("utf-8")


def is_prime(n:int)->bool:
    if n<2:return False
    if n in (2,3):return True
    if n%2==0 or n%3==0:return False
    d=5
    while d*d<=n:
        if n%d==0 or n%(d+2)==0:return False
        d+=6
    return True


def first_primes(count:int)->tuple[int,...]:
    out=[]; n=2
    while len(out)<count:
        if is_prime(n):out.append(n)
        n+=1
    return tuple(out)


def v2(n:int)->int:
    if n<=0:raise ValueError("v2 input must be positive")
    k=0
    while n%2==0:n//=2;k+=1
    return k


def build_streams(count:int=4096)->tuple[tuple[int,...],tuple[int,...],tuple[int,...]]:
    primes=first_primes(count)
    prime_gaps=tuple(b-a for a,b in zip(primes,primes[1:]))
    pool=set(primes)
    twin_starts=tuple(p for p in primes if p+2 in pool)
    twin_gaps=tuple(b-a for a,b in zip(twin_starts,twin_starts[1:]))
    dyadic=tuple(v2(p+1) for p in primes)
    return prime_gaps,twin_gaps,dyadic

PRIME_GAPS,TWIN_GAPS,DYADIC_K=build_streams()


def _idx(entropy:bytes,label:bytes,length:int)->int:
    if length<3:raise ValueError("stream too short")
    raw=hashlib.shake_256(b"DNCrypt/experiment/noema-relflow-v3/source-index|"+label+b"|"+bytes(entropy)).digest(8)
    return 2+(int.from_bytes(raw,"big")%(length-2))

@dataclass(frozen=True,slots=True)
class RelationalSourceTriple:
    previous_previous:tuple[int,int,int]
    previous:tuple[int,int,int]
    current:tuple[int,int,int]

    @property
    def commitment(self)->str:
        return str(state_dict(self)["state_sha256"])


def relational_source_triple(entropy:bytes)->RelationalSourceTriple:
    e=bytes(entropy)
    ip=_idx(e,b"prime-gap",len(PRIME_GAPS)); it=_idx(e,b"twin-gap",len(TWIN_GAPS)); ik=_idx(e,b"dyadic-k",len(DYADIC_K))
    return RelationalSourceTriple(
        (PRIME_GAPS[ip-2],TWIN_GAPS[it-2],DYADIC_K[ik-2]),
        (PRIME_GAPS[ip-1],TWIN_GAPS[it-1],DYADIC_K[ik-1]),
        (PRIME_GAPS[ip],TWIN_GAPS[it],DYADIC_K[ik]),
    )


def wrap_pi(theta:float)->float:
    return (theta+math.pi)%TAU-math.pi


def _phase(value:int,shell:int)->float:
    return (TAU*int(value)/int(shell))%TAU


def components(source:RelationalSourceTriple):
    offsets=(0.0,TAU/3.0,2.0*TAU/3.0)
    flow=[]; curvature=[]; strength=[]; values=[]; lane_scores=[]
    pp,p,c=source.previous_previous,source.previous,source.current
    for shell in SHELLS:
        for o in range(3):
            phi_pp=_phase(pp[o],shell); phi_p=_phase(p[o],shell); phi_c=_phase(c[o],shell)
            d_prev=wrap_pi(phi_p-phi_pp); d_now=wrap_pi(phi_c-phi_p); kappa=wrap_pi(d_now-d_prev)
            q=0.5*abs(math.sin(d_now))+0.5*abs(math.sin(kappa))
            flow.append(d_now); curvature.append(kappa); strength.append(q)
            for offset in offsets:
                theta=(d_now+offset)%TAU; values.append(theta)
                lane_scores.append(q*0.5*(1.0+math.cos(d_now-offset)))
    return tuple(flow),tuple(curvature),tuple(strength),tuple(values),tuple(lane_scores)


def _max_balance(values:tuple[float,...])->float:
    return max(abs(sum(complex(math.cos(values[3*o+f]),math.sin(values[3*o+f])) for f in range(3)))/3.0 for o in range(12))


def state_dict(source:RelationalSourceTriple)->dict[str,object]:
    flow,curvature,strength,values,lane_scores=components(source)
    body:dict[str,object]={
        "schema":SCHEMA,"shape":[4,3,3],"axis_order":["orbital_shell","observable","neutrino_flavour"],
        "shells":list(SHELLS),"observables":list(OBSERVABLES),"flavours":list(FLAVOURS),"coding":"Z3_RELATIONAL_PHASE_FLOW",
        "previous_previous":list(source.previous_previous),"previous":list(source.previous),"current":list(source.current),
        "flow_12":list(flow),"curvature_12":list(curvature),"orbit_strength_12":list(strength),"values_36":list(values),"lane_scores_36":list(lane_scores),
        "max_flavour_balance_residual":_max_balance(values),
        "authority":{"search_control_only":True,"cryptographic_entropy":False,"key_material":False,"security_admission":False,"physical_neutrino_carrier_claim":False},
    }
    body["state_sha256"]=hashlib.sha256(canonical_json_bytes(body)).hexdigest()
    return body


def rank_loci(source:RelationalSourceTriple,loci:Iterable[int],fresh_entropy:bytes)->list[int]:
    loci_t=tuple(int(i) for i in loci); state=state_dict(source); scores=state["lane_scores_36"]
    fresh_sha=hashlib.sha256(bytes(fresh_entropy)).hexdigest()
    seed=bytes.fromhex(fresh_sha)+bytes.fromhex(str(state["state_sha256"]))
    tie=hashlib.shake_256(seed+b"|NOEMA-TELEKOM/RELATIONAL-V3|").digest(DIM*2)
    out=sorted(loci_t,key=lambda i:(-float(scores[i]),tie[2*i],tie[2*i+1],i))
    if sorted(out)!=sorted(loci_t):raise RuntimeError("ranking mismatch")
    return out