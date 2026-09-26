from __future__ import annotations
import hashlib,json,math
from typing import Mapping
SCHEMA="NOEMA_TELEKOM_PRIME_GAP_MUTATION_CODON_WORD_V6_1"
STRATEGIES={"RELATIONAL_CODON_ORDER_V6_1","MATCHED_STATE_SHUFFLE_NULL_V6_1"}
OPS={"DUPLICATE_CHILD","INVERT_CHILDREN","TRANSLOCATE_CHILD","RECOMBINE_CHILDREN"}
AUTH={"candidate_only":True,"execution_authority":False,"cryptographic_entropy":False,"security_admission":False,"changes_frozen_aead":False,"physical_neutrino_carrier_claim":False}
SEM={"flavour_neutral":True,"full_z3_triplet_retained":True}
class WireError(ValueError): pass
def canon(v): return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()
def sha(b): return hashlib.sha256(b).hexdigest()
def hex64(x): return isinstance(x,str) and len(x)==64 and all(c in '0123456789abcdef' for c in x)
def z3_residual(xs): return abs(sum(complex(math.cos(x),math.sin(x)) for x in xs))/3.0

def validate_word_payload(value:Mapping[str,object])->dict:
    v=dict(value)
    if v.get('schema')!=SCHEMA or v.get('strategy') not in STRATEGIES: raise WireError('schema/strategy')
    for k in ('source_state_sha256','execution_state_sha256','fresh_entropy_commitment','word_sha256'):
        if not hex64(v.get(k)): raise WireError(k)
    if v.get('authority')!=AUTH or v.get('execution_semantics')!=SEM: raise WireError('authority/semantics')
    toks=v.get('tokens')
    if not isinstance(toks,list) or len(toks)!=12: raise WireError('tokens')
    groups=[]; max_res=0.0
    for t in toks:
        if not isinstance(t,dict): raise WireError('token object')
        g=t.get('group_index'); s=t.get('shell_index'); o=t.get('observable_index')
        if not isinstance(g,int) or not 0<=g<12 or s!=g//3 or o!=g%3: raise WireError('group factorization')
        if t.get('operation') not in OPS: raise WireError('operation')
        u=t.get('parameter_u64')
        if not isinstance(u,int) or not 0<=u<2**64: raise WireError('parameter_u64')
        if not hex64(t.get('parameter_commitment')) or not hex64(t.get('flavour_triplet_commitment')): raise WireError('token commitment')
        a=t.get('activity')
        if not isinstance(a,(int,float)) or not math.isfinite(float(a)) or float(a)<0: raise WireError('activity')
        trip=t.get('flavour_phase_triplet')
        if not isinstance(trip,list) or len(trip)!=3 or any(not isinstance(x,(int,float)) or not math.isfinite(float(x)) for x in trip): raise WireError('flavour triplet')
        max_res=max(max_res,z3_residual([float(x) for x in trip])); groups.append(g)
    if sorted(groups)!=list(range(12)): raise WireError('groups not bijective')
    if max_res>1e-12: raise WireError(f'Z3 closure residual {max_res}')
    declared=v['word_sha256']; body=dict(v); body.pop('word_sha256')
    actual=sha(canon(body))
    if actual!=declared: raise WireError('word_sha256 mismatch')
    return {'schema':'DNCRYPT_NOEMA_CODON_WIRE_VALIDATION_V1','status':'PASS','strategy':v['strategy'],'word_sha256':declared,'max_z3_balance_residual':max_res,'authority':{'native_execution':False,'security_admission':False}}

def exact_token_multiset_match(a:Mapping[str,object],b:Mapping[str,object])->bool:
    va=validate_word_payload(a); vb=validate_word_payload(b)
    def sig(v):
        return sorted((t['group_index'],t['operation'],t['parameter_u64'],t['parameter_commitment'],t['flavour_triplet_commitment']) for t in v['tokens'])
    return sig(a)==sig(b)