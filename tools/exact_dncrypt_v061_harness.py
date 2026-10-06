from __future__ import annotations
from dataclasses import dataclass, asdict
import hashlib, json, math
import numpy as np

DIM=36
VERSION='DNCrypt/v0.2'
IR_SCHEMA='DNCRYPT_GENETIC_IR_V0_6'
CIELINGO_SCHEMA='CIELINGO_GENOMIC_GRAMMAR_V0_1'
PHENOTYPE_SCHEMA='dncrypt.mutation-phenotype/v0.6.1-candidate'


def canonical_json_bytes(v):
    return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')

def blake2b256(b): return hashlib.blake2b(b,digest_size=32).hexdigest()

def _derive_bytes(seed,label,n): return hashlib.shake_256(seed+b'|'+label).digest(n)

@dataclass(frozen=True)
class CipherGenome:
    version:str; generation:int; parent_id:str|None; operator_vector:tuple[int,...]; route:tuple[int,...]; phase_seed_hex:str; mutation_nonce_hex:str
    @property
    def genome_id(self): return blake2b256(canonical_json_bytes(asdict(self)))

def initial_genome(entropy:bytes):
    seed=bytes(entropy)
    op=tuple(_derive_bytes(seed,b'operator',DIM))
    keys=np.frombuffer(_derive_bytes(seed,b'route',DIM*8),dtype='<u8')
    route=tuple(np.argsort(keys,kind='stable').astype(int).tolist())
    return CipherGenome(VERSION,0,None,op,route,_derive_bytes(seed,b'phase',32).hex(),_derive_bytes(seed,b'mutation-nonce',16).hex())

def mutate_genome(parent,e):
    e=bytes(e); seed=bytes.fromhex(parent.phase_seed_hex)+bytes.fromhex(parent.mutation_nonce_hex)+e
    base=np.asarray(parent.operator_vector,dtype=np.uint16)
    delta=np.frombuffer(_derive_bytes(seed,b'delta',DIM),dtype=np.uint8).astype(np.uint16)
    mask=np.frombuffer(_derive_bytes(seed,b'mask',DIM),dtype=np.uint8)<96
    child=base.copy(); child[mask]=(child[mask]+delta[mask]+1)&0xFF
    route_keys=np.frombuffer(_derive_bytes(seed,b'route',DIM*8),dtype='<u8')
    parent_route=np.asarray(parent.route,dtype=int)
    route=tuple(parent_route[np.argsort(route_keys,kind='stable')].astype(int).tolist())
    return CipherGenome(VERSION,parent.generation+1,parent.genome_id,tuple(int(x) for x in child),route,_derive_bytes(seed,b'phase',32).hex(),_derive_bytes(seed,b'mutation-nonce',16).hex())

def node(unit_id,level,payload,children=()):
    return {'schema':IR_SCHEMA,'source_schema':CIELINGO_SCHEMA,'unit_id':unit_id,'level':level,'payload':payload,'children':list(children),'relations':[],
            'authority':{'diagnostic_only':True,'security_admission':False,'changes_frozen_aead':False}}

def fixed_program_dict():
    radicals=[]
    for i in range(32):
        k=node(f'k{i:02d}','KAKU',{'symbol':'ACGT'[i%4],'benchmark_lane':i})
        radicals.append(node(f'r{i:02d}','RADICAL',{'motif':f'm{i%8}'},(k,)))
    return node('prime-phase-abcd-concept','CONCEPT',{'benchmark':'NOEMA_TELEKOM_PRIME_PHASE_ABCD_V0_1','authority':'OBSERVATION_ONLY'},tuple(radicals))

def stats(program):
    counts={k:0 for k in ['KAKU','RADICAL','CONCEPT','SENTENCE','PARAGRAPH','CHAPTER','BOOK']}; node_count=relation_count=payload_bytes=max_depth=0
    stack=[(program,0)]
    while stack:
        n,d=stack.pop(); node_count+=1; relation_count+=len(n['relations']); payload_bytes+=len(canonical_json_bytes(n['payload'])); max_depth=max(max_depth,d); counts[n['level']]+=1
        stack.extend((c,d+1) for c in n['children'])
    return {'node_count':node_count,'relation_count':relation_count,'payload_bytes':payload_bytes,'max_depth':max_depth,'level_counts':[[k,counts[k]] for k in counts]}

def _unique_loci(seed,count):
    selected=[]; counter=0
    while len(selected)<count:
        block=hashlib.shake_256(b'DNCrypt/v0.6.1/genetic-compiler/loci|'+seed+counter.to_bytes(4,'big')).digest(64)
        for value in block:
            locus=value%DIM
            if locus not in selected:
                selected.append(locus)
                if len(selected)==count: break
        counter+=1
    return tuple(sorted(selected))

def phenotype():
    program=fixed_program_dict(); st=stats(program); canonical=canonical_json_bytes(program)
    gid=blake2b256(canonical)
    seed=hashlib.shake_256(b'DNCrypt/v0.6.1/genetic-compiler|'+canonical).digest(96)
    structural_width=1+st['node_count']//4+st['relation_count']//2; allowed_count=max(1,min(DIM,structural_width)); allowed=_unique_loci(seed[:64],allowed_count)
    budget=max(1,min(len(allowed),1+st['relation_count']+st['max_depth']//2)); stride=1+(seed[64]%(DIM-1)); direction=-1 if seed[65]&1 else 1
    body={'schema':PHENOTYPE_SCHEMA,'genetic_ir_id':gid,'allowed_loci':list(allowed),'mutation_budget':budget,'route_stride':stride,'route_direction':direction,'stats':st,
          'authority':{'search_control_only':True,'cryptographic_entropy':False,'security_admission':False}}
    return body,blake2b256(canonical_json_bytes(body))

def bound_unconstrained(parent, raw_entropy):
    ph,commit=phenotype(); bound=hashlib.shake_256(b'DNCrypt/v0.6.1/genetic-mutation/fresh|'+raw_entropy+bytes.fromhex(commit)).digest(max(64,len(raw_entropy)))
    return ph,commit,mutate_genome(parent,bound)

def null_order(pool,e):
    seed=hashlib.shake_256(b'DNCrypt/experiment/noema-prime-phase-abcd/random-null/v0.1|'+e).digest(DIM*2)
    return sorted(pool,key=lambda i:(seed[2*i],seed[2*i+1],i))

def native_seed(e): return hashlib.shake_256(b'DNCrypt/v0.6.1/genetic-mutation/order|'+e).digest(DIM*2)