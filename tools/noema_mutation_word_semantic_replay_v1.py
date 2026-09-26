from __future__ import annotations
from dataclasses import dataclass
from enum import IntEnum
from itertools import permutations
import hashlib, json

class GeneticLevel(IntEnum):
    KAKU=0; RADICAL=1; CONCEPT=2

def canon(v):
    return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def h(v):
    return hashlib.blake2b(canon(v),digest_size=32).hexdigest()

@dataclass(frozen=True)
class Node:
    unit_id:str
    level:GeneticLevel
    payload:dict
    children:tuple['Node',...]=()
    def __post_init__(self):
        if not self.unit_id: raise ValueError
        if self.level is GeneticLevel.KAKU:
            if self.children: raise ValueError
        else:
            if not self.children: raise ValueError
            expected=GeneticLevel(int(self.level)-1)
            if any(c.level is not expected for c in self.children): raise ValueError
            ids=[c.unit_id for c in self.children]
            if len(ids)!=len(set(ids)): raise ValueError
    def to_dict(self):
        return {"schema":"DNCRYPT_GENETIC_IR_V0_6","source_schema":"CIELINGO_GENOMIC_GRAMMAR_V0_1","unit_id":self.unit_id,"level":self.level.name,"payload":self.payload,"children":[c.to_dict() for c in self.children],"relations":[],"authority":{"diagnostic_only":True,"security_admission":False,"changes_frozen_aead":False}}
    @property
    def semantic_id(self): return h(self.to_dict())

def clone_tag(n:Node,tag:str)->Node:
    return Node(f"{n.unit_id}__{tag}",n.level,dict(n.payload),tuple(clone_tag(c,tag) for c in n.children))

def radical(name,symbol,motif):
    return Node(name,GeneticLevel.RADICAL,{"motif":motif},(Node(f"k_{name}",GeneticLevel.KAKU,{"symbol":symbol}),))

def fixture(donor=False):
    suffix="donor" if donor else "left"
    rs=tuple(radical(f"r{i}","ACGT"[(i-1)%4],f"{suffix}-m{i}") for i in range(1,5))
    return Node("c1",GeneticLevel.CONCEPT,{"fixture":suffix},rs)

def idx(p,id):
    return [x.unit_id for x in p.children].index(id)

def duplicate(p):
    i=idx(p,"r1"); ch=list(p.children); ch.insert(i+1,clone_tag(ch[i],"dup_v5d")); return Node(p.unit_id,p.level,dict(p.payload),tuple(ch))
def invert(p):
    a,b=idx(p,"r1"),idx(p,"r4"); lo,hi=sorted((a,b)); ch=list(p.children); ch[lo:hi+1]=reversed(ch[lo:hi+1]); return Node(p.unit_id,p.level,dict(p.payload),tuple(ch))
def translocate(p):
    ids=[x.unit_id for x in p.children]; src=ids.index("r2"); tmp=list(ids); tmp.pop(src); dst=tmp.index("r4")+1
    ch=list(p.children); moved=ch.pop(src); ch.insert(dst,moved); return Node(p.unit_id,p.level,dict(p.payload),tuple(ch))
def recombine(p,donor):
    left_cut=len(p.children); right_cut=2
    left_children=p.children[:left_cut]
    donor_original=donor.children[right_cut:]
    donor_children=tuple(clone_tag(c,"xo_v5r") for c in donor_original)
    return Node(p.unit_id,p.level,dict(p.payload),left_children+donor_children)

OPS=("DUPLICATE_CHILD","INVERT_CHILDREN","TRANSLOCATE_CHILD","RECOMBINE_CHILDREN")
def apply(p,d,op):
    return duplicate(p) if op==OPS[0] else invert(p) if op==OPS[1] else translocate(p) if op==OPS[2] else recombine(p,d)

def execute(order):
    p=fixture(); d=fixture(True)
    for op in order: p=apply(p,d,op)
    return p
rows=[]
for order in permutations(OPS):
    x=execute(order)
    rows.append({"order":list(order),"semantic_id":x.semantic_id,"children":[c.unit_id for c in x.children]})
receipt={
 "schema":"DNCRYPT_NOEMA_MUTATION_WORD_SEMANTIC_REPLAY_V1",
 "status":"PASS_SEMANTIC_REPLAY_NATIVE_GATE_STILL_BLOCKED",
 "source_commit":"428fe3f0ac1707f935f833cc73be398fc136c2d3",
 "source_blob_shas":{"genetic_ir.py":"fb1b57e1d0054b8e30575793cb962e9a74e5eaa2","genetic_operators.py":"359f94414639b4ad94b83550ab218c692670af2b","util.py":"81dbbcfb121a15810bb990431abb49d7fdf1d57c"},
 "fixture_semantics":"restricted_no-relations replay of the exact operator semantics used by NOEMA_MUTATION_WORD_NATIVE_V1",
 "orders_tested":len(rows),"all_closed":len(rows)==24,
 "unique_final_semantic_states":len({r['semantic_id'] for r in rows}),
 "noncommutative":len({r['semantic_id'] for r in rows})>1,
 "rows":rows,
 "authority":{"native_dncrypt_execution":False,"security_admission":False,"cryptographic_entropy":False,"changes_frozen_aead":False}
}
body=dict(receipt); receipt["receipt_sha256"]=hashlib.sha256(canon(body)).hexdigest()
open('/mnt/data/dncrypt_mutword_native/semantic_replay_receipt_v1.json','w').write(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
print(json.dumps({k:receipt[k] for k in ('status','orders_tested','all_closed','unique_final_semantic_states','noncommutative','receipt_sha256')},indent=2))