from __future__ import annotations

from dataclasses import dataclass
from itertools import permutations

from dncrypt.genetic_ir import GeneticIRNode, GeneticLevel
from dncrypt.genetic_operators import duplicate_child, invert_children, translocate_child, recombine_children

OPERATORS=("DUPLICATE_CHILD","INVERT_CHILDREN","TRANSLOCATE_CHILD","RECOMBINE_CHILDREN")
NOEMA_SOURCE_COMMIT="8126e777d92d4d059d2e75f8cc18404ebfda3c58"


def _radical(name:str,symbol:str,motif:str)->GeneticIRNode:
    k=GeneticIRNode(f"k_{name}",GeneticLevel.KAKU,{"symbol":symbol})
    return GeneticIRNode(name,GeneticLevel.RADICAL,{"motif":motif},(k,))


def fixture_program(*, donor:bool=False)->GeneticIRNode:
    suffix="donor" if donor else "left"
    rs=tuple(_radical(f"r{i}","ACGT"[(i-1)%4],f"{suffix}-m{i}") for i in range(1,5))
    return GeneticIRNode("c1",GeneticLevel.CONCEPT,{"fixture":suffix},rs)


def _index(program:GeneticIRNode,unit_id:str)->int:
    for i,ch in enumerate(program.children):
        if ch.unit_id==unit_id:return i
    raise KeyError(unit_id)


def apply_operator(program:GeneticIRNode, donor:GeneticIRNode, op:str)->GeneticIRNode:
    if op=="DUPLICATE_CHILD":
        child,_=duplicate_child(program,"c1",_index(program,"r1"),tag="v5d")
        return child
    if op=="INVERT_CHILDREN":
        a,b=_index(program,"r1"),_index(program,"r4"); lo,hi=sorted((a,b))
        child,_=invert_children(program,"c1",lo,hi+1)
        return child
    if op=="TRANSLOCATE_CHILD":
        ids=[x.unit_id for x in program.children]; src=ids.index("r2"); tmp=list(ids); tmp.pop(src); dst=tmp.index("r4")+1
        child,_=translocate_child(program,"c1",src,dst)
        return child
    if op=="RECOMBINE_CHILDREN":
        child,_=recombine_children(program,donor,"c1",left_cut=len(program.children),right_cut=2,tag="v5r")
        return child
    raise ValueError(op)


def execute_word(order:tuple[str,...])->GeneticIRNode:
    if len(order)!=4 or set(order)!=set(OPERATORS): raise ValueError("word must be a permutation of four operators")
    state=fixture_program(); donor=fixture_program(donor=True)
    for op in order: state=apply_operator(state,donor,op)
    return state


def all_permutation_receipt()->dict:
    rows=[]
    for order in permutations(OPERATORS):
        child=execute_word(order)
        rows.append({"order":list(order),"semantic_id":child.semantic_id,"children":[x.unit_id for x in child.children]})
    unique=len({r["semantic_id"] for r in rows})
    return {"schema":"DNCRYPT_NOEMA_MUTATION_WORD_NATIVE_CLOSURE_V1","noema_source_commit":NOEMA_SOURCE_COMMIT,"orders_tested":24,"all_closed":len(rows)==24,"unique_final_semantic_states":unique,"noncommutative":unique>1,"rows":rows,"authority":{"candidate_only":True,"security_admission":False,"cryptographic_entropy":False,"changes_frozen_aead":False}}

if __name__ == "__main__":
    import json
    print(json.dumps(all_permutation_receipt(), sort_keys=True))