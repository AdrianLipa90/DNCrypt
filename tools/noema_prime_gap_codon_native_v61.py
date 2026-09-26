from __future__ import annotations
from dataclasses import asdict
from typing import Mapping
from dncrypt.genetic_ir import GeneticIRNode,GeneticLevel
from dncrypt.genetic_operators import duplicate_child,invert_children,translocate_child,recombine_children
from dncrypt.genetic_compiler import compile_genetic_program,mutate_genome_with_program
from dncrypt.genome import initial_genome
from .noema_prime_gap_codon_wire_v61 import validate_word_payload,WireError
ORIGINALS=tuple(f'r{i}' for i in range(8))
NOEMA_SOURCE_COMMIT='69b5fbcdcc37094831d04061ea88a876fe6b84af'

def _radical(name,symbol,motif):
    k=GeneticIRNode(f'k_{name}',GeneticLevel.KAKU,{'symbol':symbol})
    return GeneticIRNode(name,GeneticLevel.RADICAL,{'motif':motif},(k,))
def fixture_program(donor=False):
    suffix='donor' if donor else 'left'; rs=tuple(_radical(f'r{i}','ACGT'[i%4],f'{suffix}-m{i}') for i in range(8)); return GeneticIRNode('c1',GeneticLevel.CONCEPT,{'fixture':suffix},rs)
def _index(p,id):
    for i,ch in enumerate(p.children):
        if ch.unit_id==id:return i
    raise KeyError(id)
def _pair(u):
    a=u%8; b=(a+1+((u>>8)%7))%8; return ORIGINALS[a],ORIGINALS[b]
def _translocation_indices(p,u):
    src=ORIGINALS[u%8]; ids=[x.unit_id for x in p.children]; si=ids.index(src)
    base=(u>>8)%7
    for step in range(7):
        dst=ORIGINALS[(u%8+1+base+step)%8]
        if dst==src: continue
        rem=list(ids); rem.pop(si); ins=rem.index(dst)+1; sim=list(rem); sim.insert(ins,src)
        if ins!=si and sim!=ids: return si,ins,src,dst
    raise WireError('no bounded translocation target changes state')
def execute_native_word(payload:Mapping[str,object],*,mutation_entropy:bytes|None=None)->dict:
    wire=validate_word_payload(payload); p=fixture_program(); donor=fixture_program(True); trace=[]
    for t in payload['tokens']:
        g=int(t['group_index']); u=int(t['parameter_u64']); op=str(t['operation']); before=p.semantic_id
        if op=='DUPLICATE_CHILD':
            anchor=ORIGINALS[u%8]; p,r=duplicate_child(p,'c1',_index(p,anchor),tag=f'v61d_g{g}_{u&0xffff:04x}'); args={'anchor':anchor}
        elif op=='INVERT_CHILDREN':
            a,b=_pair(u); ia,ib=_index(p,a),_index(p,b); lo,hi=sorted((ia,ib)); p,r=invert_children(p,'c1',lo,hi+1); args={'anchor_a':a,'anchor_b':b}
        elif op=='TRANSLOCATE_CHILD':
            si,di,src,dst=_translocation_indices(p,u); p,r=translocate_child(p,'c1',si,di); args={'source':src,'after':dst}
        elif op=='RECOMBINE_CHILDREN':
            right_cut=u%8; p,r=recombine_children(p,donor,'c1',left_cut=len(p.children),right_cut=right_cut,tag=f'v61r_g{g}_{u&0xffff:04x}'); args={'right_cut':right_cut}
        else: raise WireError(op)
        if p.semantic_id==before: raise WireError(f'native operator produced no semantic change: {op}')
        if len({c.unit_id for c in p.children})!=len(p.children): raise WireError('child id collision')
        trace.append({'group_index':g,'operation':op,'operator_receipt':r.digest,'child_semantic_id':p.semantic_id,'args':args})
    phenotype=compile_genetic_program(p)
    out={'schema':'DNCRYPT_NOEMA_PRIME_GAP_CODON_NATIVE_EXECUTION_V6_1','status':'PASS_NATIVE_STRUCTURAL_CLOSURE','noema_source_commit':NOEMA_SOURCE_COMMIT,'word_sha256':wire['word_sha256'],'strategy':wire['strategy'],'final_program_semantic_id':p.semantic_id,'operator_trace':trace,'phenotype_commitment':phenotype.commitment,'phenotype':phenotype.to_dict(),'authority':{'candidate_only':True,'security_admission':False,'cryptographic_entropy':False,'changes_frozen_aead':False}}
    if mutation_entropy is not None:
        parent=initial_genome(bytes(range(64))); child,binding=mutate_genome_with_program(parent,p,entropy=mutation_entropy); out['candidate_genome_id']=child.genome_id; out['genetic_binding']=binding.to_dict()
    return out