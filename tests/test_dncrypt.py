import json
from dataclasses import replace, asdict
import pytest

from dncrypt import (
    decrypt, encrypt, initial_genome, initial_surface, evolve_surface,
    transition_surface, vectorized_mutation_population, population_commitment,
    envelope_to_dna, envelope_from_dna, DNCryptState, save_state_atomic, load_state,
    FitnessRecord, PopulationFitnessReport, EvolutionPolicy, propose_generation,
    select_generation, make_evaluation_request, write_evaluation_request,
    load_external_evaluation, append_ledger_record, resolve_ledger_record,
    append_evolution_receipt, verify_evolution_ledger,
)
from dncrypt.crypto import DNCryptEnvelope


def fixture():
    g=initial_genome(bytes(range(64)))
    s=initial_surface(g)
    k=bytes(range(32))
    return k,g,s


def fit(g, *, leakage=.01, predict=.01, db=0.0, da=0.0, avalanche=.01, throughput=100.0, dec=0, integ=0, p=.9, source="fixture"):
    return FitnessRecord(g.genome_id,g.generation,leakage,predict,db,da,avalanche,throughput,dec,integ,p,source)


def make_report(request, population, records):
    return PopulationFitnessReport("dncrypt.external-evaluation/v0.2", request.request_id, tuple(records))


def test_roundtrip_and_provenance():
    k,g,s=fixture(); e=encrypt(k,b"secret payload",g,s,user_aad=b"meta",entropy=b"x"*44)
    assert e.verify_receipt() and decrypt(k,e,g,s)==b"secret payload"
    assert e.protocol_id=="dncrypt.frozen-protocol/v0.2"


def test_nondeterministic_ciphertext():
    k,g,s=fixture(); e1=encrypt(k,b"same",g,s); e2=encrypt(k,b"same",g,s)
    assert e1.ciphertext_b64!=e2.ciphertext_b64 and e1.receipt_blake2b!=e2.receipt_blake2b


def test_tamper_fails_closed():
    k,g,s=fixture(); e=encrypt(k,b"secret",g,s,entropy=b"y"*44)
    bad=replace(e,ciphertext_b64=e.ciphertext_b64[:-2]+"AA")
    with pytest.raises(ValueError): decrypt(k,bad,g,s)


def test_wrong_key_fails_closed():
    k,g,s=fixture(); e=encrypt(k,b"secret",g,s,entropy=b"z"*44)
    with pytest.raises(ValueError): decrypt(bytes(reversed(k)),e,g,s)


def test_surface_binding_and_internal_tick():
    k,g,s=fixture(); e=encrypt(k,b"x",g,s,entropy=b"q"*44); s2=evolve_surface(s,g,steps=3)
    assert s2.tick==3 and s2.commitment!=s.commitment
    with pytest.raises(ValueError): decrypt(k,e,g,s2)


def test_dna_transport_roundtrip():
    k,g,s=fixture(); e=encrypt(k,b"DNA transport",g,s,entropy=b"r"*44); seq=envelope_to_dna(e)
    assert set(seq)<=set("ACGT")
    e2=envelope_from_dna(seq); assert e2==e and decrypt(k,e2,g,s)==b"DNA transport"


def test_vectorized_population_is_distinct_and_bound():
    _,g,_=fixture(); pop=vectorized_mutation_population(g,128,bytes(range(256))*32)
    assert len(pop)==128 and len({x.genome_id for x in pop})==128
    assert all(x.generation==1 and x.parent_id==g.genome_id for x in pop)
    assert len(population_commitment(pop))==64


def test_transition_surface_preserves_time_continuity():
    _,g,s=fixture(); child=vectorized_mutation_population(g,1,b"a"*64)[0]
    cs=transition_surface(s,child,steps=5)
    assert cs.tick==s.tick+5 and cs.commitment!=s.commitment


def test_state_roundtrip_v02(tmp_path):
    _,g,s=fixture(); st=DNCryptState(g,s,"msg","evo"); p=tmp_path/"state.json"; save_state_atomic(p,st)
    assert load_state(p)==st


def test_message_ledger_resolves_historical_state(tmp_path):
    k,g,s=fixture(); e=encrypt(k,b"ledger",g,s,entropy=b"l"*44); p=tmp_path/"ledger.jsonl"
    d=append_ledger_record(p,e,g,s); assert len(d)==64
    rg,rs=resolve_ledger_record(p,e.receipt_blake2b); assert rg==g and rs==s and decrypt(k,e,rg,rs)==b"ledger"


def test_evaluation_request_binds_exact_population(tmp_path):
    _,g,_=fixture(); pop=vectorized_mutation_population(g,4,b"b"*(4*64)); req=make_evaluation_request(g,pop)
    assert req.population_commitment==population_commitment(pop) and len(req.request_id)==64
    p=tmp_path/"request.json"; write_evaluation_request(p,req); value=json.loads(p.read_text())
    assert value["request_id"]==req.request_id


def test_external_evaluation_roundtrip_and_exact_coverage(tmp_path):
    _,g,_=fixture(); pop=vectorized_mutation_population(g,3,b"c"*(3*64)); req=make_evaluation_request(g,pop)
    records=[fit(x) for x in pop]
    payload={"schema":"dncrypt.external-evaluation/v0.2","request_id":req.request_id,"records":[asdict(r) for r in records]}
    p=tmp_path/"report.json"; p.write_text(json.dumps(payload))
    report=load_external_evaluation(p,req,pop); assert len(report.records)==3


def test_external_evaluation_rejects_missing_candidate(tmp_path):
    _,g,_=fixture(); pop=vectorized_mutation_population(g,3,b"d"*(3*64)); req=make_evaluation_request(g,pop)
    payload={"schema":"dncrypt.external-evaluation/v0.2","request_id":req.request_id,"records":[asdict(fit(pop[0])),asdict(fit(pop[1]))]}
    p=tmp_path/"bad.json"; p.write_text(json.dumps(payload))
    with pytest.raises(ValueError): load_external_evaluation(p,req,pop)


def test_external_evaluation_rejects_duplicate_id():
    _,g,_=fixture(); pop=vectorized_mutation_population(g,2,b"e"*(2*64)); req=make_evaluation_request(g,pop); r=fit(pop[0])
    with pytest.raises(ValueError): PopulationFitnessReport("dncrypt.external-evaluation/v0.2",req.request_id,(r,r))


def test_proposal_requires_adversarial_risk():
    _,g,_=fixture(); policy=EvolutionPolicy(population_size=8,mutation_risk_threshold=.02)
    quiet=fit(g,leakage=.001,predict=.001,avalanche=.001,p=.9)
    pop,rec=propose_generation(g,quiet,policy,entropy=b"f"*(8*64)); assert pop==tuple() and not rec.proposed
    attacked=fit(g,leakage=.05,predict=.03,db=.5,da=.1,avalanche=.02,p=.01)
    pop,rec=propose_generation(g,attacked,policy,entropy=b"g"*(8*64)); assert len(pop)==8 and rec.proposed


def test_selection_promotes_better_pareto_candidate_and_surface():
    _,g,s=fixture(); policy=EvolutionPolicy(population_size=4,mutation_risk_threshold=.02,surface_transition_steps=2)
    parent=fit(g,leakage=.05,predict=.04,db=.4,da=.1,avalanche=.03,throughput=100,p=.01)
    pop,_=propose_generation(g,parent,policy,entropy=b"h"*(4*64)); req=make_evaluation_request(g,pop)
    rs=[
        fit(pop[0],leakage=.02,predict=.02,db=.1,da=.02,avalanche=.02,throughput=90,p=.01),
        fit(pop[1],leakage=.005,predict=.005,db=0,da=0,avalanche=.005,throughput=95,p=.8),
        fit(pop[2],leakage=.01,predict=.01,db=.05,da=.01,avalanche=.01,throughput=110,p=.01),
        fit(pop[3],leakage=.03,predict=.03,db=.2,da=.03,avalanche=.03,throughput=120,p=.01),
    ]
    report=make_report(req,pop,rs); child,cs,receipt=select_generation(g,s,parent,pop,report,policy)
    assert receipt.promoted and child.genome_id==pop[1].genome_id and cs.tick==2 and receipt.selected_surface_commitment==cs.commitment


def test_selection_fails_closed_when_all_candidates_break_invariants():
    _,g,s=fixture(); policy=EvolutionPolicy(population_size=2); parent=fit(g,leakage=.1,predict=.1,db=.3,da=.1,avalanche=.1,p=.01)
    pop,_=propose_generation(g,parent,policy,entropy=b"i"*(2*64)); req=make_evaluation_request(g,pop)
    report=make_report(req,pop,[fit(pop[0],dec=1),fit(pop[1],integ=1)])
    child,cs,receipt=select_generation(g,s,parent,pop,report,policy)
    assert not receipt.promoted and child==g and cs==s and "no_candidate" in receipt.reason


def test_selection_rejects_worse_population():
    _,g,s=fixture(); policy=EvolutionPolicy(population_size=2); parent=fit(g,leakage=.02,predict=.02,db=.1,da=.02,avalanche=.01,p=.01)
    pop,_=propose_generation(g,parent,policy,entropy=b"j"*(2*64)); req=make_evaluation_request(g,pop)
    report=make_report(req,pop,[fit(x,leakage=.2,predict=.2,db=.5,da=.2,avalanche=.2,p=.01) for x in pop])
    child,cs,receipt=select_generation(g,s,parent,pop,report,policy)
    assert not receipt.promoted and child==g and cs==s and "did_not_improve" in receipt.reason


def test_selection_rejects_too_slow_candidate():
    _,g,s=fixture(); policy=EvolutionPolicy(population_size=2,minimum_throughput_ratio=.8); parent=fit(g,leakage=.1,predict=.1,db=.4,da=.1,avalanche=.1,throughput=100,p=.01)
    pop,_=propose_generation(g,parent,policy,entropy=b"k"*(2*64)); req=make_evaluation_request(g,pop)
    report=make_report(req,pop,[fit(x,leakage=.001,predict=.001,avalanche=.001,throughput=20,p=.9) for x in pop])
    child,cs,receipt=select_generation(g,s,parent,pop,report,policy)
    assert not receipt.promoted and "throughput" in receipt.reason


def test_evolution_ledger_append_and_verify(tmp_path):
    _,g,s=fixture(); policy=EvolutionPolicy(population_size=2); parent=fit(g,leakage=.1,predict=.1,db=.4,da=.1,avalanche=.1,p=.01)
    pop,proposal=propose_generation(g,parent,policy,entropy=b"m"*(2*64)); req=make_evaluation_request(g,pop)
    report=make_report(req,pop,[fit(pop[0],leakage=.001,predict=.001,avalanche=.001,p=.9),fit(pop[1],leakage=.01,predict=.01,avalanche=.01,p=.9)])
    _,_,promotion=select_generation(g,s,parent,pop,report,policy)
    p=tmp_path/"evolution.jsonl"; d1=append_evolution_receipt(p,proposal); d2=append_evolution_receipt(p,promotion)
    assert len(d1)==64 and len(d2)==64 and verify_evolution_ledger(p)


def test_evolution_ledger_tamper_detected(tmp_path):
    _,g,_=fixture(); policy=EvolutionPolicy(population_size=1); parent=fit(g,leakage=.1,predict=.1,db=.4,da=.1,avalanche=.1,p=.01)
    _,proposal=propose_generation(g,parent,policy,entropy=b"n"*64); p=tmp_path/"e.jsonl"; append_evolution_receipt(p,proposal)
    raw=p.read_text(); p.write_text(raw.replace("significant_adversarial_risk_above_threshold","tampered"))
    with pytest.raises(ValueError): verify_evolution_ledger(p)
