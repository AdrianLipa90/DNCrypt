from __future__ import annotations
from dataclasses import asdict
import json, tempfile
from pathlib import Path

from dncrypt import (
    initial_genome, initial_surface, encrypt_deterministic_for_test, decrypt, EvolutionPolicy,
    FitnessRecord, PopulationFitnessReport, propose_generation, make_evaluation_request,
    select_generation, append_evolution_receipt, verify_evolution_ledger,
)


def _fitness(genome, rank: int) -> FitnessRecord:
    # Synthetic orchestration fixture only: deterministic metrics exercise the v0.2 bus/gates.
    if rank == 0:
        return FitnessRecord(genome.genome_id, genome.generation, 0.002, 0.002, 0.0, 0.0, 0.002, 96.0, 0, 0, 0.8, "synthetic_fixture")
    x = 0.01 + rank * 0.001
    return FitnessRecord(genome.genome_id, genome.generation, x, x, 0.02, 0.01, x, 100.0 + rank, 0, 0, 0.01, "synthetic_fixture")


def main() -> int:
    key = bytes(range(32))
    parent = initial_genome(bytes(range(64)))
    surface = initial_surface(parent)
    envelope = encrypt_deterministic_for_test(key, b"DNCrypt v0.2 smoke", parent, surface, entropy=b"s" * 44)
    assert decrypt(key, envelope, parent, surface) == b"DNCrypt v0.2 smoke"

    policy = EvolutionPolicy(population_size=64, mutation_risk_threshold=0.02, surface_transition_steps=2)
    parent_report = FitnessRecord(parent.genome_id, parent.generation, 0.08, 0.05, 0.6, 0.1, 0.04, 100.0, 0, 0, 0.01, "synthetic_fixture")
    population, proposal = propose_generation(parent, parent_report, policy, entropy=bytes(range(256)) * 16)
    request = make_evaluation_request(parent, population)
    report = PopulationFitnessReport("dncrypt.external-evaluation/v0.2", request.request_id, tuple(_fitness(g, i) for i, g in enumerate(population)))
    child, child_surface, promotion = select_generation(parent, surface, parent_report, population, report, policy)

    with tempfile.TemporaryDirectory() as td:
        ledger = Path(td) / "evolution.jsonl"
        append_evolution_receipt(ledger, proposal)
        append_evolution_receipt(ledger, promotion)
        ledger_ok = verify_evolution_ledger(ledger)

    result = {
        "schema": "dncrypt.smoke-demo/v0.2",
        "status": "PASS" if promotion.promoted and ledger_ok else "FAIL",
        "evidence_status": "synthetic_orchestration_fixture",
        "parent_genome_id": parent.genome_id,
        "population_size": len(population),
        "population_commitment": request.population_commitment,
        "evaluation_request_id": request.request_id,
        "selected_genome_id": child.genome_id,
        "selected_generation": child.generation,
        "parent_tick": surface.tick,
        "selected_tick": child_surface.tick,
        "proposal_receipt_digest": proposal.digest,
        "promotion_receipt_digest": promotion.digest,
        "promoted": promotion.promoted,
        "ledger_verified": ledger_ok,
        "message_receipt": envelope.receipt_blake2b,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
