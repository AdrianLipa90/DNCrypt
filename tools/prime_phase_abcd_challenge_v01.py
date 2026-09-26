from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, replace
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import statistics
from typing import Iterable

from dncrypt.evolution import EvolutionPolicy, ProposalReceipt
from dncrypt.fitness import FitnessRecord, PopulationFitnessReport
from dncrypt.generalization import GeneralizationPolicy
from dncrypt.genetic_compiler import (
    GeneticMutationBinding,
    compile_genetic_program,
    mutate_genome_with_program,
)
from dncrypt.genetic_ir import GeneticIRNode, GeneticLevel
from dncrypt.genome import CipherGenome, DIM, mutate_genome, population_commitment
from dncrypt.statistical_gate import (
    StatisticalAdmissionPolicy,
    select_generation_multifold_statistically_hardened,
)
from dncrypt.surface import initial_surface
from dncrypt.util import blake2b256, canonical_json_bytes

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "dncrypt_challenge_v042_real",
    ROOT / "tools" / "cryptanalysis_challenge_v042.py",
)
challenge = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(challenge)
base = challenge.base

SCHEMA = "dncrypt.noema-prime-phase-abcd/v0.1"
BINDING_SCHEMA = "dncrypt.noema-prime-phase-candidate-binding/v0.1"
STRATEGIES = (
    "A_NATIVE_GENETIC_IR",
    "B_RANDOM_LOCUS_NULL",
    "C_RAW_FLAVOUR_PHASE_V1",
    "D_ORBITAL_FLAVOUR_PHASE_V2",
)
SHELLS = (6, 30, 210, 2310)
OBSERVABLES = ("prime_gap", "twin_start_gap", "v2_p_plus_1")
FLAVOURS = ("nu_e", "nu_mu", "nu_tau")
TAU = 2.0 * math.pi


@dataclass(frozen=True, slots=True)
class CandidateBinding:
    schema: str
    strategy: str
    parent_genome_id: str
    child_genome_id: str
    phenotype_commitment: str
    fresh_entropy_commitment: str
    phase_frame_commitment: str | None
    changed_loci: tuple[int, ...]
    allowed_loci: tuple[int, ...]
    mutation_budget: int
    frozen_aead_changed: bool = False
    cryptographic_entropy_authority: bool = False
    security_admission_authority: bool = False

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))


def fixed_program() -> GeneticIRNode:
    """Public fixed Genetic IR fixture; identical for A/B/C/D."""
    radicals = []
    for i in range(32):
        kaku = GeneticIRNode(
            f"k{i:02d}",
            GeneticLevel.KAKU,
            {"symbol": "ACGT"[i % 4], "benchmark_lane": i},
        )
        radicals.append(
            GeneticIRNode(
                f"r{i:02d}",
                GeneticLevel.RADICAL,
                {"motif": f"m{i % 8}"},
                (kaku,),
            )
        )
    return GeneticIRNode(
        "prime-phase-abcd-concept",
        GeneticLevel.CONCEPT,
        {
            "benchmark": "NOEMA_TELEKOM_PRIME_PHASE_ABCD_V0_1",
            "authority": "OBSERVATION_ONLY",
        },
        tuple(radicals),
    )


def _is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    d = 5
    while d * d <= n:
        if n % d == 0 or n % (d + 2) == 0:
            return False
        d += 6
    return True


def _first_primes(count: int) -> tuple[int, ...]:
    out: list[int] = []
    n = 2
    while len(out) < count:
        if _is_prime(n):
            out.append(n)
        n += 1
    return tuple(out)


def _v2(n: int) -> int:
    if n <= 0:
        raise ValueError("v2 input must be positive")
    k = 0
    while n % 2 == 0:
        n //= 2
        k += 1
    return k


def _phase_frames() -> tuple[tuple[int, int, int], ...]:
    primes = _first_primes(2048)
    prime_gaps = tuple(b - a for a, b in zip(primes, primes[1:]))
    pool = set(primes)
    twin_starts = tuple(p for p in primes if p + 2 in pool)
    twin_gaps = tuple(b - a for a, b in zip(twin_starts, twin_starts[1:]))
    dyadic = tuple(_v2(p + 1) for p in primes[:-1])
    n = min(len(prime_gaps), len(twin_gaps), len(dyadic))
    if n < 64:
        raise RuntimeError("insufficient deterministic prime/twin-prime frames")
    return tuple((prime_gaps[i], twin_gaps[i], dyadic[i]) for i in range(n))


PHASE_FRAMES = _phase_frames()


def _wrap_pi(theta: float) -> float:
    return (theta + math.pi) % TAU - math.pi


def _frame_commitment(frame: tuple[int, int, int]) -> str:
    return blake2b256(canonical_json_bytes({
        "shells": list(SHELLS),
        "observables": list(OBSERVABLES),
        "flavours": list(FLAVOURS),
        "frame": list(frame),
    }))


def _phase36(frame: tuple[int, int, int]) -> tuple[float, ...]:
    out: list[float] = []
    offsets = (0.0, TAU / 3.0, 2.0 * TAU / 3.0)
    for shell in SHELLS:
        for value in frame:
            base_phase = (TAU * value / shell) % TAU
            for offset in offsets:
                out.append((base_phase + offset) % TAU)
    if len(out) != DIM:
        raise RuntimeError("phase tensor must flatten to 36 loci")
    return tuple(out)


def _orbit_base_scores(frame: tuple[int, int, int]) -> tuple[float, ...]:
    scores: list[float] = []
    for shell in SHELLS:
        for value in frame:
            theta = (TAU * value / shell) % TAU
            scores.append(abs(_wrap_pi(theta)) / math.pi)
    if len(scores) != 12:
        raise RuntimeError("expected 12 orbital scores")
    return tuple(scores)


def _native_order_seed(fresh_entropy: bytes) -> bytes:
    return hashlib.shake_256(
        b"DNCrypt/v0.6.1/genetic-mutation/order|" + fresh_entropy
    ).digest(DIM * 2)


def _null_order_seed(fresh_entropy: bytes) -> bytes:
    return hashlib.shake_256(
        b"DNCrypt/experiment/noema-prime-phase-abcd/random-null/v0.1|" + fresh_entropy
    ).digest(DIM * 2)


def _frame_index(fresh_entropy: bytes) -> int:
    raw = hashlib.shake_256(
        b"DNCrypt/experiment/noema-prime-phase-abcd/frame/v0.1|" + fresh_entropy
    ).digest(8)
    return int.from_bytes(raw, "big") % len(PHASE_FRAMES)


def _rank_native(loci: Iterable[int], fresh_entropy: bytes) -> list[int]:
    seed = _native_order_seed(fresh_entropy)
    return sorted(loci, key=lambda i: (seed[2 * i], seed[2 * i + 1], i))


def _rank_null(loci: Iterable[int], fresh_entropy: bytes) -> list[int]:
    seed = _null_order_seed(fresh_entropy)
    return sorted(loci, key=lambda i: (seed[2 * i], seed[2 * i + 1], i))


def _rank_raw_flavour(
    loci: Iterable[int],
    fresh_entropy: bytes,
    frame: tuple[int, int, int],
) -> list[int]:
    phase = _phase36(frame)
    seed = _native_order_seed(fresh_entropy)
    return sorted(
        loci,
        key=lambda i: (
            -(abs(_wrap_pi(phase[i])) / math.pi),
            seed[2 * i],
            seed[2 * i + 1],
            i,
        ),
    )


def _rank_orbital_v2(
    loci: Iterable[int],
    fresh_entropy: bytes,
    frame: tuple[int, int, int],
) -> list[int]:
    """Rank 12 phase orbits first, then use fresh entropy only within each Z3 orbit."""
    loci_t = tuple(loci)
    orbit_scores = _orbit_base_scores(frame)
    seed = _native_order_seed(fresh_entropy)
    groups: dict[int, list[int]] = {}
    for locus in loci_t:
        groups.setdefault(locus // 3, []).append(locus)

    orbit_order = sorted(
        groups,
        key=lambda orbit: (
            -orbit_scores[orbit],
            min((seed[2 * i], seed[2 * i + 1], i) for i in groups[orbit]),
            orbit,
        ),
    )
    first_pass: list[int] = []
    leftovers: list[int] = []
    for orbit in orbit_order:
        members = sorted(
            groups[orbit],
            key=lambda i: (seed[2 * i], seed[2 * i + 1], i),
        )
        first_pass.append(members[0])
        leftovers.extend(members[1:])
    leftovers.sort(
        key=lambda i: (
            -orbit_scores[i // 3],
            seed[2 * i],
            seed[2 * i + 1],
            i,
        )
    )
    return first_pass + leftovers


def _strategy_ranking(
    strategy: str,
    loci: Iterable[int],
    fresh_entropy: bytes,
    frame: tuple[int, int, int],
) -> list[int]:
    if strategy == "A_NATIVE_GENETIC_IR":
        return _rank_native(loci, fresh_entropy)
    if strategy == "B_RANDOM_LOCUS_NULL":
        return _rank_null(loci, fresh_entropy)
    if strategy == "C_RAW_FLAVOUR_PHASE_V1":
        return _rank_raw_flavour(loci, fresh_entropy, frame)
    if strategy == "D_ORBITAL_FLAVOUR_PHASE_V2":
        return _rank_orbital_v2(loci, fresh_entropy, frame)
    raise ValueError(f"unsupported strategy {strategy!r}")


def mutate_with_strategy(
    parent: CipherGenome,
    program: GeneticIRNode,
    *,
    fresh_entropy: bytes,
    strategy: str,
) -> tuple[CipherGenome, CandidateBinding]:
    raw_entropy = bytes(fresh_entropy)
    if len(raw_entropy) < 32:
        raise ValueError("fresh mutation entropy must contain at least 32 bytes")
    phenotype = compile_genetic_program(program)

    # Exact native DNCrypt substrate. Only the admitted-locus ordering changes.
    bound_entropy = hashlib.shake_256(
        b"DNCrypt/v0.6.1/genetic-mutation/fresh|"
        + raw_entropy
        + bytes.fromhex(phenotype.commitment)
    ).digest(max(64, len(raw_entropy)))
    unconstrained = mutate_genome(parent, bound_entropy)

    allowed = tuple(phenotype.allowed_loci)
    changed = tuple(
        i
        for i in allowed
        if unconstrained.operator_vector[i] != parent.operator_vector[i]
    )
    frame = PHASE_FRAMES[_frame_index(raw_entropy)]
    ranking = _strategy_ranking(strategy, allowed, raw_entropy, frame)
    changed_set = set(changed)
    keep = [i for i in ranking if i in changed_set][: phenotype.mutation_budget]
    if not keep:
        keep = [ranking[0]]

    operator = list(parent.operator_vector)
    native_seed = _native_order_seed(raw_entropy)
    for index in keep:
        candidate_value = unconstrained.operator_vector[index]
        if candidate_value == parent.operator_vector[index]:
            delta = 1 + (native_seed[index] % 255)
            candidate_value = (parent.operator_vector[index] + delta) & 0xFF
        operator[index] = candidate_value

    route = list(unconstrained.route)
    shift = (phenotype.route_direction * phenotype.route_stride) % DIM
    route = route[shift:] + route[:shift]

    child = CipherGenome(
        version=unconstrained.version,
        generation=unconstrained.generation,
        parent_id=unconstrained.parent_id,
        operator_vector=tuple(operator),
        route=tuple(route),
        phase_seed_hex=unconstrained.phase_seed_hex,
        mutation_nonce_hex=unconstrained.mutation_nonce_hex,
    )
    changed_loci = tuple(
        i for i in range(DIM)
        if child.operator_vector[i] != parent.operator_vector[i]
    )
    if not changed_loci:
        raise RuntimeError("strategy produced no mutation")
    if not set(changed_loci).issubset(set(allowed)):
        raise RuntimeError("strategy escaped native Genetic IR allowed_loci")
    if len(changed_loci) > phenotype.mutation_budget:
        raise RuntimeError("strategy exceeded native Genetic IR mutation budget")

    binding = CandidateBinding(
        schema=BINDING_SCHEMA,
        strategy=strategy,
        parent_genome_id=parent.genome_id,
        child_genome_id=child.genome_id,
        phenotype_commitment=phenotype.commitment,
        fresh_entropy_commitment=blake2b256(raw_entropy),
        phase_frame_commitment=(
            None
            if strategy in {"A_NATIVE_GENETIC_IR", "B_RANDOM_LOCUS_NULL"}
            else _frame_commitment(frame)
        ),
        changed_loci=changed_loci,
        allowed_loci=allowed,
        mutation_budget=phenotype.mutation_budget,
    )
    return child, binding


def strategy_population(
    parent: CipherGenome,
    program: GeneticIRNode,
    population_size: int,
    *,
    entropy: bytes,
    strategy: str,
) -> tuple[tuple[CipherGenome, ...], tuple[CandidateBinding, ...], str]:
    if population_size < 1:
        raise ValueError("population_size must be positive")
    raw = bytes(entropy)
    if len(raw) != population_size * 64:
        raise ValueError("population entropy must be exactly population_size*64 bytes")
    genomes: list[CipherGenome] = []
    bindings: list[CandidateBinding] = []
    for index in range(population_size):
        child_entropy = hashlib.shake_256(
            b"DNCrypt/v0.6.1/genetic-population|"
            + raw
            + index.to_bytes(8, "big")
        ).digest(64)
        child, binding = mutate_with_strategy(
            parent,
            program,
            fresh_entropy=child_entropy,
            strategy=strategy,
        )
        genomes.append(child)
        bindings.append(binding)
    population = tuple(genomes)
    if len({g.genome_id for g in population}) != len(population):
        raise RuntimeError("strategy population produced duplicate genome ids")
    return population, tuple(bindings), population_commitment(population)


def _single_report_digest(report: FitnessRecord) -> str:
    return blake2b256(canonical_json_bytes(asdict(report)))


def proposal_receipt(
    parent: CipherGenome,
    parent_report: FitnessRecord,
    policy: EvolutionPolicy,
    population: tuple[CipherGenome, ...],
    entropy: bytes,
    *,
    strategy: str,
) -> ProposalReceipt:
    return ProposalReceipt(
        "dncrypt.proposal-receipt/v0.2",
        parent.genome_id,
        _single_report_digest(parent_report),
        policy.digest,
        population_commitment(population),
        blake2b256(bytes(entropy)),
        True,
        f"abcd_observation_only:{strategy}",
    )


def _normalized_record(record: FitnessRecord) -> FitnessRecord:
    return replace(record, throughput=1.0)


def _normalized_report(report: PopulationFitnessReport) -> PopulationFitnessReport:
    return PopulationFitnessReport(
        report.schema,
        report.request_id,
        tuple(_normalized_record(r) for r in report.records),
    )


def _risk(record: FitnessRecord) -> float:
    return record.adversarial_risk(0.05)


def _exact_two_sided_sign_test(wins: int, losses: int) -> float:
    n = wins + losses
    if n == 0:
        return 1.0
    k = min(wins, losses)
    return min(
        1.0,
        2.0 * sum(math.comb(n, i) for i in range(k + 1)) / (2 ** n),
    )


def _summary(values: list[float]) -> dict[str, float]:
    return {
        "mean": float(statistics.fmean(values)),
        "median": float(statistics.median(values)),
        "min": float(min(values)),
        "max": float(max(values)),
    }


def run_replicate(rep: int, cfg: dict) -> dict:
    root = bytes.fromhex(cfg["seed_hex"])
    rep_seed = base.derive(root, "replicate", rep, n=32)
    master = base.derive(rep_seed, "master-key", n=32)
    parent = base.initial_genome(base.derive(rep_seed, "initial-genome", n=64))
    surface = initial_surface(parent)
    program = fixed_program()
    phenotype = compile_genetic_program(program)

    folds = [
        base.corpus(
            rep_seed,
            f"selection-generation-0-fold-{fold_idx}",
            cfg["fold_messages"],
            cfg["message_bytes"],
        )
        for fold_idx in range(cfg["folds"])
    ]
    sealed_holdout = base.corpus(
        rep_seed,
        "sealed-holdout",
        cfg["holdout_messages"],
        cfg["message_bytes"],
    )
    sealed_commitment = base.corpus_commitment(sealed_holdout)

    parent_folds_raw = tuple(
        challenge.evaluate_genome_paired(
            master,
            parent,
            surface,
            messages,
            rep_seed,
            f"parent-f{fold_idx}",
        )
        for fold_idx, messages in enumerate(folds)
    )
    parent_folds = tuple(_normalized_record(r) for r in parent_folds_raw)
    parent_holdout = challenge.evaluate_genome_paired(
        master,
        parent,
        surface,
        sealed_holdout,
        rep_seed,
        "sealed-parent",
    )

    aggregate_parent = base.aggregate_parent_reports(parent_folds_raw)
    proposal_policy = EvolutionPolicy(
        population_size=cfg["population_size"],
        mutation_risk_threshold=0.0,
        minimum_risk_improvement=0.0,
        minimum_throughput_ratio=1.0,
        surface_transition_steps=1,
    )
    generalization_policy = GeneralizationPolicy(
        minimum_folds=cfg["folds"],
        minimum_winning_fraction=cfg["minimum_winning_fraction"],
        minimum_median_risk_improvement=cfg["minimum_median_risk_improvement"],
        maximum_worst_fold_regression=cfg["maximum_worst_fold_regression"],
        maximum_delta_stddev=cfg["maximum_delta_stddev"],
        minimum_throughput_ratio=1.0,
        surface_transition_steps=1,
    )
    statistical_policy = StatisticalAdmissionPolicy(
        fdr_alpha=cfg["fdr_alpha"],
        minimum_effect_improvement=cfg["minimum_effect_improvement"],
        minimum_non_tie_folds=cfg["folds"],
    )
    population_entropy = base.derive(
        rep_seed,
        "abcd-matched-population",
        parent.genome_id,
        n=cfg["population_size"] * 64,
    )

    strategies: dict[str, dict] = {}
    substrate_by_index: dict[int, dict[str, tuple]] = {}

    for strategy in STRATEGIES:
        population, bindings, pop_commit = strategy_population(
            parent,
            program,
            cfg["population_size"],
            entropy=population_entropy,
            strategy=strategy,
        )
        proposal = proposal_receipt(
            parent,
            aggregate_parent,
            proposal_policy,
            population,
            population_entropy,
            strategy=strategy,
        )

        # Verify paired substrate invariants: route/phase/nonce are held matched
        # across strategies candidate-by-candidate; only operator-locus selection varies.
        for i, genome in enumerate(population):
            signature = (
                genome.route,
                genome.phase_seed_hex,
                genome.mutation_nonce_hex,
                genome.parent_id,
                genome.generation,
            )
            substrate_by_index.setdefault(i, {})[strategy] = signature

        fold_reports_raw: list[PopulationFitnessReport] = []
        for fold_idx, messages in enumerate(folds):
            records = tuple(
                challenge.evaluate_genome_paired(
                    master,
                    genome,
                    surface,
                    messages,
                    rep_seed,
                    f"{strategy}-candidate-f{fold_idx}",
                )
                for genome in population
            )
            request_id = blake2b256(canonical_json_bytes({
                "schema": "dncrypt.abcd-observation-request/v0.1",
                "replicate": rep,
                "strategy": strategy,
                "fold": fold_idx,
                "population_commitment": pop_commit,
                "proposal_receipt": proposal.digest,
            }))
            fold_reports_raw.append(
                PopulationFitnessReport(
                    "dncrypt.external-evaluation/v0.2",
                    request_id,
                    records,
                )
            )

        fold_reports = tuple(_normalized_report(r) for r in fold_reports_raw)
        child, child_surface, admission, scores, statistical = (
            select_generation_multifold_statistically_hardened(
                parent,
                surface,
                parent_folds,
                population,
                fold_reports,
                generalization_policy,
                statistical_policy,
                sealed_holdout_commitment=sealed_commitment,
            )
        )

        # Exploratory winner is based only on selection folds. It has NO security
        # admission authority and exists so the search geometry can be compared even
        # when the current DNCrypt causality firewall correctly blocks promotion.
        def exploratory_rank(i: int) -> tuple:
            score = scores[i]
            return (
                score.median_risk_delta,
                score.worst_fold_risk_delta,
                score.delta_stddev,
                score.genome_id,
            )

        exploratory_index = min(range(len(population)), key=exploratory_rank)
        exploratory = population[exploratory_index]
        exploratory_holdout = challenge.evaluate_genome_paired(
            master,
            exploratory,
            surface,
            sealed_holdout,
            rep_seed,
            f"{strategy}-sealed-exploratory",
        )
        admitted_holdout = challenge.evaluate_genome_paired(
            master,
            child,
            child_surface if admission.promoted else surface,
            sealed_holdout,
            rep_seed,
            f"{strategy}-sealed-admitted",
        )

        changed_histogram = [0] * DIM
        for binding in bindings:
            for locus in binding.changed_loci:
                changed_histogram[locus] += 1

        strategies[strategy] = {
            "population_commitment": pop_commit,
            "proposal_receipt": proposal.digest,
            "phenotype_commitment": phenotype.commitment,
            "allowed_loci": list(phenotype.allowed_loci),
            "mutation_budget": phenotype.mutation_budget,
            "binding_commitment": blake2b256(
                canonical_json_bytes([asdict(b) for b in bindings])
            ),
            "changed_locus_histogram": changed_histogram,
            "admission": {
                "promoted": admission.promoted,
                "reason": admission.reason,
                "selected_genome_id": admission.selected_genome_id,
                "receipt": admission.digest,
                "note": "DIAGNOSTIC_SELECTOR_ONLY; current causality firewall remains authoritative for security admission",
            },
            "exploratory": {
                "selected_index": exploratory_index,
                "selected_genome_id": exploratory.genome_id,
                "selection_score": asdict(scores[exploratory_index]),
                "statistical_evidence": asdict(statistical[exploratory_index]),
                "holdout_risk": _risk(exploratory_holdout),
                "holdout_risk_delta_vs_parent": _risk(exploratory_holdout) - _risk(parent_holdout),
                "holdout_record": asdict(exploratory_holdout),
            },
            "admitted_path_holdout": {
                "risk": _risk(admitted_holdout),
                "risk_delta_vs_parent": _risk(admitted_holdout) - _risk(parent_holdout),
                "record": asdict(admitted_holdout),
            },
        }

    substrate_match = all(
        len(set(items.values())) == 1 for items in substrate_by_index.values()
    )
    if not substrate_match:
        raise RuntimeError("A/B/C/D substrate mismatch: route/phase/nonce drift detected")

    return {
        "replicate": rep,
        "parent_genome_id": parent.genome_id,
        "genetic_ir_id": program.semantic_id,
        "phenotype_commitment": phenotype.commitment,
        "allowed_loci": list(phenotype.allowed_loci),
        "mutation_budget": phenotype.mutation_budget,
        "population_entropy_commitment": blake2b256(population_entropy),
        "paired_substrate_match": substrate_match,
        "sealed_holdout": {
            "commitment": sealed_commitment,
            "used_for_selection": False,
            "opened_after_selection": True,
            "message_count": len(sealed_holdout),
        },
        "parent_holdout_risk": _risk(parent_holdout),
        "strategies": strategies,
    }


def run(cfg: dict) -> dict:
    reps = [run_replicate(i, cfg) for i in range(cfg["replicates"])]

    strategy_summary: dict[str, dict] = {}
    for strategy in STRATEGIES:
        deltas = [
            rep["strategies"][strategy]["exploratory"]["holdout_risk_delta_vs_parent"]
            for rep in reps
        ]
        wins = sum(x < 0 for x in deltas)
        losses = sum(x > 0 for x in deltas)
        ties = len(deltas) - wins - losses
        strategy_summary[strategy] = {
            "exploratory_holdout_delta": _summary(deltas),
            "wins_vs_parent": wins,
            "losses_vs_parent": losses,
            "ties": ties,
            "sign_test_two_sided_p": _exact_two_sided_sign_test(wins, losses),
            "diagnostic_selector_promotions": sum(
                bool(rep["strategies"][strategy]["admission"]["promoted"])
                for rep in reps
            ),
        }

    pairwise_d: dict[str, dict] = {}
    d = "D_ORBITAL_FLAVOUR_PHASE_V2"
    for other in STRATEGIES[:-1]:
        diffs = [
            rep["strategies"][d]["exploratory"]["holdout_risk_delta_vs_parent"]
            - rep["strategies"][other]["exploratory"]["holdout_risk_delta_vs_parent"]
            for rep in reps
        ]
        d_wins = sum(x < 0 for x in diffs)
        other_wins = sum(x > 0 for x in diffs)
        ties = len(diffs) - d_wins - other_wins
        pairwise_d[f"{d}_minus_{other}"] = {
            "paired_delta": _summary(diffs),
            "D_lower_risk_count": d_wins,
            "other_lower_risk_count": other_wins,
            "ties": ties,
            "sign_test_two_sided_p": _exact_two_sided_sign_test(d_wins, other_wins),
        }

    result = {
        "schema": SCHEMA,
        "status": "PASS",
        "evidence_class": "CONTROLLED_PAIRED_ACTUAL_CIPHERTEXT_OBSERVATION",
        "authority": {
            "security_admission": False,
            "cryptographic_entropy": False,
            "changes_frozen_aead": False,
            "holdout_used_for_selection": False,
        },
        "configuration": cfg,
        "strategies": list(STRATEGIES),
        "matched_design": {
            "same_parent_per_replicate": True,
            "same_fresh_population_entropy_per_replicate": True,
            "same_native_genetic_ir_phenotype": True,
            "same_route_phase_seed_mutation_nonce_per_candidate_index": True,
            "same_selection_corpora": True,
            "same_paired_ciphertext_entropy_schedule": True,
            "same_sealed_holdout": True,
            "only_operator_locus_ordering_varies": True,
        },
        "primary_endpoint": "sealed_holdout_diagnostic_adversarial_risk_of_selection_fold_exploratory_winner",
        "strategy_summary": strategy_summary,
        "pairwise_D": pairwise_d,
        "all_substrate_matches": all(rep["paired_substrate_match"] for rep in reps),
        "all_holdouts_excluded_from_selection": all(
            not rep["sealed_holdout"]["used_for_selection"] for rep in reps
        ),
        "replicates": reps,
        "interpretation_boundary": (
            "Observation-only comparison of mutation search geometry under the real paired "
            "DNCrypt ciphertext evaluator. It does not promote ciphertext diagnostics to "
            "security-admission evidence and does not alter the frozen v0.2 AEAD anchor."
        ),
    }
    result["commitment_blake2b"] = blake2b256(canonical_json_bytes(result))
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True)
    ap.add_argument("--replicates", type=int, default=8)
    ap.add_argument("--population-size", type=int, default=12)
    ap.add_argument("--folds", type=int, default=6)
    ap.add_argument("--fold-messages", type=int, default=16)
    ap.add_argument("--holdout-messages", type=int, default=64)
    ap.add_argument("--message-bytes", type=int, default=128)
    args = ap.parse_args()
    cfg = {
        "seed_hex": hashlib.sha256(
            b"DNCrypt NOEMA prime-phase A/B/C/D challenge v0.1 frozen seed"
        ).hexdigest(),
        "replicates": args.replicates,
        "population_size": args.population_size,
        "folds": args.folds,
        "fold_messages": args.fold_messages,
        "holdout_messages": args.holdout_messages,
        "message_bytes": args.message_bytes,
        "minimum_winning_fraction": 2 / 3,
        "minimum_median_risk_improvement": 0.0,
        "maximum_worst_fold_regression": 0.02,
        "maximum_delta_stddev": 0.05,
        "fdr_alpha": 0.05,
        "minimum_effect_improvement": 0.0,
    }
    out = run(cfg)
    Path(args.output).write_text(
        json.dumps(out, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    printable = {
        "status": out["status"],
        "evidence_class": out["evidence_class"],
        "strategy_summary": out["strategy_summary"],
        "pairwise_D": out["pairwise_D"],
        "all_substrate_matches": out["all_substrate_matches"],
        "all_holdouts_excluded_from_selection": out["all_holdouts_excluded_from_selection"],
        "commitment_blake2b": out["commitment_blake2b"],
    }
    print(json.dumps(printable, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
