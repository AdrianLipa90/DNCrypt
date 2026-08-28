from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("challenge_v042", ROOT / "tools" / "cryptanalysis_challenge_v042.py")
challenge = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(challenge)


def test_v042_frozen_anchor_null_is_exactly_stable():
    cfg = {
        "seed_hex": "55" * 32,
        "replicates": 2,
        "generations": 2,
        "population_size": 4,
        "folds": 3,
        "fold_messages": 4,
        "holdout_messages": 6,
        "message_bytes": 32,
        "minimum_winning_fraction": 2 / 3,
        "minimum_median_risk_improvement": 0.0,
        "maximum_worst_fold_regression": 0.05,
        "maximum_delta_stddev": 0.20,
        "minimum_throughput_ratio": 0.1,
    }
    a = challenge.run(cfg)
    b = challenge.run(cfg)
    assert a["summary"]["mean_promotions"] == 0.0
    assert a["summary"]["adaptive_holdout_wins"] == 0
    assert a["summary"]["static_holdout_wins"] == 0
    assert a["summary"]["ties"] == 2
    assert a["summary"]["mean_holdout_risk_delta_adaptive_minus_static"] == 0.0
    assert a["fitness_causality_firewall"]["admission_fields"] == []
    assert a["fitness_causality_firewall"]["paired_entropy_schedule"] is True
    assert a["security_evidence_commitment_blake2b"] == b["security_evidence_commitment_blake2b"]
