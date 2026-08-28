from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("challenge_v041", ROOT / "tools" / "cryptanalysis_challenge_v041.py")
challenge = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(challenge)


def test_v041_security_commitment_replays_while_performance_is_observational():
    cfg = {
        "seed_hex": "44" * 32,
        "replicates": 2,
        "generations": 1,
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
    assert a["security_evidence_commitment_blake2b"] == b["security_evidence_commitment_blake2b"]
    assert a["security_admission"]["performance_mode"] == "observe_only"
    assert a["security_admission"]["wallclock_performance_in_security_selection"] is False
    assert a["summary"]["all_holdouts_excluded_from_selection"] is True
    assert len(a["measurement_commitment_blake2b"]) == 64
