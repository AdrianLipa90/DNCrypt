from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("challenge_v02", ROOT / "tools" / "cryptanalysis_challenge_v02.py")
challenge = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(challenge)


def test_challenge_v02_smoke_keeps_holdout_sealed_until_after_selection():
    cfg = {
        "seed_hex": "22" * 32,
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
    out = challenge.run(cfg)
    assert out["status"] == "PASS"
    assert out["selection_boundary"] == "MULTIFOLD_ONLY_SEALED_HOLDOUT_EXCLUDED"
    assert out["summary"]["all_holdouts_excluded_from_selection"] is True
    assert out["verdict"] in {
        "SEALED_HOLDOUT_ADVANTAGE_DEMONSTRATED",
        "NO_SEALED_HOLDOUT_ADVANTAGE_DEMONSTRATED",
    }
    for rep in out["replicates"]:
        assert rep["sealed_holdout"]["opened_after_all_promotion_decisions"] is True
        assert rep["sealed_holdout"]["used_for_selection"] is False
        assert len(rep["sealed_holdout"]["commitment"]) == 64
        assert rep["static_holdout"]["decrypt_failures"] == 0
        assert rep["static_holdout"]["integrity_failures"] == 0
        assert rep["adaptive_holdout"]["decrypt_failures"] == 0
        assert rep["adaptive_holdout"]["integrity_failures"] == 0
        for generation in rep["generations"]:
            if generation.get("proposed"):
                assert generation["holdout_used_for_selection"] is False
