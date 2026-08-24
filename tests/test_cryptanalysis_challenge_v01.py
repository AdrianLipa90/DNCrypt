from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("challenge", ROOT / "tools" / "cryptanalysis_challenge_v01.py")
challenge = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(challenge)


def test_challenge_smoke_preserves_integrity_and_holdout_fields():
    cfg = {
        "seed_hex": "11" * 32,
        "replicates": 2,
        "generations": 1,
        "population_size": 4,
        "train_messages": 4,
        "holdout_messages": 6,
        "message_bytes": 32,
        "minimum_throughput_ratio": 0.1,
    }
    out = challenge.run(cfg)
    assert out["status"] == "PASS"
    assert out["verdict"] in {"HOLDOUT_ADVANTAGE_DEMONSTRATED", "NO_HOLDOUT_ADVANTAGE_DEMONSTRATED"}
    assert out["summary"]["replicates"] == 2
    for rep in out["replicates"]:
        assert rep["static_holdout"]["decrypt_failures"] == 0
        assert rep["static_holdout"]["integrity_failures"] == 0
        assert rep["adaptive_holdout"]["decrypt_failures"] == 0
        assert rep["adaptive_holdout"]["integrity_failures"] == 0
        assert "train_risk_delta_adaptive_minus_static" in rep
        assert "holdout_risk_delta_adaptive_minus_static" in rep
