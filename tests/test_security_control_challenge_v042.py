from pathlib import Path
import importlib.util

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("control_challenge",ROOT/"tools/security_control_challenge_v042.py")
challenge=importlib.util.module_from_spec(SPEC); assert SPEC.loader is not None; SPEC.loader.exec_module(challenge)

def test_control_challenge_smoke_is_sealed_and_deterministic():
    cfg={"seed_hex":"55"*32,"replicates":2,"generations":1,"population_size":4,"folds":3,"fold_observations":16,"holdout_observations":32,"minimum_winning_fraction":2/3,"minimum_median_risk_improvement":0.0,"maximum_worst_fold_regression":0.02,"maximum_delta_stddev":0.05}
    a=challenge.run(cfg); b=challenge.run(cfg)
    assert a["commitment_blake2b"]==b["commitment_blake2b"]
    assert a["summary"]["all_holdouts_excluded_from_selection"] is True
    assert a["evidence_class"]=="CONTROLLED_SECURITY_CONTROL_SIMULATION"
