from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

from dncrypt.security_admission import select_generation_multifold_security_only
from dncrypt.util import blake2b256, canonical_json_bytes

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("dncrypt_challenge_v02_base", ROOT / "tools" / "cryptanalysis_challenge_v02.py")
base = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(base)


def _selector_adapter(*args, **kwargs):
    child, surface, receipt, scores, _binding = select_generation_multifold_security_only(*args, **kwargs)
    return child, surface, receipt, scores


def _security_projection(value):
    if isinstance(value, dict):
        projected = {}
        for key, item in value.items():
            if key == "commitment_blake2b" or "throughput" in key:
                continue
            projected[key] = _security_projection(item)
        return projected
    if isinstance(value, list):
        return [_security_projection(item) for item in value]
    return value


def run(cfg: dict) -> dict:
    run_cfg = dict(cfg)
    run_cfg["performance_mode"] = "observe_only"
    original_selector = base.select_generation_multifold
    base.select_generation_multifold = _selector_adapter
    try:
        result = base.run(run_cfg)
    finally:
        base.select_generation_multifold = original_selector

    measurement_commitment = result.pop("commitment_blake2b")
    result["security_admission"] = {
        "schema": "dncrypt.security-admission/v0.4.1",
        "performance_mode": "observe_only",
        "wallclock_performance_in_security_selection": False,
    }
    projection = _security_projection(result)
    result["security_evidence_commitment_blake2b"] = blake2b256(canonical_json_bytes(projection))
    result["measurement_commitment_blake2b"] = measurement_commitment
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True)
    ap.add_argument("--replicates", type=int, default=12)
    ap.add_argument("--generations", type=int, default=3)
    ap.add_argument("--population-size", type=int, default=24)
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--fold-messages", type=int, default=48)
    ap.add_argument("--holdout-messages", type=int, default=192)
    ap.add_argument("--message-bytes", type=int, default=256)
    args = ap.parse_args()
    cfg = {
        "seed_hex": hashlib.sha256(b"DNCrypt Cryptanalysis Challenge v0.4.1 frozen seed").hexdigest(),
        "replicates": args.replicates,
        "generations": args.generations,
        "population_size": args.population_size,
        "folds": args.folds,
        "fold_messages": args.fold_messages,
        "holdout_messages": args.holdout_messages,
        "message_bytes": args.message_bytes,
        "minimum_winning_fraction": 0.60,
        "minimum_median_risk_improvement": 0.0,
        "maximum_worst_fold_regression": 0.02,
        "maximum_delta_stddev": 0.05,
        "minimum_throughput_ratio": 0.50,
    }
    out = run(cfg)
    Path(args.output).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "verdict": out["verdict"],
        **out["summary"],
        "security_commitment": out["security_evidence_commitment_blake2b"],
        "measurement_commitment": out["measurement_commitment_blake2b"],
    }, indent=2))


if __name__ == "__main__":
    main()
