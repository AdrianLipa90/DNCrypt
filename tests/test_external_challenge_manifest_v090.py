from __future__ import annotations

import json
from pathlib import Path

from dncrypt.cryptanalysis_release import CryptanalysisChallengeManifest


def test_frozen_external_challenge_manifest_commitment_matches_provenance_file():
    path = Path("provenance/DNCRYPT_EXTERNAL_CRYPTANALYSIS_CHALLENGE_V1.json")
    value = json.loads(path.read_text())
    manifest = dict(value["manifest"])
    manifest["attack_tracks"] = tuple(manifest["attack_tracks"])
    manifest["required_artifacts"] = tuple(manifest["required_artifacts"])
    parsed = CryptanalysisChallengeManifest(**manifest)
    assert parsed.challenge_id == value["challenge_id"]
    assert parsed.target_commit_sha == "8651c3914e060cad5fd6ca1751f4420eb7a8360d"
    assert value["internal_benchmark"]["classification"] == (
        "CONTROLLED_INTERNAL_BENCHMARK_NOT_INDEPENDENT_CRYPTANALYSIS"
    )
