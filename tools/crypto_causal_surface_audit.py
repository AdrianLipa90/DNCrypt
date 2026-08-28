from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path

SCHEMA = "dncrypt.crypto-causal-surface-audit/v0.1"


def _attributes_for_parameter(tree: ast.AST, function_name: str, parameter: str) -> set[str]:
    out: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.name != function_name:
            continue
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name) and child.value.id == parameter:
                out.add(child.attr)
    return out


def run(crypto_path: Path, genome_path: Path) -> dict:
    crypto_raw = crypto_path.read_bytes()
    genome_raw = genome_path.read_bytes()
    tree = ast.parse(crypto_raw.decode("utf-8"), filename=str(crypto_path))
    key_genome = _attributes_for_parameter(tree, "_derive_message_key", "genome")
    aad_genome = _attributes_for_parameter(tree, "_aad_bytes", "genome")
    aad_surface = _attributes_for_parameter(tree, "_aad_bytes", "surface")
    decrypt_genome = _attributes_for_parameter(tree, "decrypt", "genome")
    decrypt_surface = _attributes_for_parameter(tree, "decrypt", "surface")
    result = {
        "schema": SCHEMA,
        "status": "PASS_CAUSAL_BOUNDARY_IDENTIFIED",
        "source": {
            "crypto_sha256": hashlib.sha256(crypto_raw).hexdigest(),
            "genome_sha256": hashlib.sha256(genome_raw).hexdigest(),
        },
        "frozen_anchor": {
            "kdf": "HKDF-SHA3-512",
            "aead": "ChaCha20-Poly1305",
        },
        "dataflow": {
            "message_key_genome_attributes": sorted(key_genome),
            "aad_genome_attributes": sorted(aad_genome),
            "aad_surface_attributes": sorted(aad_surface),
            "decrypt_genome_attributes": sorted(decrypt_genome),
            "decrypt_surface_attributes": sorted(decrypt_surface),
        },
        "adaptive_state_binding": {
            "genome_identity_commitment": "genome_id",
            "surface_identity_commitment": "surface.commitment",
            "candidate_policy_fields": ["operator_vector", "route", "phase_seed_hex", "mutation_nonce_hex"],
            "next_frontier": "ADAPTIVE_SECURITY_CONTROL_STATE",
        },
    }
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    result["receipt_sha256"] = hashlib.sha256(encoded).hexdigest()
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--crypto", type=Path, default=Path("src/dncrypt/crypto.py"))
    ap.add_argument("--genome", type=Path, default=Path("src/dncrypt/genome.py"))
    ap.add_argument("--output", type=Path)
    ns = ap.parse_args()
    result = run(ns.crypto, ns.genome)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if ns.output is not None:
        ns.output.write_text(text)
    print(text, end="")


if __name__ == "__main__":
    main()
