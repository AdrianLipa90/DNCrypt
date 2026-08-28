from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("causal_audit", ROOT / "tools" / "crypto_causal_surface_audit.py")
audit = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(audit)


def test_crypto_causal_surface_is_explicit_and_receipted():
    out = audit.run(ROOT / "src/dncrypt/crypto.py", ROOT / "src/dncrypt/genome.py")
    assert out["status"] == "PASS_CAUSAL_BOUNDARY_IDENTIFIED"
    assert out["frozen_anchor"] == {"kdf": "HKDF-SHA3-512", "aead": "ChaCha20-Poly1305"}
    assert out["dataflow"]["message_key_genome_attributes"] == ["genome_id"]
    assert set(out["dataflow"]["aad_genome_attributes"]) == {"generation", "genome_id"}
    assert set(out["dataflow"]["aad_surface_attributes"]) == {"commitment", "tick"}
    assert out["adaptive_state_binding"]["next_frontier"] == "ADAPTIVE_SECURITY_CONTROL_STATE"
    assert len(out["receipt_sha256"]) == 64
