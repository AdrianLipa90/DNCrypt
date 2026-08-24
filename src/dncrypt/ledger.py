from __future__ import annotations
from dataclasses import asdict
import json, os
from pathlib import Path
from .crypto import DNCryptEnvelope
from .genome import CipherGenome
from .surface import CipherSurface
from .util import canonical_json_bytes, blake2b256


def append_ledger_record(path: str | Path, envelope: DNCryptEnvelope, genome: CipherGenome, surface: CipherSurface) -> str:
    if envelope.genome_id != genome.genome_id or envelope.surface_commitment != surface.commitment:
        raise ValueError("ledger binding mismatch")
    p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    record = {"schema": "dncrypt.ledger-record/v0.2", "receipt": envelope.receipt_blake2b, "parent_receipt": envelope.parent_receipt, "generation": envelope.generation, "tick": envelope.tick, "genome": asdict(genome), "surface": asdict(surface), "envelope_sha3_256": envelope.receipt_sha3_256}
    record["record_digest"] = blake2b256(canonical_json_bytes(record))
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, canonical_json_bytes(record) + b"\n"); os.fsync(fd)
    finally:
        os.close(fd)
    return record["record_digest"]


def resolve_ledger_record(path: str | Path, receipt: str) -> tuple[CipherGenome, CipherSurface]:
    p = Path(path)
    if not p.exists(): raise FileNotFoundError(p)
    match = None
    for raw in p.read_bytes().splitlines():
        if not raw: continue
        value = json.loads(raw)
        digest = value.pop("record_digest", None)
        if digest != blake2b256(canonical_json_bytes(value)):
            raise ValueError("ledger record digest mismatch")
        if value.get("receipt") == receipt:
            if match is not None: raise ValueError("duplicate receipt in ledger")
            match = value
    if match is None: raise KeyError(receipt)
    g = dict(match["genome"]); g["operator_vector"] = tuple(g["operator_vector"]); g["route"] = tuple(g["route"])
    s = dict(match["surface"]); s["phi"] = tuple(s["phi"]); s["omega"] = tuple(s["omega"])
    return CipherGenome(**g), CipherSurface(**s)
