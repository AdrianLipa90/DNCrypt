from __future__ import annotations
from dataclasses import asdict
import json, os
from pathlib import Path
from .evolution import ProposalReceipt, PromotionReceipt
from .util import canonical_json_bytes, blake2b256


def append_evolution_receipt(path: str | Path, receipt: ProposalReceipt | PromotionReceipt) -> str:
    p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    record = {"schema": "dncrypt.evolution-ledger-record/v0.2", "receipt_type": type(receipt).__name__, "receipt": asdict(receipt), "receipt_digest": receipt.digest}
    record["record_digest"] = blake2b256(canonical_json_bytes(record))
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, canonical_json_bytes(record) + b"\n"); os.fsync(fd)
    finally:
        os.close(fd)
    return record["record_digest"]


def verify_evolution_ledger(path: str | Path) -> bool:
    p = Path(path)
    if not p.exists():
        return True
    for raw in p.read_bytes().splitlines():
        if not raw:
            continue
        value = json.loads(raw)
        digest = value.pop("record_digest", None)
        if digest != blake2b256(canonical_json_bytes(value)):
            raise ValueError("evolution ledger record digest mismatch")
    return True
