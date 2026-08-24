from __future__ import annotations
import base64, hashlib, json
from typing import Any

def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")

def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text.encode("ascii"))

def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def blake2b256(data: bytes) -> str:
    return hashlib.blake2b(data, digest_size=32).hexdigest()

def sha3_256(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()
