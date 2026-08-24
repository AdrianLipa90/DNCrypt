from __future__ import annotations
from .crypto import DNCryptEnvelope

_ALPHABET = "ACGT"
_TO_BITS = {c: i for i, c in enumerate(_ALPHABET)}

def bytes_to_dna(data: bytes) -> str:
    out = []
    for byte in data:
        out.extend((_ALPHABET[(byte >> 6) & 3], _ALPHABET[(byte >> 4) & 3], _ALPHABET[(byte >> 2) & 3], _ALPHABET[byte & 3]))
    return "".join(out)

def dna_to_bytes(sequence: str) -> bytes:
    seq = "".join(sequence.split()).upper()
    if len(seq) % 4:
        raise ValueError("DNA transport length must be divisible by 4")
    if any(c not in _TO_BITS for c in seq):
        raise ValueError("DNA transport accepts only A/C/G/T")
    out = bytearray()
    for i in range(0, len(seq), 4):
        a,b,c,d = (_TO_BITS[x] for x in seq[i:i+4])
        out.append((a << 6) | (b << 4) | (c << 2) | d)
    return bytes(out)

def envelope_to_dna(envelope: DNCryptEnvelope) -> str:
    return bytes_to_dna(envelope.to_bytes())

def envelope_from_dna(sequence: str) -> DNCryptEnvelope:
    return DNCryptEnvelope.from_bytes(dna_to_bytes(sequence))
