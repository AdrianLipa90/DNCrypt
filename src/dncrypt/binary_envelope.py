from __future__ import annotations

import hashlib
import struct

from .crypto import DNCryptEnvelope, PROTOCOL_ID, VERSION
from .util import b64d, b64e

MAGIC = b"DNCB"
CODEC_VERSION = 1
CODEC_ID = "dncrypt.binary-envelope/v0.1"

# magic, codec_version, flags, reserved, generation, tick,
# parent_len, aad_len, ciphertext_len
_HEADER = struct.Struct(">4sBBHQQHII")
_PARENT_PRESENT = 0x01
_KNOWN_FLAGS = _PARENT_PRESENT
_FIXED_BYTES = 32 + 32 + 32 + 12 + 32 + 32 + 32
MAX_COMPONENT_BYTES = 64 * 1024 * 1024


def _hex32(value: str, field: str) -> bytes:
    try:
        raw = bytes.fromhex(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be hex") from exc
    if len(raw) != 32:
        raise ValueError(f"{field} must encode 32 bytes")
    return raw


def pack_envelope(envelope: DNCryptEnvelope) -> bytes:
    if not isinstance(envelope, DNCryptEnvelope):
        raise TypeError("DNCryptEnvelope required")
    if not envelope.verify_receipt():
        raise ValueError("cannot pack envelope with invalid receipt")

    parent = b"" if envelope.parent_receipt is None else envelope.parent_receipt.encode("utf-8")
    if len(parent) > 0xFFFF:
        raise ValueError("parent_receipt is too large for binary envelope")
    aad = b64d(envelope.aad_b64)
    ciphertext = b64d(envelope.ciphertext_b64)
    if len(aad) > MAX_COMPONENT_BYTES or len(ciphertext) > MAX_COMPONENT_BYTES:
        raise ValueError("binary envelope component exceeds bounded codec limit")

    salt = b64d(envelope.salt_b64)
    nonce = b64d(envelope.nonce_b64)
    if len(salt) != 32 or len(nonce) != 12:
        raise ValueError("invalid salt/nonce length")

    flags = _PARENT_PRESENT if envelope.parent_receipt is not None else 0
    header = _HEADER.pack(MAGIC, CODEC_VERSION, flags, 0, envelope.generation, envelope.tick, len(parent), len(aad), len(ciphertext))
    return b"".join((
        header,
        _hex32(envelope.genome_id, "genome_id"),
        _hex32(envelope.surface_commitment, "surface_commitment"),
        salt,
        nonce,
        _hex32(envelope.entropy_commitment_blake2b, "entropy_commitment_blake2b"),
        _hex32(envelope.receipt_blake2b, "receipt_blake2b"),
        _hex32(envelope.receipt_sha3_256, "receipt_sha3_256"),
        parent,
        aad,
        ciphertext,
    ))


def unpack_envelope(raw: bytes, *, verify_receipt: bool = True) -> DNCryptEnvelope:
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        raise TypeError("binary envelope must be bytes-like")
    data = bytes(raw)
    minimum = _HEADER.size + _FIXED_BYTES
    if len(data) < minimum:
        raise ValueError("truncated binary envelope")

    magic, codec_version, flags, reserved, generation, tick, parent_len, aad_len, ciphertext_len = _HEADER.unpack_from(data, 0)
    if magic != MAGIC:
        raise ValueError("invalid binary envelope magic")
    if codec_version != CODEC_VERSION:
        raise ValueError("unsupported binary envelope codec version")
    if flags & ~_KNOWN_FLAGS:
        raise ValueError("unknown binary envelope flags")
    if reserved != 0:
        raise ValueError("binary envelope reserved field must be zero")
    if aad_len > MAX_COMPONENT_BYTES or ciphertext_len > MAX_COMPONENT_BYTES:
        raise ValueError("binary envelope component exceeds bounded codec limit")

    expected = minimum + parent_len + aad_len + ciphertext_len
    if len(data) != expected:
        raise ValueError("binary envelope length mismatch")

    off = _HEADER.size

    def take(n: int) -> bytes:
        nonlocal off
        value = data[off:off+n]
        if len(value) != n:
            raise ValueError("truncated binary envelope component")
        off += n
        return value

    genome_id = take(32).hex()
    surface_commitment = take(32).hex()
    salt = take(32)
    nonce = take(12)
    entropy_commitment = take(32).hex()
    receipt_blake2b = take(32).hex()
    receipt_sha3_256 = take(32).hex()
    parent_raw = take(parent_len)
    aad = take(aad_len)
    ciphertext = take(ciphertext_len)

    parent_present = bool(flags & _PARENT_PRESENT)
    if not parent_present and parent_len != 0:
        raise ValueError("parent length present without parent flag")
    if parent_present:
        try:
            parent_receipt = parent_raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("parent_receipt is not UTF-8") from exc
    else:
        parent_receipt = None

    envelope = DNCryptEnvelope(
        version=VERSION,
        protocol_id=PROTOCOL_ID,
        generation=generation,
        tick=tick,
        genome_id=genome_id,
        surface_commitment=surface_commitment,
        parent_receipt=parent_receipt,
        salt_b64=b64e(salt),
        nonce_b64=b64e(nonce),
        aad_b64=b64e(aad),
        ciphertext_b64=b64e(ciphertext),
        entropy_commitment_blake2b=entropy_commitment,
        receipt_blake2b=receipt_blake2b,
        receipt_sha3_256=receipt_sha3_256,
    )
    if verify_receipt and not envelope.verify_receipt():
        raise ValueError("binary envelope reconstructed invalid provenance receipt")
    return envelope


def binary_envelope_id(raw_or_envelope: bytes | DNCryptEnvelope) -> str:
    raw = pack_envelope(raw_or_envelope) if isinstance(raw_or_envelope, DNCryptEnvelope) else bytes(raw_or_envelope)
    return f"dncrypt:binary-envelope:sha256:{hashlib.sha256(raw).hexdigest()}"
