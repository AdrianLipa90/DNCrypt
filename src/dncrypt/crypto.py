from __future__ import annotations
from dataclasses import dataclass, asdict
import json, secrets
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .genome import CipherGenome
from .surface import CipherSurface
from .util import b64e, b64d, canonical_json_bytes, blake2b256, sha3_256

VERSION = "DNCrypt/v0.2"
PROTOCOL_ID = "dncrypt.frozen-protocol/v0.2"

@dataclass(frozen=True, slots=True)
class DNCryptEnvelope:
    version: str
    protocol_id: str
    generation: int
    tick: int
    genome_id: str
    surface_commitment: str
    parent_receipt: str | None
    salt_b64: str
    nonce_b64: str
    aad_b64: str
    ciphertext_b64: str
    entropy_commitment_blake2b: str
    receipt_blake2b: str
    receipt_sha3_256: str

    def __post_init__(self) -> None:
        if self.version != VERSION or self.protocol_id != PROTOCOL_ID:
            raise ValueError("unsupported envelope version/protocol")
        if self.generation < 0 or self.tick < 0:
            raise ValueError("invalid generation/tick")
        if len(b64d(self.salt_b64)) != 32 or len(b64d(self.nonce_b64)) != 12:
            raise ValueError("invalid salt or nonce length")

    def _receipt_payload(self) -> dict[str, object]:
        d = asdict(self)
        d.pop("receipt_blake2b", None)
        d.pop("receipt_sha3_256", None)
        return d

    def verify_receipt(self) -> bool:
        raw = canonical_json_bytes(self._receipt_payload())
        return blake2b256(raw) == self.receipt_blake2b and sha3_256(raw) == self.receipt_sha3_256

    def to_bytes(self) -> bytes:
        return canonical_json_bytes(asdict(self))

    @classmethod
    def from_bytes(cls, raw: bytes) -> "DNCryptEnvelope":
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("envelope root must be object")
        return cls(**value)


def generate_master_key() -> bytes:
    return secrets.token_bytes(32)


def _derive_message_key(master_key: bytes, salt: bytes, genome: CipherGenome) -> bytes:
    if len(master_key) != 32:
        raise ValueError("master_key must be exactly 32 bytes")
    info = b"DNCrypt/v0.2/message-key/" + bytes.fromhex(genome.genome_id)
    return HKDF(algorithm=hashes.SHA3_512(), length=32, salt=salt, info=info).derive(master_key)


def _aad_bytes(genome: CipherGenome, surface: CipherSurface, parent_receipt: str | None, user_aad: bytes) -> bytes:
    meta = {
        "version": VERSION,
        "protocol_id": PROTOCOL_ID,
        "generation": genome.generation,
        "tick": surface.tick,
        "genome_id": genome.genome_id,
        "surface_commitment": surface.commitment,
        "parent_receipt": parent_receipt,
        "user_aad": b64e(user_aad),
    }
    return canonical_json_bytes(meta)


def encrypt(master_key: bytes, plaintext: bytes, genome: CipherGenome, surface: CipherSurface, *, user_aad: bytes = b"", parent_receipt: str | None = None, entropy: bytes | None = None) -> DNCryptEnvelope:
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")
    e = secrets.token_bytes(44) if entropy is None else bytes(entropy)
    if len(e) != 44:
        raise ValueError("entropy must be exactly 44 bytes (32-byte salt + 12-byte nonce)")
    salt, nonce = e[:32], e[32:]
    key = _derive_message_key(master_key, salt, genome)
    aad = _aad_bytes(genome, surface, parent_receipt, bytes(user_aad))
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, bytes(plaintext), aad)
    payload = {
        "version": VERSION,
        "protocol_id": PROTOCOL_ID,
        "generation": genome.generation,
        "tick": surface.tick,
        "genome_id": genome.genome_id,
        "surface_commitment": surface.commitment,
        "parent_receipt": parent_receipt,
        "salt_b64": b64e(salt),
        "nonce_b64": b64e(nonce),
        "aad_b64": b64e(aad),
        "ciphertext_b64": b64e(ciphertext),
        "entropy_commitment_blake2b": blake2b256(e),
    }
    raw = canonical_json_bytes(payload)
    return DNCryptEnvelope(**payload, receipt_blake2b=blake2b256(raw), receipt_sha3_256=sha3_256(raw))


def decrypt(master_key: bytes, envelope: DNCryptEnvelope, genome: CipherGenome, surface: CipherSurface) -> bytes:
    if not envelope.verify_receipt():
        raise ValueError("provenance receipt mismatch")
    if envelope.genome_id != genome.genome_id or envelope.generation != genome.generation:
        raise ValueError("genome binding mismatch")
    if envelope.surface_commitment != surface.commitment or envelope.tick != surface.tick:
        raise ValueError("surface binding mismatch")
    salt = b64d(envelope.salt_b64)
    nonce = b64d(envelope.nonce_b64)
    aad = b64d(envelope.aad_b64)
    ciphertext = b64d(envelope.ciphertext_b64)
    key = _derive_message_key(master_key, salt, genome)
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise ValueError("authentication failed") from exc
