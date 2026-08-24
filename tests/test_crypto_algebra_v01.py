from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path
import sys

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from dncrypt.crypto_algebra_v01 import (
    PNCSCryptoAlgebraError,
    add_mod32,
    blake2b,
    blake2b256,
    chacha20_block,
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
    chacha20_xor,
    chacha_quarter_round,
    hkdf_sha3_512,
    hmac_sha3_512,
    poly1305_mac,
    rotl32,
    sha3_256,
    sha3_512,
    shake256,
    xor32,
)


def test_word_algebra():
    assert add_mod32(0xFFFFFFFF, 1) == 0
    assert xor32(0xAAAAAAAA, 0x55555555) == 0xFFFFFFFF
    assert rotl32(0x12345678, 8) == 0x34567812


def test_rfc8439_quarter_round_vector():
    assert chacha_quarter_round(0x11111111, 0x01020304, 0x9B8D6F43, 0x01234567) == (
        0xEA2A92F4, 0xCB1CF8CE, 0x4581472E, 0x5881C4BB
    )


def test_rfc8439_chacha20_block_vector():
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    expected = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )
    assert chacha20_block(key, 1, nonce) == expected


def test_rfc8439_chacha20_cipher_vector():
    key = bytes(range(32))
    nonce = bytes.fromhex("000000000000004a00000000")
    plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    expected = bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42"
        "874d"
    )
    assert chacha20_xor(key, 1, nonce, plaintext) == expected


def test_rfc8439_poly1305_vector():
    key = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b"
    )
    assert poly1305_mac(b"Cryptographic Forum Research Group", key).hex() == "a8061dc1305136c6c22b8baf0c0127a9"


def test_rfc8439_aead_vector():
    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    expected_ct = bytes.fromhex(
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116"
    )
    expected_tag = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")
    out = chacha20_poly1305_encrypt(key, nonce, plaintext, aad)
    assert out == expected_ct + expected_tag
    assert chacha20_poly1305_decrypt(key, nonce, out, aad) == plaintext


def test_aead_fail_closed_on_tag_mutation():
    key = bytes(range(32)); nonce = bytes(range(12)); aad = b"aad"; pt = b"payload"
    out = bytearray(chacha20_poly1305_encrypt(key, nonce, pt, aad))
    out[-1] ^= 1
    with pytest.raises(PNCSCryptoAlgebraError):
        chacha20_poly1305_decrypt(key, nonce, bytes(out), aad)


def test_fips202_sha3_and_shake_against_stdlib():
    for n in (0, 1, 3, 31, 72, 135, 136, 137, 511):
        msg = bytes((i * 29 + 11) % 256 for i in range(n))
        assert sha3_256(msg) == hashlib.sha3_256(msg).digest()
        assert sha3_512(msg) == hashlib.sha3_512(msg).digest()
        assert shake256(msg, 97) == hashlib.shake_256(msg).digest(97)


def test_hmac_sha3_512_against_stdlib():
    vectors = [
        (b"", b""),
        (b"key", b"message"),
        (bytes(range(72)), bytes(range(50))),
        (bytes(range(100)), bytes(range(200))),
    ]
    for key, msg in vectors:
        assert hmac_sha3_512(key, msg) == hmac.new(key, msg, hashlib.sha3_512).digest()


def test_hkdf_sha3_512_against_cryptography():
    for i in range(12):
        ikm = bytes((x * 13 + i) % 256 for x in range(32 + i))
        salt = bytes((x * 7 + 2 * i) % 256 for x in range(16 + i))
        info = b"PNCS/DNCrypt/HKDF/" + bytes((i,))
        length = 1 + ((i * 17) % 96)
        native = hkdf_sha3_512(ikm, salt, info, length)
        ref = HKDF(algorithm=hashes.SHA3_512(), length=length, salt=salt, info=info).derive(ikm)
        assert native == ref


def test_blake2b_rfc_and_stdlib():
    assert blake2b(b"abc", 64).hex() == (
        "ba80a53f981c4d0d6a2797b69f12f6e9"
        "4c212f14685ac4b74b12bb6fdbffa2d1"
        "7d87c5392aab792dc252d5de4533cc95"
        "18d38aa8dbf1925ab92386edd4009923"
    )
    for n in (0, 1, 3, 127, 128, 129, 255, 256, 1000):
        msg = bytes((i * 7 + 3) % 256 for i in range(n))
        assert blake2b(msg, 64) == hashlib.blake2b(msg, digest_size=64).digest()
        assert blake2b256(msg) == hashlib.blake2b(msg, digest_size=32).digest()


def test_deterministic_aead_differential_against_cryptography():
    for i in range(32):
        key = bytes((x * 11 + i) % 256 for x in range(32))
        nonce = bytes((x * 19 + 3 * i) % 256 for x in range(12))
        aad = bytes((x * 5 + i) % 256 for x in range(i % 23))
        pt = bytes((x * 17 + 7 * i) % 256 for x in range((i * 37) % 257))
        native = chacha20_poly1305_encrypt(key, nonce, pt, aad)
        ref = ChaCha20Poly1305(key).encrypt(nonce, pt, aad)
        assert native == ref
        assert chacha20_poly1305_decrypt(key, nonce, native, aad) == pt


def test_pnv_uses_existing_relation_alphabet_only():
    allowed = {"IDENTITY", "DIFFERENCE", "COMPOSITION", "TRANSFORM", "CONDITION", "RESOLVE", "DERIVE", "ORDER"}
    pnv = (REPO_ROOT / "native" / "experimental" / "PNCS_CRYPTOGRAPHIC_ALGEBRA_V0_1.pnv").read_text().splitlines()
    for line in pnv:
        if line.startswith("OP "):
            relation = line.split()[2]
            assert relation in allowed


def test_dncrypt_v02_exact_native_crypto_conformance():
    from dncrypt.genome import initial_genome
    from dncrypt.surface import initial_surface
    from dncrypt.crypto import encrypt as ref_encrypt
    from dncrypt.util import b64d, canonical_json_bytes

    genome = initial_genome(bytes(range(64)))
    surface = initial_surface(genome)
    master = bytes(range(32))
    entropy = bytes((255 - i) % 256 for i in range(44))
    user_aad = b"pncs-native-crypto-v02"
    plaintext = b"DNCrypt native PNCS crypto algebra exact conformance"
    envelope = ref_encrypt(master, plaintext, genome, surface, user_aad=user_aad, entropy=entropy)

    salt, nonce = entropy[:32], entropy[32:]
    info = b"DNCrypt/v0.2/message-key/" + bytes.fromhex(genome.genome_id)
    native_key = hkdf_sha3_512(master, salt, info, 32)
    ref_key = HKDF(algorithm=hashes.SHA3_512(), length=32, salt=salt, info=info).derive(master)
    assert native_key == ref_key

    aad = b64d(envelope.aad_b64)
    native_ct = chacha20_poly1305_encrypt(native_key, nonce, plaintext, aad)
    assert native_ct == b64d(envelope.ciphertext_b64)
    assert chacha20_poly1305_decrypt(native_key, nonce, native_ct, aad) == plaintext

    payload = envelope._receipt_payload()
    raw = canonical_json_bytes(payload)
    assert blake2b256(raw).hex() == envelope.receipt_blake2b
    assert sha3_256(raw).hex() == envelope.receipt_sha3_256

    phase_input = bytes.fromhex(genome.phase_seed_hex) + b"DNCrypt/v0.2/phase36"
    assert shake256(phase_input, 36 * 8) == hashlib.shake_256(phase_input).digest(36 * 8)


def test_native_registry_is_self_consistent():
    reg = json.loads((REPO_ROOT / "registry" / "programs" / "DNCRYPT_NATIVE_CRYPTO_REGISTRY_V0_2.json").read_text())
    assert reg["deterministic_crypto_native"] is True
    assert reg["external_entropy_effect_only"] is True
    assert len(reg["primitives"]) == 6
    assert {p["role"] for p in reg["primitives"]} >= {"aead", "message_key_derivation", "content_commitment", "entropy_source"}
