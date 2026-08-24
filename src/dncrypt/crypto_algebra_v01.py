from __future__ import annotations

from dataclasses import dataclass
import hmac
from typing import Iterable

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF
P1305 = (1 << 130) - 5
R1305_MASK = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF

CHACHA_CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)

KECCAK_RHO = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)

KECCAK_RC = (
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008,
)


class PNCSCryptoAlgebraError(ValueError):
    pass


def add_mod32(a: int, b: int) -> int:
    return (int(a) + int(b)) & MASK32


def xor32(a: int, b: int) -> int:
    return (int(a) ^ int(b)) & MASK32


def rotl32(x: int, n: int) -> int:
    n %= 32
    x &= MASK32
    return ((x << n) | (x >> (32 - n))) & MASK32 if n else x


def rotl64(x: int, n: int) -> int:
    n %= 64
    x &= MASK64
    return ((x << n) | (x >> (64 - n))) & MASK64 if n else x


def chacha_quarter_round(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    a = add_mod32(a, b)
    d = rotl32(xor32(d, a), 16)
    c = add_mod32(c, d)
    b = rotl32(xor32(b, c), 12)
    a = add_mod32(a, b)
    d = rotl32(xor32(d, a), 8)
    c = add_mod32(c, d)
    b = rotl32(xor32(b, c), 7)
    return a, b, c, d


def _qround_state(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a], state[b], state[c], state[d] = chacha_quarter_round(
        state[a], state[b], state[c], state[d]
    )


def chacha_inner_block(state: list[int]) -> None:
    _qround_state(state, 0, 4, 8, 12)
    _qround_state(state, 1, 5, 9, 13)
    _qround_state(state, 2, 6, 10, 14)
    _qround_state(state, 3, 7, 11, 15)
    _qround_state(state, 0, 5, 10, 15)
    _qround_state(state, 1, 6, 11, 12)
    _qround_state(state, 2, 7, 8, 13)
    _qround_state(state, 3, 4, 9, 14)


def chacha20_initial_state(key: bytes, counter: int, nonce: bytes) -> tuple[int, ...]:
    if len(key) != 32:
        raise PNCSCryptoAlgebraError("ChaCha20 key must be 32 bytes")
    if len(nonce) != 12:
        raise PNCSCryptoAlgebraError("ChaCha20 nonce must be 12 bytes")
    if not 0 <= counter <= MASK32:
        raise PNCSCryptoAlgebraError("ChaCha20 counter must fit uint32")
    key_words = tuple(int.from_bytes(key[i:i+4], "little") for i in range(0, 32, 4))
    nonce_words = tuple(int.from_bytes(nonce[i:i+4], "little") for i in range(0, 12, 4))
    return CHACHA_CONSTANTS + key_words + (counter,) + nonce_words


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    initial = chacha20_initial_state(key, counter, nonce)
    state = list(initial)
    for _ in range(10):
        chacha_inner_block(state)
    out = [add_mod32(x, y) for x, y in zip(state, initial)]
    return b"".join(word.to_bytes(4, "little") for word in out)


def chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    if counter < 0 or counter > MASK32:
        raise PNCSCryptoAlgebraError("ChaCha20 counter outside uint32")
    out = bytearray(len(data))
    for block_index, start in enumerate(range(0, len(data), 64)):
        block_counter = counter + block_index
        if block_counter > MASK32:
            raise PNCSCryptoAlgebraError("ChaCha20 counter overflow")
        stream = chacha20_block(key, block_counter, nonce)
        chunk = data[start:start+64]
        out[start:start+len(chunk)] = bytes(a ^ b for a, b in zip(chunk, stream))
    return bytes(out)


def poly1305_clamp(r: bytes) -> int:
    if len(r) != 16:
        raise PNCSCryptoAlgebraError("Poly1305 r must be 16 bytes")
    return int.from_bytes(r, "little") & R1305_MASK


def poly1305_mac(message: bytes, one_time_key: bytes) -> bytes:
    if len(one_time_key) != 32:
        raise PNCSCryptoAlgebraError("Poly1305 one-time key must be 32 bytes")
    r = poly1305_clamp(one_time_key[:16])
    s = int.from_bytes(one_time_key[16:], "little")
    acc = 0
    for start in range(0, len(message), 16):
        block = message[start:start+16]
        n = int.from_bytes(block + b"\x01", "little")
        acc = ((acc + n) * r) % P1305
    tag = (acc + s) & ((1 << 128) - 1)
    return tag.to_bytes(16, "little")


def _pad16(data: bytes) -> bytes:
    rem = len(data) % 16
    return b"" if rem == 0 else bytes(16 - rem)


def chacha20_poly1305_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    otk = chacha20_block(key, 0, nonce)[:32]
    ciphertext = chacha20_xor(key, 1, nonce, plaintext)
    mac_data = (
        aad + _pad16(aad) + ciphertext + _pad16(ciphertext)
        + len(aad).to_bytes(8, "little") + len(ciphertext).to_bytes(8, "little")
    )
    tag = poly1305_mac(mac_data, otk)
    return ciphertext + tag


def chacha20_poly1305_decrypt(key: bytes, nonce: bytes, ciphertext_and_tag: bytes, aad: bytes = b"") -> bytes:
    if len(ciphertext_and_tag) < 16:
        raise PNCSCryptoAlgebraError("AEAD ciphertext shorter than tag")
    ciphertext, tag = ciphertext_and_tag[:-16], ciphertext_and_tag[-16:]
    otk = chacha20_block(key, 0, nonce)[:32]
    mac_data = (
        aad + _pad16(aad) + ciphertext + _pad16(ciphertext)
        + len(aad).to_bytes(8, "little") + len(ciphertext).to_bytes(8, "little")
    )
    expected = poly1305_mac(mac_data, otk)
    if not hmac.compare_digest(tag, expected):
        raise PNCSCryptoAlgebraError("AEAD authentication failed")
    return chacha20_xor(key, 1, nonce, ciphertext)


def keccak_theta(a: list[int]) -> list[int]:
    if len(a) != 25:
        raise PNCSCryptoAlgebraError("Keccak state must contain 25 lanes")
    c = [a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20] for x in range(5)]
    d = [c[(x-1) % 5] ^ rotl64(c[(x+1) % 5], 1) for x in range(5)]
    return [(a[x + 5*y] ^ d[x]) & MASK64 for y in range(5) for x in range(5)]


def keccak_rho(a: list[int]) -> list[int]:
    return [rotl64(a[x + 5*y], KECCAK_RHO[x][y]) for y in range(5) for x in range(5)]


def keccak_pi(a: list[int]) -> list[int]:
    out = [0] * 25
    for y in range(5):
        for x in range(5):
            out[y + 5 * ((2*x + 3*y) % 5)] = a[x + 5*y]
    return out


def keccak_chi(a: list[int]) -> list[int]:
    out = [0] * 25
    for y in range(5):
        row = [a[x + 5*y] for x in range(5)]
        for x in range(5):
            out[x + 5*y] = (row[x] ^ ((~row[(x+1) % 5]) & row[(x+2) % 5])) & MASK64
    return out


def keccak_iota(a: list[int], round_index: int) -> list[int]:
    if not 0 <= round_index < 24:
        raise PNCSCryptoAlgebraError("Keccak round index must be 0..23")
    out = list(a)
    out[0] ^= KECCAK_RC[round_index]
    out[0] &= MASK64
    return out


def keccak_round(a: list[int], round_index: int) -> list[int]:
    return keccak_iota(keccak_chi(keccak_pi(keccak_rho(keccak_theta(a)))), round_index)


def keccak_f1600(state: Iterable[int]) -> tuple[int, ...]:
    a = [int(x) & MASK64 for x in state]
    if len(a) != 25:
        raise PNCSCryptoAlgebraError("Keccak-f[1600] state must contain 25 lanes")
    for rnd in range(24):
        a = keccak_round(a, rnd)
    return tuple(a)


def _sha3_sponge(message: bytes, rate_bytes: int, output_bytes: int, suffix: int) -> bytes:
    if rate_bytes % 8:
        raise PNCSCryptoAlgebraError("rate must be lane-aligned")
    padded = bytearray(message)
    pad_len = rate_bytes - (len(padded) % rate_bytes)
    pad = bytearray(pad_len)
    pad[0] = suffix
    pad[-1] |= 0x80
    padded.extend(pad)
    state = [0] * 25
    lanes = rate_bytes // 8
    for start in range(0, len(padded), rate_bytes):
        block = padded[start:start+rate_bytes]
        for i in range(lanes):
            state[i] ^= int.from_bytes(block[8*i:8*i+8], "little")
        state = list(keccak_f1600(state))
    out = bytearray()
    while len(out) < output_bytes:
        block = b"".join(state[i].to_bytes(8, "little") for i in range(lanes))
        take = min(output_bytes - len(out), rate_bytes)
        out.extend(block[:take])
        if len(out) < output_bytes:
            state = list(keccak_f1600(state))
    return bytes(out)


def sha3_256(message: bytes) -> bytes:
    return _sha3_sponge(message, rate_bytes=136, output_bytes=32, suffix=0x06)


def sha3_512(message: bytes) -> bytes:
    return _sha3_sponge(message, rate_bytes=72, output_bytes=64, suffix=0x06)


def shake256(message: bytes, output_bytes: int) -> bytes:
    if output_bytes < 0:
        raise PNCSCryptoAlgebraError("SHAKE output length must be non-negative")
    return _sha3_sponge(message, rate_bytes=136, output_bytes=output_bytes, suffix=0x1F)


def hmac_sha3_512(key: bytes, message: bytes) -> bytes:
    block_size = 72
    if len(key) > block_size:
        key = sha3_512(key)
    key = key + bytes(block_size - len(key))
    ipad = bytes((x ^ 0x36) for x in key)
    opad = bytes((x ^ 0x5C) for x in key)
    return sha3_512(opad + sha3_512(ipad + message))


def hkdf_extract_sha3_512(salt: bytes | None, ikm: bytes) -> bytes:
    actual_salt = bytes(64) if salt is None or len(salt) == 0 else salt
    return hmac_sha3_512(actual_salt, ikm)


def hkdf_expand_sha3_512(prk: bytes, info: bytes, length: int) -> bytes:
    hash_len = 64
    if length < 0 or length > 255 * hash_len:
        raise PNCSCryptoAlgebraError("HKDF output length outside RFC 5869 bound")
    n = (length + hash_len - 1) // hash_len
    t = b""
    okm = bytearray()
    for i in range(1, n + 1):
        t = hmac_sha3_512(prk, t + info + bytes((i,)))
        okm.extend(t)
    return bytes(okm[:length])


def hkdf_sha3_512(ikm: bytes, salt: bytes | None, info: bytes, length: int = 32) -> bytes:
    return hkdf_expand_sha3_512(hkdf_extract_sha3_512(salt, ikm), info, length)


@dataclass(frozen=True)
class CryptoAlgebraSelfTest:
    quarter_round: bool
    chacha20_block: bool
    poly1305: bool
    aead: bool
    sha3_512: bool
    hkdf_sha3_512: bool

    @property
    def passed(self) -> bool:
        return all((self.quarter_round, self.chacha20_block, self.poly1305, self.aead, self.sha3_512, self.hkdf_sha3_512))

BLAKE2B_IV = (
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
)

BLAKE2B_SIGMA = (
    (0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15),
    (14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3),
    (11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4),
    (7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8),
    (9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13),
    (2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9),
    (12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11),
    (13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10),
    (6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5),
    (10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0),
    (0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15),
    (14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3),
)


def rotr64(x: int, n: int) -> int:
    n %= 64
    x &= MASK64
    return ((x >> n) | (x << (64 - n))) & MASK64 if n else x


def _blake2b_g(v: list[int], a: int, b: int, c: int, d: int, x: int, y: int) -> None:
    v[a] = (v[a] + v[b] + x) & MASK64
    v[d] = rotr64(v[d] ^ v[a], 32)
    v[c] = (v[c] + v[d]) & MASK64
    v[b] = rotr64(v[b] ^ v[c], 24)
    v[a] = (v[a] + v[b] + y) & MASK64
    v[d] = rotr64(v[d] ^ v[a], 16)
    v[c] = (v[c] + v[d]) & MASK64
    v[b] = rotr64(v[b] ^ v[c], 63)


def _blake2b_compress(h: list[int], block: bytes, t: int, last: bool) -> list[int]:
    if len(block) != 128:
        raise PNCSCryptoAlgebraError("BLAKE2b compression block must be 128 bytes")
    m = [int.from_bytes(block[i:i+8], "little") for i in range(0, 128, 8)]
    v = list(h) + list(BLAKE2B_IV)
    v[12] ^= t & MASK64
    v[13] ^= (t >> 64) & MASK64
    if last:
        v[14] ^= MASK64
    for r in range(12):
        s = BLAKE2B_SIGMA[r]
        _blake2b_g(v, 0,4,8,12, m[s[0]], m[s[1]])
        _blake2b_g(v, 1,5,9,13, m[s[2]], m[s[3]])
        _blake2b_g(v, 2,6,10,14, m[s[4]], m[s[5]])
        _blake2b_g(v, 3,7,11,15, m[s[6]], m[s[7]])
        _blake2b_g(v, 0,5,10,15, m[s[8]], m[s[9]])
        _blake2b_g(v, 1,6,11,12, m[s[10]], m[s[11]])
        _blake2b_g(v, 2,7,8,13, m[s[12]], m[s[13]])
        _blake2b_g(v, 3,4,9,14, m[s[14]], m[s[15]])
    return [(h[i] ^ v[i] ^ v[i+8]) & MASK64 for i in range(8)]


def blake2b(message: bytes, digest_size: int = 64) -> bytes:
    if not 1 <= digest_size <= 64:
        raise PNCSCryptoAlgebraError("BLAKE2b digest size must be 1..64 bytes")
    h = list(BLAKE2B_IV)
    h[0] ^= 0x01010000 ^ digest_size
    if len(message) == 0:
        h = _blake2b_compress(h, bytes(128), 0, True)
    else:
        full_blocks = (len(message) + 127) // 128
        for idx in range(full_blocks):
            start = idx * 128
            chunk = message[start:start+128]
            last = idx == full_blocks - 1
            t = min((idx + 1) * 128, len(message))
            block = chunk + bytes(128 - len(chunk))
            h = _blake2b_compress(h, block, t, last)
    return b"".join(x.to_bytes(8, "little") for x in h)[:digest_size]


def blake2b256(message: bytes) -> bytes:
    return blake2b(message, 32)
