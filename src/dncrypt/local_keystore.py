from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
import time
from typing import Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .crypto import generate_master_key
from .util import blake2b256, canonical_json_bytes

PROFILE_SCHEMA = "dncrypt.local-key-profile/v1"
DPAPI_BACKEND = "windows-dpapi-current-user"
DPAPI_PASSPHRASE_BACKEND = "windows-dpapi-passphrase"
PASSPHRASE_BACKEND = "scrypt-chacha20poly1305"
DEFAULT_SCRYPT_N = 1 << 17
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1
_PROFILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


@dataclass(frozen=True, slots=True)
class LocalKeyProfileStatus:
    profile: str
    backend: str
    key_commitment: str
    path: str
    created_unix_ns: int
    schema: str = PROFILE_SCHEMA


def default_dncrypt_home() -> Path:
    override = os.environ.get("DNCRYPT_HOME")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / "DNCrypt"
        return Path.home() / "AppData" / "Local" / "DNCrypt"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    return (Path(xdg) if xdg else Path.home() / ".config") / "dncrypt"


def _validate_profile_name(name: str) -> str:
    value = str(name).strip()
    if not _PROFILE_RE.fullmatch(value):
        raise ValueError("profile name must match [A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
    return value


def profile_path(profile: str = "default", *, home: str | Path | None = None) -> Path:
    name = _validate_profile_name(profile)
    root = default_dncrypt_home() if home is None else Path(home).expanduser()
    return root / "profiles" / f"{name}.json"


def _atomic_private_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError):
            pass
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _profile_aad(profile: str) -> bytes:
    return canonical_json_bytes(
        {
            "schema": PROFILE_SCHEMA,
            "profile": _validate_profile_name(profile),
            "domain": "DNCrypt/local-key-wrap/v1",
        }
    )


def _derive_passphrase_key(
    passphrase: str,
    *,
    salt: bytes,
    n: int,
    r: int,
    p: int,
) -> bytes:
    if not isinstance(passphrase, str) or len(passphrase) < 12:
        raise ValueError("passphrase must contain at least 12 characters")
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(
        passphrase.encode("utf-8")
    )


def _dpapi_protect(raw: bytes, *, entropy: bytes) -> bytes:
    if os.name != "nt":
        raise RuntimeError("Windows DPAPI is available only on Windows")
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    def blob(data: bytes):
        buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))), buf

    in_blob, in_buf = blob(raw)
    entropy_blob, entropy_buf = blob(entropy)
    out_blob = DATA_BLOB()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        wintypes.LPCWSTR,
        ctypes.POINTER(DATA_BLOB),
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    if not crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "DNCrypt local profile",
        ctypes.byref(entropy_blob),
        None,
        None,
        0x1,  # CRYPTPROTECT_UI_FORBIDDEN
        ctypes.byref(out_blob),
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        if out_blob.pbData:
            kernel32.LocalFree(out_blob.pbData)
        _ = (in_buf, entropy_buf)


def _dpapi_unprotect(raw: bytes, *, entropy: bytes) -> bytearray:
    if os.name != "nt":
        raise RuntimeError("Windows DPAPI is available only on Windows")
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    def blob(data: bytes):
        buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))), buf

    in_blob, in_buf = blob(raw)
    entropy_blob, entropy_buf = blob(entropy)
    out_blob = DATA_BLOB()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(DATA_BLOB),
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    if not crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        ctypes.byref(entropy_blob),
        None,
        None,
        0x1,
        ctypes.byref(out_blob),
    ):
        raise ctypes.WinError()
    try:
        key = bytearray(ctypes.string_at(out_blob.pbData, out_blob.cbData))
        if out_blob.pbData and out_blob.cbData:
            ctypes.memset(out_blob.pbData, 0, out_blob.cbData)
        return key
    finally:
        if out_blob.pbData:
            kernel32.LocalFree(out_blob.pbData)
        _ = (in_buf, entropy_buf)


def create_profile(
    profile: str = "default",
    *,
    backend: str = "auto",
    passphrase: str | None = None,
    home: str | Path | None = None,
    overwrite: bool = False,
) -> LocalKeyProfileStatus:
    name = _validate_profile_name(profile)
    path = profile_path(name, home=home)
    if path.exists() and not overwrite:
        raise FileExistsError(f"DNCrypt key profile already exists: {path}")
    selected = backend.strip().lower()
    if selected == "auto":
        selected = "dpapi-passphrase" if os.name == "nt" else "passphrase"
    master = bytearray(generate_master_key())
    try:
        core: dict[str, object] = {
            "schema": PROFILE_SCHEMA,
            "profile": name,
            "created_unix_ns": time.time_ns(),
            "key_commitment": blake2b256(bytes(master)),
        }
        if selected in {"dpapi", DPAPI_BACKEND}:
            entropy = hashlib.sha256(_profile_aad(name)).digest()
            protected = _dpapi_protect(bytes(master), entropy=entropy)
            core.update(
                {
                    "backend": DPAPI_BACKEND,
                    "protected_key_b64": base64.urlsafe_b64encode(protected).decode("ascii"),
                }
            )
        elif selected in {"dpapi-passphrase", DPAPI_PASSPHRASE_BACKEND}:
            if os.name != "nt":
                raise RuntimeError("DPAPI + passphrase backend is available only on Windows")
            if passphrase is None:
                raise ValueError("passphrase is required for DPAPI + passphrase backend")
            salt = secrets.token_bytes(32)
            entropy_key = bytearray(
                _derive_passphrase_key(
                    passphrase,
                    salt=salt,
                    n=DEFAULT_SCRYPT_N,
                    r=DEFAULT_SCRYPT_R,
                    p=DEFAULT_SCRYPT_P,
                )
            )
            try:
                protected = _dpapi_protect(bytes(master), entropy=bytes(entropy_key))
            finally:
                for i in range(len(entropy_key)):
                    entropy_key[i] = 0
            core.update(
                {
                    "backend": DPAPI_PASSPHRASE_BACKEND,
                    "protected_key_b64": base64.urlsafe_b64encode(protected).decode("ascii"),
                    "scrypt": {
                        "n": DEFAULT_SCRYPT_N,
                        "r": DEFAULT_SCRYPT_R,
                        "p": DEFAULT_SCRYPT_P,
                        "salt_b64": base64.urlsafe_b64encode(salt).decode("ascii"),
                    },
                }
            )
        elif selected in {"passphrase", PASSPHRASE_BACKEND}:
            if passphrase is None:
                raise ValueError("passphrase is required for passphrase backend")
            salt = secrets.token_bytes(32)
            nonce = secrets.token_bytes(12)
            wrap_key = bytearray(
                _derive_passphrase_key(
                    passphrase,
                    salt=salt,
                    n=DEFAULT_SCRYPT_N,
                    r=DEFAULT_SCRYPT_R,
                    p=DEFAULT_SCRYPT_P,
                )
            )
            try:
                wrapped = ChaCha20Poly1305(bytes(wrap_key)).encrypt(
                    nonce,
                    bytes(master),
                    _profile_aad(name),
                )
            finally:
                for i in range(len(wrap_key)):
                    wrap_key[i] = 0
            core.update(
                {
                    "backend": PASSPHRASE_BACKEND,
                    "scrypt": {
                        "n": DEFAULT_SCRYPT_N,
                        "r": DEFAULT_SCRYPT_R,
                        "p": DEFAULT_SCRYPT_P,
                        "salt_b64": base64.urlsafe_b64encode(salt).decode("ascii"),
                    },
                    "nonce_b64": base64.urlsafe_b64encode(nonce).decode("ascii"),
                    "wrapped_key_b64": base64.urlsafe_b64encode(wrapped).decode("ascii"),
                }
            )
        else:
            raise ValueError("backend must be auto, dpapi, dpapi-passphrase, or passphrase")
        _atomic_private_write(
            path,
            json.dumps(core, sort_keys=True, indent=2).encode("utf-8") + b"\n",
        )
        return profile_status(name, home=home)
    finally:
        for i in range(len(master)):
            master[i] = 0


def _load_profile(profile: str, *, home: str | Path | None = None) -> tuple[Path, dict[str, object]]:
    path = profile_path(profile, home=home)
    try:
        value = json.loads(path.read_text("utf-8"))
    except FileNotFoundError:
        raise FileNotFoundError(f"DNCrypt key profile not found: {path}") from None
    if not isinstance(value, dict) or value.get("schema") != PROFILE_SCHEMA:
        raise ValueError("unsupported DNCrypt local key profile")
    if value.get("profile") != _validate_profile_name(profile):
        raise ValueError("key profile name mismatch")
    return path, value


def profile_status(profile: str = "default", *, home: str | Path | None = None) -> LocalKeyProfileStatus:
    path, value = _load_profile(profile, home=home)
    commitment = value.get("key_commitment")
    if not isinstance(commitment, str) or len(commitment) != 64:
        raise ValueError("key profile commitment is invalid")
    return LocalKeyProfileStatus(
        profile=str(value["profile"]),
        backend=str(value["backend"]),
        key_commitment=commitment,
        path=str(path),
        created_unix_ns=int(value["created_unix_ns"]),
    )


def _unlock(profile: str, *, passphrase: str | None, home: str | Path | None) -> bytearray:
    _, value = _load_profile(profile, home=home)
    backend = value.get("backend")
    if backend == DPAPI_BACKEND:
        protected = base64.urlsafe_b64decode(str(value["protected_key_b64"]).encode("ascii"))
        if not (32 <= len(protected) <= 4096):
            raise ValueError("DNCrypt DPAPI profile blob length is invalid")
        entropy = hashlib.sha256(_profile_aad(profile)).digest()
        key = _dpapi_unprotect(protected, entropy=entropy)
    elif backend == DPAPI_PASSPHRASE_BACKEND:
        if passphrase is None:
            raise ValueError("passphrase is required for this DNCrypt profile")
        params = value.get("scrypt")
        if not isinstance(params, dict) or set(params) != {"n", "r", "p", "salt_b64"}:
            raise ValueError("DNCrypt DPAPI-passphrase profile is malformed")
        n, r, p = int(params["n"]), int(params["r"]), int(params["p"])
        if (n, r, p) != (DEFAULT_SCRYPT_N, DEFAULT_SCRYPT_R, DEFAULT_SCRYPT_P):
            raise ValueError("DNCrypt scrypt parameters are outside the v1 profile contract")
        salt = base64.urlsafe_b64decode(str(params["salt_b64"]).encode("ascii"))
        protected = base64.urlsafe_b64decode(str(value["protected_key_b64"]).encode("ascii"))
        if len(salt) != 32 or not (32 <= len(protected) <= 4096):
            raise ValueError("DNCrypt DPAPI-passphrase profile encoding is invalid")
        entropy_key = bytearray(
            _derive_passphrase_key(passphrase, salt=salt, n=n, r=r, p=p)
        )
        try:
            key = _dpapi_unprotect(protected, entropy=bytes(entropy_key))
        finally:
            for i in range(len(entropy_key)):
                entropy_key[i] = 0
    elif backend == PASSPHRASE_BACKEND:
        if passphrase is None:
            raise ValueError("passphrase is required for this DNCrypt profile")
        params = value.get("scrypt")
        if not isinstance(params, dict) or set(params) != {"n", "r", "p", "salt_b64"}:
            raise ValueError("DNCrypt scrypt profile is malformed")
        n, r, p = int(params["n"]), int(params["r"]), int(params["p"])
        if (n, r, p) != (DEFAULT_SCRYPT_N, DEFAULT_SCRYPT_R, DEFAULT_SCRYPT_P):
            raise ValueError("DNCrypt scrypt parameters are outside the v1 profile contract")
        salt = base64.urlsafe_b64decode(str(params["salt_b64"]).encode("ascii"))
        nonce = base64.urlsafe_b64decode(str(value["nonce_b64"]).encode("ascii"))
        wrapped = base64.urlsafe_b64decode(str(value["wrapped_key_b64"]).encode("ascii"))
        if len(salt) != 32 or len(nonce) != 12 or len(wrapped) != 48:
            raise ValueError("DNCrypt passphrase profile encoding is invalid")
        wrap_key = bytearray(
            _derive_passphrase_key(
                passphrase,
                salt=salt,
                n=n,
                r=r,
                p=p,
            )
        )
        try:
            try:
                clear = ChaCha20Poly1305(bytes(wrap_key)).decrypt(
                    nonce,
                    wrapped,
                    _profile_aad(profile),
                )
            except InvalidTag as exc:
                raise ValueError("invalid passphrase or tampered DNCrypt key profile") from exc
            key = bytearray(clear)
        finally:
            for i in range(len(wrap_key)):
                wrap_key[i] = 0
    else:
        raise ValueError("unsupported DNCrypt local key backend")
    if len(key) != 32:
        for i in range(len(key)):
            key[i] = 0
        raise ValueError("DNCrypt profile did not unlock a 256-bit master key")
    expected = value.get("key_commitment")
    if blake2b256(bytes(key)) != expected:
        for i in range(len(key)):
            key[i] = 0
        raise ValueError("DNCrypt key commitment mismatch")
    return key


@contextmanager
def unlocked_master_key(
    profile: str = "default",
    *,
    passphrase: str | None = None,
    home: str | Path | None = None,
) -> Iterator[bytearray]:
    key = _unlock(profile, passphrase=passphrase, home=home)
    try:
        yield key
    finally:
        for i in range(len(key)):
            key[i] = 0


__all__ = [
    "DPAPI_BACKEND",
    "DPAPI_PASSPHRASE_BACKEND",
    "PASSPHRASE_BACKEND",
    "LocalKeyProfileStatus",
    "create_profile",
    "default_dncrypt_home",
    "profile_path",
    "profile_status",
    "unlocked_master_key",
]