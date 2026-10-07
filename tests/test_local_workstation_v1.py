from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from dncrypt.local_container import (
    DEFAULT_CHUNK_SIZE,
    decrypt_path,
    encrypt_path,
    verify_container,
)
from dncrypt.local_keystore import (
    PASSPHRASE_BACKEND,
    create_profile,
    profile_status,
    unlocked_master_key,
)


def test_passphrase_profile_roundtrip(tmp_path: Path):
    status = create_profile(
        "default",
        backend="passphrase",
        passphrase="correct horse battery staple",
        home=tmp_path / "home",
    )
    assert status.backend == PASSPHRASE_BACKEND
    assert len(status.key_commitment) == 64
    with unlocked_master_key(
        "default",
        passphrase="correct horse battery staple",
        home=tmp_path / "home",
    ) as key:
        assert len(key) == 32
        first = bytes(key)
    assert set(key) <= {0}
    with unlocked_master_key(
        "default",
        passphrase="correct horse battery staple",
        home=tmp_path / "home",
    ) as key2:
        assert bytes(key2) == first

    with pytest.raises(ValueError):
        with unlocked_master_key(
            "default",
            passphrase="totally wrong passphrase",
            home=tmp_path / "home",
        ):
            pass


def test_file_roundtrip_streaming_and_verify(tmp_path: Path):
    key = bytearray(os.urandom(32))
    source = tmp_path / "notes.txt"
    payload = (b"DNCrypt local layer\n" * 10000) + os.urandom(200000)
    source.write_bytes(payload)
    encrypted = tmp_path / "notes.txt.dncrypt"
    result = encrypt_path(
        source,
        encrypted,
        key,
        chunk_size=64 * 1024,
    )
    assert result.payload_kind == "file"
    assert encrypted.is_file()
    source.unlink()

    verified = verify_container(encrypted, key)
    assert verified.payload_kind == "file"
    assert verified.plaintext_stream_bytes == len(payload)

    restored = decrypt_path(encrypted, key)
    assert Path(restored.destination).read_bytes() == payload
    assert restored.container_id == result.container_id


def test_wrong_key_and_tamper_fail_closed_without_plaintext_commit(tmp_path: Path):
    key = bytearray(os.urandom(32))
    source = tmp_path / "secret.bin"
    source.write_bytes(os.urandom(180000))
    encrypted = tmp_path / "secret.bin.dncrypt"
    encrypt_path(source, encrypted, key, chunk_size=64 * 1024)
    source.unlink()

    with pytest.raises(ValueError):
        decrypt_path(
            encrypted,
            bytearray(os.urandom(32)),
            destination=tmp_path / "wrong.bin",
        )
    assert not (tmp_path / "wrong.bin").exists()

    raw = bytearray(encrypted.read_bytes())
    raw[-100] ^= 1
    tampered = tmp_path / "tampered.dncrypt"
    tampered.write_bytes(raw)
    with pytest.raises(ValueError):
        decrypt_path(
            tampered,
            key,
            destination=tmp_path / "tampered.out",
        )
    assert not (tmp_path / "tampered.out").exists()


def test_truncation_fails_closed(tmp_path: Path):
    key = bytearray(os.urandom(32))
    source = tmp_path / "x.bin"
    source.write_bytes(os.urandom(150000))
    encrypted = tmp_path / "x.dncrypt"
    encrypt_path(source, encrypted, key, chunk_size=64 * 1024)
    source.unlink()
    truncated = tmp_path / "truncated.dncrypt"
    truncated.write_bytes(encrypted.read_bytes()[:-25])
    with pytest.raises(ValueError):
        decrypt_path(truncated, key, destination=tmp_path / "x.out")
    assert not (tmp_path / "x.out").exists()


def test_no_overwrite_by_default(tmp_path: Path):
    key = bytearray(os.urandom(32))
    source = tmp_path / "a.txt"
    source.write_text("alpha")
    dest = tmp_path / "a.txt.dncrypt"
    dest.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        encrypt_path(source, dest, key)


def test_directory_roundtrip(tmp_path: Path):
    key = bytearray(os.urandom(32))
    source = tmp_path / "project"
    source.mkdir()
    (source / "a.txt").write_text("alpha", encoding="utf-8")
    nested = source / "nested"
    nested.mkdir()
    (nested / "b.bin").write_bytes(os.urandom(120000))
    expected_a = (source / "a.txt").read_bytes()
    expected_b = (nested / "b.bin").read_bytes()

    encrypted = tmp_path / "project.dncrypt"
    result = encrypt_path(source, encrypted, key, chunk_size=64 * 1024)
    assert result.payload_kind == "directory"
    import shutil
    shutil.rmtree(source)

    verified = verify_container(encrypted, key)
    assert verified.payload_kind == "directory"

    restored = decrypt_path(encrypted, key)
    target = Path(restored.destination)
    assert (target / "a.txt").read_bytes() == expected_a
    assert (target / "nested" / "b.bin").read_bytes() == expected_b


def test_directory_symlink_rejected_when_supported(tmp_path: Path):
    source = tmp_path / "d"
    source.mkdir()
    target = source / "target.txt"
    target.write_text("x")
    link = source / "link.txt"
    try:
        link.symlink_to(target.name)
    except (OSError, NotImplementedError):
        pytest.skip("symlink unavailable")
    with pytest.raises(ValueError, match="symlink"):
        encrypt_path(source, tmp_path / "d.dncrypt", bytearray(os.urandom(32)))


def test_profile_status_never_contains_clear_key(tmp_path: Path):
    home = tmp_path / "home"
    create_profile(
        "private",
        backend="passphrase",
        passphrase="this is a strong local passphrase",
        home=home,
    )
    status = profile_status("private", home=home)
    raw = Path(status.path).read_text("utf-8")
    value = json.loads(raw)
    assert "master_key" not in raw
    assert "wrapped_key_b64" in value
    assert status.key_commitment == value["key_commitment"]


def test_filename_and_plaintext_not_exposed_in_public_container_bytes(tmp_path: Path):
    key = bytearray(os.urandom(32))
    source = tmp_path / "highly-sensitive-name.txt"
    marker = b"TOP-SECRET-MARKER-DO-NOT-LEAK"
    source.write_bytes(marker * 100)
    encrypted = tmp_path / "opaque.dncrypt"
    encrypt_path(source, encrypted, key, chunk_size=64 * 1024)
    raw = encrypted.read_bytes()
    assert b"highly-sensitive-name.txt" not in raw
    assert marker not in raw


def test_header_tamper_fails_before_plaintext_commit(tmp_path: Path):
    key = bytearray(os.urandom(32))
    source = tmp_path / "header.txt"
    source.write_text("header-binding")
    encrypted = tmp_path / "header.dncrypt"
    encrypt_path(source, encrypted, key, chunk_size=64 * 1024)
    raw = bytearray(encrypted.read_bytes())
    # Header begins after 9-byte prefix. Flip a byte inside canonical JSON while
    # keeping it parseable by changing one hex nibble in the container id.
    start = 9
    pos = raw.find(b'"container_id":"', start)
    assert pos > 0
    nibble = pos + len(b'"container_id":"')
    raw[nibble] = ord("a") if raw[nibble] != ord("a") else ord("b")
    tampered = tmp_path / "header-tampered.dncrypt"
    tampered.write_bytes(raw)
    with pytest.raises(ValueError):
        decrypt_path(tampered, key, destination=tmp_path / "header.out")
    assert not (tmp_path / "header.out").exists()


def test_tampered_scrypt_cost_is_rejected_before_derivation(tmp_path: Path):
    home = tmp_path / "home"
    create_profile(
        "bounded",
        backend="passphrase",
        passphrase="correct horse battery staple",
        home=home,
    )
    status = profile_status("bounded", home=home)
    path = Path(status.path)
    value = json.loads(path.read_text("utf-8"))
    value["scrypt"]["n"] = 1 << 30
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="outside the v1 profile contract"):
        with unlocked_master_key(
            "bounded",
            passphrase="correct horse battery staple",
            home=home,
        ):
            pass


def test_local_runtime_modules_have_no_network_or_ai_client_imports():
    package = Path(__file__).resolve().parents[1] / "src" / "dncrypt"
    forbidden = ("import socket", "import urllib", "import requests", "import httpx", "import openai")
    for name in ("local_keystore.py", "local_container.py", "local_cli.py"):
        source = (package / name).read_text("utf-8").lower()
        for marker in forbidden:
            assert marker not in source


def test_cli_passphrase_profile_encrypt_decrypt(tmp_path: Path, monkeypatch, capsys):
    from dncrypt import local_cli

    monkeypatch.setattr(
        local_cli.getpass,
        "getpass",
        lambda prompt="": "correct horse battery staple",
    )
    home = tmp_path / "cli-home"
    assert local_cli.main([
        "--home", str(home),
        "init", "--profile", "cli", "--backend", "passphrase",
    ]) == 0
    source = tmp_path / "cli.txt"
    source.write_text("local CLI works", encoding="utf-8")
    encrypted = tmp_path / "cli.txt.dncrypt"
    assert local_cli.main([
        "--home", str(home),
        "encrypt", str(source), "-o", str(encrypted), "--profile", "cli",
        "--chunk-size-mib", "1",
    ]) == 0
    source.unlink()
    assert local_cli.main([
        "--home", str(home),
        "verify", str(encrypted), "--profile", "cli",
    ]) == 0
    assert local_cli.main([
        "--home", str(home),
        "decrypt", str(encrypted), "--profile", "cli",
    ]) == 0
    assert source.read_text("utf-8") == "local CLI works"
    captured = capsys.readouterr()
    assert "ENCRYPTED" in captured.out
    assert "VERIFIED" in captured.out
    assert "DECRYPTED" in captured.out