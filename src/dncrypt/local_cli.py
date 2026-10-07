from __future__ import annotations

import argparse
from dataclasses import asdict
import getpass
import json
import os
from pathlib import Path
import sys

from .local_container import (
    DEFAULT_CHUNK_SIZE,
    decrypt_path,
    default_encrypted_path,
    encrypt_path,
    verify_container,
)
from .local_keystore import (
    DPAPI_BACKEND,
    DPAPI_PASSPHRASE_BACKEND,
    PASSPHRASE_BACKEND,
    create_profile,
    profile_status,
    unlocked_master_key,
)

CLI_SCHEMA = "dncrypt.local-cli/v1"


def _json(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def _profile_passphrase(profile: str, *, confirm: bool = False) -> str:
    first = getpass.getpass(f"DNCrypt passphrase for profile '{profile}': ")
    if confirm:
        second = getpass.getpass("Confirm DNCrypt passphrase: ")
        if first != second:
            raise ValueError("passphrases do not match")
    return first


def _status_dict(status) -> dict[str, object]:
    return {
        "schema": CLI_SCHEMA,
        "status": "READY",
        "profile": status.profile,
        "backend": status.backend,
        "key_commitment": status.key_commitment,
        "profile_path": status.path,
        "created_unix_ns": status.created_unix_ns,
        "runtime_network_dependency": False,
        "frozen_aead_protocol": "dncrypt.frozen-protocol/v0.2",
        "ai_required_for_decrypt": False,
    }


def _load_passphrase_if_needed(profile: str, home: str | None) -> str | None:
    status = profile_status(profile, home=home)
    if status.backend in {PASSPHRASE_BACKEND, DPAPI_PASSPHRASE_BACKEND}:
        return _profile_passphrase(profile)
    return None


def _default_decrypt_destination(source: Path) -> Path | None:
    # The actual original basename is encrypted. Returning None makes
    # decrypt_path choose the authenticated metadata name after opening.
    return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dncrypt-local",
        description=(
            "Local-first DNCrypt workstation encryption. Runtime encrypt/decrypt "
            "does not require a network service or AI."
        ),
    )
    parser.add_argument(
        "--home",
        default=None,
        help="Override DNCrypt local profile home (default: DNCRYPT_HOME / OS config dir).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="Create a local DNCrypt key profile.")
    init.add_argument("--profile", default="default")
    init.add_argument(
        "--backend",
        choices=("auto", "dpapi", "dpapi-passphrase", "passphrase"),
        default="auto",
        help="auto uses Windows DPAPI + passphrase on Windows, passphrase elsewhere.",
    )
    init.add_argument(
        "--replace-profile",
        action="store_true",
        help="Replace an existing key profile. This makes old ciphertext unreadable unless the old key is backed up.",
    )

    status = sub.add_parser("status", help="Show local profile status without unlocking the key.")
    status.add_argument("--profile", default="default")

    enc = sub.add_parser("encrypt", help="Encrypt a file or directory into one .dncrypt container.")
    enc.add_argument("source")
    enc.add_argument("-o", "--output", default=None)
    enc.add_argument("--profile", default="default")
    enc.add_argument(
        "--chunk-size-mib",
        type=int,
        default=DEFAULT_CHUNK_SIZE // (1024 * 1024),
        help="Streaming chunk size in MiB (default: 4).",
    )
    enc.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing encrypted destination file.",
    )

    dec = sub.add_parser("decrypt", help="Decrypt a .dncrypt container locally.")
    dec.add_argument("source")
    dec.add_argument("-o", "--output", default=None)
    dec.add_argument("--profile", default="default")
    dec.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing regular-file destination. Directories are never replaced.",
    )

    verify = sub.add_parser("verify", help="Authenticate and verify a container without writing plaintext.")
    verify.add_argument("source")
    verify.add_argument("--profile", default="default")

    doctor = sub.add_parser("doctor", help="Check local-only deployment invariants.")
    doctor.add_argument("--profile", default="default")

    return parser


def _run(args: argparse.Namespace) -> int:
    home = args.home
    if args.command == "init":
        passphrase = None
        selected = args.backend
        if selected in {"passphrase", "dpapi-passphrase"} or selected == "auto":
            passphrase = _profile_passphrase(args.profile, confirm=True)
        status = create_profile(
            args.profile,
            backend=selected,
            passphrase=passphrase,
            home=home,
            overwrite=args.replace_profile,
        )
        _json(_status_dict(status))
        return 0

    if args.command == "status":
        _json(_status_dict(profile_status(args.profile, home=home)))
        return 0

    if args.command == "doctor":
        status = profile_status(args.profile, home=home)
        data = _status_dict(status)
        data.update(
            {
                "doctor": "PASS",
                "profile_file_exists": Path(status.path).is_file(),
                "dpapi_current_user": status.backend == DPAPI_BACKEND,
                "dpapi_plus_passphrase": status.backend == DPAPI_PASSPHRASE_BACKEND,
                "portable_passphrase_profile": status.backend == PASSPHRASE_BACKEND,
                "network_module_required": False,
                "plaintext_auto_delete": False,
                "secure_erase_claim": False,
            }
        )
        _json(data)
        return 0

    passphrase = _load_passphrase_if_needed(args.profile, home)
    with unlocked_master_key(
        args.profile,
        passphrase=passphrase,
        home=home,
    ) as key:
        if args.command == "encrypt":
            src = Path(args.source)
            dst = Path(args.output) if args.output else default_encrypted_path(src)
            chunk_size = args.chunk_size_mib * 1024 * 1024
            result = encrypt_path(
                src,
                dst,
                key,
                chunk_size=chunk_size,
                force=args.force,
            )
            _json({"schema": CLI_SCHEMA, "status": "ENCRYPTED", **asdict(result)})
            return 0

        if args.command == "decrypt":
            src = Path(args.source)
            dst = Path(args.output) if args.output else _default_decrypt_destination(src)
            result = decrypt_path(
                src,
                key,
                destination=dst,
                force=args.force,
            )
            _json({"schema": CLI_SCHEMA, "status": "DECRYPTED", **asdict(result)})
            return 0

        if args.command == "verify":
            result = verify_container(args.source, key)
            _json({"schema": CLI_SCHEMA, "status": "VERIFIED", **asdict(result)})
            return 0

    raise AssertionError("unreachable command")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        return _run(parser.parse_args(argv))
    except KeyboardInterrupt:
        print("DNCrypt operation cancelled.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"DNCrypt local error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())