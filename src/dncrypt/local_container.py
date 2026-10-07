from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import shutil
import struct
import tarfile
import tempfile
from typing import BinaryIO

from .binary_envelope import pack_envelope, unpack_envelope
from .crypto import PROTOCOL_ID, decrypt, encrypt
from .genome import CipherGenome, initial_genome
from .surface import CipherSurface, initial_surface
from .util import b64d, blake2b256, canonical_json_bytes

LOCAL_CONTAINER_SCHEMA = "dncrypt.local-container/v1"
LOCAL_METADATA_SCHEMA = "dncrypt.local-metadata/v1"
LOCAL_RECORD_AAD_SCHEMA = "dncrypt.local-record-aad/v1"
LOCAL_FINAL_SCHEMA = "dncrypt.local-final/v1"
LOCAL_MAGIC = b"DNCL"
LOCAL_VERSION = 1
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024
MIN_CHUNK_SIZE = 64 * 1024
MAX_CHUNK_SIZE = 16 * 1024 * 1024
MAX_HEADER_BYTES = 1024 * 1024
_MAX_RECORD_SLACK = 1024 * 1024
_HEADER_PREFIX = struct.Struct(">4sBI")
_RECORD_PREFIX = struct.Struct(">I")
_ALLOWED_PAYLOAD_KINDS = frozenset({"file", "directory"})


@dataclass(frozen=True, slots=True)
class LocalContainerHeader:
    container_id: str
    payload_kind: str
    chunk_size: int
    genome: dict[str, object]
    surface: dict[str, object]
    header_commitment: str
    schema: str = LOCAL_CONTAINER_SCHEMA
    protocol_id: str = PROTOCOL_ID

    def __post_init__(self) -> None:
        if self.schema != LOCAL_CONTAINER_SCHEMA:
            raise ValueError("unsupported DNCrypt local container schema")
        if self.protocol_id != PROTOCOL_ID:
            raise ValueError("local container must use frozen DNCrypt v0.2 protocol")
        if self.payload_kind not in _ALLOWED_PAYLOAD_KINDS:
            raise ValueError("unsupported local payload kind")
        if not (MIN_CHUNK_SIZE <= self.chunk_size <= MAX_CHUNK_SIZE):
            raise ValueError("local container chunk_size outside admitted bounds")
        if len(self.container_id) != 32:
            raise ValueError("container_id must encode 16 random bytes")
        try:
            int(self.container_id, 16)
        except ValueError as exc:
            raise ValueError("container_id must be hexadecimal") from exc
        if len(self.header_commitment) != 64:
            raise ValueError("header_commitment must be a 32-byte digest")
        try:
            int(self.header_commitment, 16)
        except ValueError as exc:
            raise ValueError("header_commitment must be hexadecimal") from exc

    def core(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "protocol_id": self.protocol_id,
            "container_id": self.container_id,
            "payload_kind": self.payload_kind,
            "chunk_size": self.chunk_size,
            "genome": self.genome,
            "surface": self.surface,
        }

    def to_dict(self) -> dict[str, object]:
        return {**self.core(), "header_commitment": self.header_commitment}

    def verify_commitment(self) -> bool:
        return blake2b256(canonical_json_bytes(self.core())) == self.header_commitment


@dataclass(frozen=True, slots=True)
class LocalEncryptionResult:
    source: str
    destination: str
    payload_kind: str
    container_id: str
    plaintext_stream_bytes: int
    data_records: int
    final_receipt: str


@dataclass(frozen=True, slots=True)
class LocalDecryptionResult:
    source: str
    destination: str
    payload_kind: str
    container_id: str
    plaintext_stream_bytes: int
    data_records: int
    final_receipt: str


@dataclass(frozen=True, slots=True)
class LocalVerificationResult:
    source: str
    payload_kind: str
    container_id: str
    plaintext_stream_bytes: int
    data_records: int
    final_receipt: str


def _validate_chunk_size(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("chunk_size must be an integer")
    if not (MIN_CHUNK_SIZE <= value <= MAX_CHUNK_SIZE):
        raise ValueError(
            f"chunk_size must be in {MIN_CHUNK_SIZE}..{MAX_CHUNK_SIZE}"
        )
    return value


def _build_header(payload_kind: str, chunk_size: int) -> tuple[LocalContainerHeader, CipherGenome, CipherSurface]:
    if payload_kind not in _ALLOWED_PAYLOAD_KINDS:
        raise ValueError("payload_kind must be file or directory")
    size = _validate_chunk_size(chunk_size)
    genome = initial_genome(secrets.token_bytes(64))
    surface = initial_surface(genome)
    core = {
        "schema": LOCAL_CONTAINER_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "container_id": secrets.token_hex(16),
        "payload_kind": payload_kind,
        "chunk_size": size,
        "genome": asdict(genome),
        "surface": asdict(surface),
    }
    header = LocalContainerHeader(
        container_id=str(core["container_id"]),
        payload_kind=payload_kind,
        chunk_size=size,
        genome=dict(core["genome"]),
        surface=dict(core["surface"]),
        header_commitment=blake2b256(canonical_json_bytes(core)),
    )
    return header, genome, surface


def _write_header(handle: BinaryIO, header: LocalContainerHeader) -> None:
    raw = canonical_json_bytes(header.to_dict())
    if len(raw) > MAX_HEADER_BYTES:
        raise ValueError("local container header exceeds bound")
    handle.write(_HEADER_PREFIX.pack(LOCAL_MAGIC, LOCAL_VERSION, len(raw)))
    handle.write(raw)


def _header_to_state(value: dict[str, object]) -> tuple[LocalContainerHeader, CipherGenome, CipherSurface]:
    exact = {
        "schema",
        "protocol_id",
        "container_id",
        "payload_kind",
        "chunk_size",
        "genome",
        "surface",
        "header_commitment",
    }
    if set(value) != exact:
        raise ValueError("local container header exact-field mismatch")
    raw_genome = value.get("genome")
    raw_surface = value.get("surface")
    if not isinstance(raw_genome, dict) or not isinstance(raw_surface, dict):
        raise ValueError("local container state is malformed")
    g = dict(raw_genome)
    if set(g) != {
        "version", "generation", "parent_id", "operator_vector",
        "route", "phase_seed_hex", "mutation_nonce_hex",
    }:
        raise ValueError("local genome exact-field mismatch")
    g["operator_vector"] = tuple(g["operator_vector"])
    g["route"] = tuple(g["route"])
    s = dict(raw_surface)
    if set(s) != {"tick", "phi", "omega"}:
        raise ValueError("local surface exact-field mismatch")
    s["phi"] = tuple(s["phi"])
    s["omega"] = tuple(s["omega"])
    header = LocalContainerHeader(
        container_id=str(value["container_id"]),
        payload_kind=str(value["payload_kind"]),
        chunk_size=int(value["chunk_size"]),
        genome=dict(raw_genome),
        surface=dict(raw_surface),
        header_commitment=str(value["header_commitment"]),
        schema=str(value["schema"]),
        protocol_id=str(value["protocol_id"]),
    )
    if not header.verify_commitment():
        raise ValueError("local container header commitment mismatch")
    genome = CipherGenome(**g)
    surface = CipherSurface(**s)
    return header, genome, surface


def _read_header(handle: BinaryIO) -> tuple[LocalContainerHeader, CipherGenome, CipherSurface]:
    prefix = handle.read(_HEADER_PREFIX.size)
    if len(prefix) != _HEADER_PREFIX.size:
        raise ValueError("truncated DNCrypt local container header")
    magic, version, header_len = _HEADER_PREFIX.unpack(prefix)
    if magic != LOCAL_MAGIC:
        raise ValueError("invalid DNCrypt local container magic")
    if version != LOCAL_VERSION:
        raise ValueError("unsupported DNCrypt local container version")
    if not (1 <= header_len <= MAX_HEADER_BYTES):
        raise ValueError("invalid DNCrypt local container header length")
    raw = handle.read(header_len)
    if len(raw) != header_len:
        raise ValueError("truncated DNCrypt local container header body")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("DNCrypt local container header is malformed") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise ValueError("DNCrypt local container header is not canonical JSON")
    return _header_to_state(value)


def _aad_object(
    *,
    header: LocalContainerHeader,
    record_index: int,
    record_kind: str,
    plaintext_size: int,
) -> dict[str, object]:
    return {
        "schema": LOCAL_RECORD_AAD_SCHEMA,
        "container_id": header.container_id,
        "header_commitment": header.header_commitment,
        "record_index": record_index,
        "record_kind": record_kind,
        "plaintext_size": plaintext_size,
    }


def _authenticated_user_aad(envelope) -> dict[str, object]:
    try:
        outer = json.loads(b64d(envelope.aad_b64).decode("utf-8"))
        encoded = outer["user_aad"]
        if not isinstance(encoded, str):
            raise ValueError
        raw = b64d(encoded)
        value = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ValueError("local container authenticated user AAD is malformed") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise ValueError("local container user AAD is not canonical")
    return value


def _write_envelope_record(handle: BinaryIO, raw: bytes) -> None:
    if len(raw) > 0xFFFFFFFF:
        raise ValueError("DNCrypt local envelope record exceeds uint32 framing")
    handle.write(_RECORD_PREFIX.pack(len(raw)))
    handle.write(raw)


def _read_envelope_record(handle: BinaryIO, *, max_record_bytes: int) -> bytes:
    prefix = handle.read(_RECORD_PREFIX.size)
    if len(prefix) == 0:
        raise ValueError("DNCrypt local container ended before final record")
    if len(prefix) != _RECORD_PREFIX.size:
        raise ValueError("truncated DNCrypt local record prefix")
    (length,) = _RECORD_PREFIX.unpack(prefix)
    if length <= 0 or length > max_record_bytes:
        raise ValueError("DNCrypt local record length outside admitted bound")
    raw = handle.read(length)
    if len(raw) != length:
        raise ValueError("truncated DNCrypt local envelope record")
    return raw


class LocalContainerEncryptWriter:
    def __init__(
        self,
        handle: BinaryIO,
        master_key: bytes | bytearray,
        *,
        payload_kind: str,
        metadata: dict[str, object],
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> None:
        self._handle = handle
        self._master_key = master_key
        self.header, self._genome, self._surface = _build_header(
            payload_kind, chunk_size
        )
        _write_header(handle, self.header)
        self._parent_receipt: str | None = None
        self._record_index = 0
        self._data_records = 0
        self._buffer = bytearray()
        self._sha256 = hashlib.sha256()
        self._plaintext_bytes = 0
        self._finalized = False
        self._position = 0
        self._final_receipt: str | None = None
        meta = {"schema": LOCAL_METADATA_SCHEMA, **metadata}
        if meta.get("kind") != payload_kind:
            raise ValueError("encrypted metadata kind must match container payload_kind")
        self._emit("metadata", canonical_json_bytes(meta))

    @property
    def plaintext_bytes(self) -> int:
        return self._plaintext_bytes

    @property
    def data_records(self) -> int:
        return self._data_records

    @property
    def final_receipt(self) -> str:
        if self._final_receipt is None:
            raise RuntimeError("local container has not been finalized")
        return self._final_receipt

    def _emit(self, kind: str, plaintext: bytes) -> None:
        aad = canonical_json_bytes(
            _aad_object(
                header=self.header,
                record_index=self._record_index,
                record_kind=kind,
                plaintext_size=len(plaintext),
            )
        )
        envelope = encrypt(
            self._master_key,
            plaintext,
            self._genome,
            self._surface,
            user_aad=aad,
            parent_receipt=self._parent_receipt,
        )
        _write_envelope_record(self._handle, pack_envelope(envelope))
        self._parent_receipt = envelope.receipt_blake2b
        self._record_index += 1
        if kind == "data":
            self._data_records += 1

    def write(self, data: bytes | bytearray | memoryview) -> int:
        if self._finalized:
            raise ValueError("cannot write after DNCrypt local container finalization")
        raw = bytes(data)
        if not raw:
            return 0
        self._sha256.update(raw)
        self._plaintext_bytes += len(raw)
        self._position += len(raw)
        self._buffer.extend(raw)
        chunk = self.header.chunk_size
        while len(self._buffer) >= chunk:
            block = bytes(self._buffer[:chunk])
            del self._buffer[:chunk]
            self._emit("data", block)
        return len(raw)

    def tell(self) -> int:
        return self._position

    def flush(self) -> None:
        flush = getattr(self._handle, "flush", None)
        if flush:
            flush()

    def finalize(self) -> None:
        if self._finalized:
            return
        if self._buffer:
            block = bytes(self._buffer)
            self._buffer.clear()
            self._emit("data", block)
        final = canonical_json_bytes(
            {
                "schema": LOCAL_FINAL_SCHEMA,
                "payload_sha256": self._sha256.hexdigest(),
                "payload_bytes": self._plaintext_bytes,
                "data_records": self._data_records,
            }
        )
        self._emit("final", final)
        self._final_receipt = self._parent_receipt
        self._finalized = True
        self.flush()


class LocalContainerDecryptReader:
    def __init__(self, handle: BinaryIO, master_key: bytes | bytearray) -> None:
        self._handle = handle
        self._master_key = master_key
        self.header, self._genome, self._surface = _read_header(handle)
        self._max_record_bytes = self.header.chunk_size + _MAX_RECORD_SLACK
        self._parent_receipt: str | None = None
        self._record_index = 0
        self._data_records = 0
        self._plaintext_bytes = 0
        self._sha256 = hashlib.sha256()
        self._buffer = bytearray()
        self._final_seen = False
        self._final_receipt: str | None = None
        plaintext, kind = self._consume_record()
        if kind != "metadata":
            raise ValueError("DNCrypt local container first record must be metadata")
        try:
            metadata = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("DNCrypt local metadata is malformed") from exc
        if not isinstance(metadata, dict) or canonical_json_bytes(metadata) != plaintext:
            raise ValueError("DNCrypt local metadata is not canonical JSON")
        if metadata.get("schema") != LOCAL_METADATA_SCHEMA:
            raise ValueError("unsupported DNCrypt local metadata schema")
        if metadata.get("kind") != self.header.payload_kind:
            raise ValueError("DNCrypt local metadata kind mismatch")
        self.metadata: dict[str, object] = metadata

    @property
    def plaintext_bytes(self) -> int:
        return self._plaintext_bytes

    @property
    def data_records(self) -> int:
        return self._data_records

    @property
    def final_receipt(self) -> str:
        if self._final_receipt is None:
            raise RuntimeError("DNCrypt local container final record not verified")
        return self._final_receipt

    def _consume_record(self) -> tuple[bytes, str]:
        raw = _read_envelope_record(
            self._handle, max_record_bytes=self._max_record_bytes
        )
        envelope = unpack_envelope(raw)
        if envelope.parent_receipt != self._parent_receipt:
            raise ValueError("DNCrypt local record parent-receipt chain mismatch")
        plaintext = decrypt(
            self._master_key,
            envelope,
            self._genome,
            self._surface,
        )
        user_aad = _authenticated_user_aad(envelope)
        if set(user_aad) != {
            "schema", "container_id", "header_commitment",
            "record_index", "record_kind", "plaintext_size",
        }:
            raise ValueError("DNCrypt local record AAD exact-field mismatch")
        if user_aad.get("schema") != LOCAL_RECORD_AAD_SCHEMA:
            raise ValueError("DNCrypt local record AAD schema mismatch")
        if user_aad.get("container_id") != self.header.container_id:
            raise ValueError("DNCrypt local container id mismatch")
        if user_aad.get("header_commitment") != self.header.header_commitment:
            raise ValueError("DNCrypt local header/AAD commitment mismatch")
        if user_aad.get("record_index") != self._record_index:
            raise ValueError("DNCrypt local record index mismatch")
        if user_aad.get("plaintext_size") != len(plaintext):
            raise ValueError("DNCrypt local plaintext length binding mismatch")
        kind = user_aad.get("record_kind")
        if kind not in {"metadata", "data", "final"}:
            raise ValueError("DNCrypt local record kind is invalid")
        self._parent_receipt = envelope.receipt_blake2b
        self._record_index += 1
        return plaintext, str(kind)

    def _consume_next_data_or_final(self) -> None:
        plaintext, kind = self._consume_record()
        if kind == "data":
            self._sha256.update(plaintext)
            self._plaintext_bytes += len(plaintext)
            self._data_records += 1
            self._buffer.extend(plaintext)
            return
        if kind != "final":
            raise ValueError("DNCrypt local metadata record appeared after record zero")
        try:
            final = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("DNCrypt local final record is malformed") from exc
        if not isinstance(final, dict) or canonical_json_bytes(final) != plaintext:
            raise ValueError("DNCrypt local final record is not canonical JSON")
        if set(final) != {
            "schema", "payload_sha256", "payload_bytes", "data_records"
        }:
            raise ValueError("DNCrypt local final record exact-field mismatch")
        if final.get("schema") != LOCAL_FINAL_SCHEMA:
            raise ValueError("unsupported DNCrypt local final schema")
        if final.get("payload_sha256") != self._sha256.hexdigest():
            raise ValueError("DNCrypt local full-payload SHA-256 mismatch")
        if final.get("payload_bytes") != self._plaintext_bytes:
            raise ValueError("DNCrypt local full-payload byte-count mismatch")
        if final.get("data_records") != self._data_records:
            raise ValueError("DNCrypt local data-record count mismatch")
        if self._handle.read(1) != b"":
            raise ValueError("trailing data after DNCrypt local final record")
        self._final_seen = True
        self._final_receipt = self._parent_receipt

    def read(self, size: int = -1) -> bytes:
        if size == 0:
            return b""
        if size < 0:
            size = self.header.chunk_size
        while len(self._buffer) < size and not self._final_seen:
            self._consume_next_data_or_final()
        if not self._buffer:
            return b""
        out = bytes(self._buffer[:size])
        del self._buffer[:size]
        return out

    def finish(self) -> None:
        while not self._final_seen:
            if self._buffer:
                self._buffer.clear()
            self._consume_next_data_or_final()
        self._buffer.clear()


def _safe_original_name(value: object) -> str:
    if not isinstance(value, str) or not value or value in {".", ".."}:
        raise ValueError("encrypted original name is invalid")
    if Path(value).name != value or "/" in value or "\\" in value or ":" in value:
        raise ValueError("encrypted original name is not a safe basename")
    return value


def _safe_tar_member(member: tarfile.TarInfo) -> PurePosixPath:
    name = member.name
    if not name or "\\" in name or ":" in name:
        raise ValueError("unsafe path in encrypted directory archive")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("unsafe path in encrypted directory archive")
    if path.parts[0] != "payload":
        raise ValueError("encrypted directory archive escaped fixed payload root")
    if member.issym() or member.islnk() or member.isdev() or member.isfifo():
        raise ValueError("links and special files are not admitted in local directory archives")
    if getattr(member, "sparse", None):
        raise ValueError("sparse archive members are not admitted in local directory archives")
    if not (member.isdir() or member.isfile()):
        raise ValueError("unsupported file type in local directory archive")
    return path


def _preflight_directory(source: Path) -> None:
    if source.is_symlink():
        raise ValueError("directory symlinks are not admitted in DNCrypt local v1")
    for current, dirs, files in os.walk(source, followlinks=False):
        base = Path(current)
        for name in [*dirs, *files]:
            path = base / name
            if path.is_symlink():
                raise ValueError(f"symlink is not admitted in DNCrypt local v1: {path}")
            if path.is_dir():
                continue
            if not path.is_file():
                raise ValueError(f"special filesystem object is not admitted: {path}")



def _tar_add_filter(member: tarfile.TarInfo) -> tarfile.TarInfo:
    _safe_tar_member(member)
    return member


def _atomic_file_target(destination: Path, *, force: bool) -> tuple[int, Path]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not force:
        raise FileExistsError(f"destination already exists: {destination}")
    if destination.exists() and destination.is_dir():
        raise IsADirectoryError(str(destination))
    fd, raw_path = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=str(destination.parent),
    )
    return fd, Path(raw_path)


def encrypt_path(
    source: str | Path,
    destination: str | Path,
    master_key: bytes | bytearray,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    force: bool = False,
) -> LocalEncryptionResult:
    src = Path(source)
    dst = Path(destination)
    if not src.exists():
        raise FileNotFoundError(str(src))
    if src.is_symlink():
        raise ValueError("DNCrypt local v1 does not encrypt symlink roots")
    if src.resolve() == dst.resolve(strict=False):
        raise ValueError("source and destination must differ")
    if src.is_file():
        kind = "file"
        st = src.stat()
        metadata = {
            "kind": "file",
            "name": src.name,
            "size": st.st_size,
            "mtime_ns": st.st_mtime_ns,
            "mode": st.st_mode & 0o777,
        }
    elif src.is_dir():
        kind = "directory"
        _preflight_directory(src)
        metadata = {
            "kind": "directory",
            "name": src.name,
        }
    else:
        raise ValueError("source must be a regular file or directory")

    fd, tmp = _atomic_file_target(dst, force=force)
    try:
        with os.fdopen(fd, "wb") as out:
            writer = LocalContainerEncryptWriter(
                out,
                master_key,
                payload_kind=kind,
                metadata=metadata,
                chunk_size=chunk_size,
            )
            if kind == "file":
                with src.open("rb") as inp:
                    while True:
                        block = inp.read(chunk_size)
                        if not block:
                            break
                        writer.write(block)
            else:
                with tarfile.open(
                    fileobj=writer,
                    mode="w|",
                    format=tarfile.PAX_FORMAT,
                ) as archive:
                    archive.add(src, arcname="payload", recursive=True, filter=_tar_add_filter)
            writer.finalize()
            out.flush()
            os.fsync(out.fileno())
        if dst.exists() and not force:
            raise FileExistsError(f"destination appeared during encryption: {dst}")
        os.replace(tmp, dst)
        return LocalEncryptionResult(
            source=str(src),
            destination=str(dst),
            payload_kind=kind,
            container_id=writer.header.container_id,
            plaintext_stream_bytes=writer.plaintext_bytes,
            data_records=writer.data_records,
            final_receipt=writer.final_receipt,
        )
    finally:
        if tmp.exists():
            tmp.unlink()


def _extract_tar_stream(reader: LocalContainerDecryptReader, temp_root: Path) -> None:
    created_dirs: list[tuple[Path, tarfile.TarInfo]] = []
    with tarfile.open(fileobj=reader, mode="r|*") as archive:
        for member in archive:
            rel = _safe_tar_member(member)
            target = temp_root.joinpath(*rel.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                created_dirs.append((target, member))
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ValueError("regular tar member had no file payload")
            with target.open("xb") as out:
                shutil.copyfileobj(extracted, out, length=1024 * 1024)
                out.flush()
                os.fsync(out.fileno())
            try:
                os.chmod(target, member.mode & 0o777)
            except OSError:
                pass
            try:
                os.utime(target, (member.mtime, member.mtime))
            except OSError:
                pass
    reader.finish()
    for target, member in reversed(created_dirs):
        try:
            os.chmod(target, member.mode & 0o777)
        except OSError:
            pass


def decrypt_path(
    source: str | Path,
    master_key: bytes | bytearray,
    *,
    destination: str | Path | None = None,
    force: bool = False,
) -> LocalDecryptionResult:
    src = Path(source)
    if not src.is_file():
        raise FileNotFoundError(str(src))
    with src.open("rb") as inp:
        reader = LocalContainerDecryptReader(inp, master_key)
        name = _safe_original_name(reader.metadata.get("name"))
        dst = Path(destination) if destination is not None else src.parent / name
        if src.resolve() == dst.resolve(strict=False):
            raise ValueError("encrypted source and plaintext destination must differ")
        if reader.header.payload_kind == "file":
            fd, tmp = _atomic_file_target(dst, force=force)
            try:
                with os.fdopen(fd, "wb") as out:
                    while True:
                        block = reader.read(reader.header.chunk_size)
                        if not block:
                            break
                        out.write(block)
                    reader.finish()
                    out.flush()
                    os.fsync(out.fileno())
                expected_size = reader.metadata.get("size")
                if expected_size != reader.plaintext_bytes:
                    raise ValueError("decrypted file size does not match encrypted metadata")
                if dst.exists() and not force:
                    raise FileExistsError(f"destination appeared during decryption: {dst}")
                os.replace(tmp, dst)
                try:
                    mode = int(reader.metadata.get("mode", 0o600))
                    os.chmod(dst, mode & 0o777)
                except (OSError, TypeError, ValueError):
                    pass
                try:
                    mtime_ns = int(reader.metadata["mtime_ns"])
                    os.utime(dst, ns=(mtime_ns, mtime_ns))
                except (OSError, KeyError, TypeError, ValueError):
                    pass
            finally:
                if tmp.exists():
                    tmp.unlink()
        elif reader.header.payload_kind == "directory":
            if dst.exists():
                raise FileExistsError(
                    "directory destination already exists; local v1 never replaces directories"
                )
            dst.parent.mkdir(parents=True, exist_ok=True)
            temp_root = Path(
                tempfile.mkdtemp(prefix=f".{dst.name}.", dir=str(dst.parent))
            )
            try:
                _extract_tar_stream(reader, temp_root)
                payload_root = temp_root / "payload"
                if not payload_root.is_dir():
                    raise ValueError("encrypted directory archive lacks payload root")
                extras = [p for p in temp_root.iterdir() if p.name != "payload"]
                if extras:
                    raise ValueError("encrypted directory archive contains unexpected root entries")
                os.replace(payload_root, dst)
            finally:
                shutil.rmtree(temp_root, ignore_errors=True)
        else:
            raise ValueError("unsupported encrypted payload kind")

        return LocalDecryptionResult(
            source=str(src),
            destination=str(dst),
            payload_kind=reader.header.payload_kind,
            container_id=reader.header.container_id,
            plaintext_stream_bytes=reader.plaintext_bytes,
            data_records=reader.data_records,
            final_receipt=reader.final_receipt,
        )


def verify_container(
    source: str | Path,
    master_key: bytes | bytearray,
) -> LocalVerificationResult:
    src = Path(source)
    with src.open("rb") as inp:
        reader = LocalContainerDecryptReader(inp, master_key)
        while reader.read(reader.header.chunk_size):
            pass
        reader.finish()
        return LocalVerificationResult(
            source=str(src),
            payload_kind=reader.header.payload_kind,
            container_id=reader.header.container_id,
            plaintext_stream_bytes=reader.plaintext_bytes,
            data_records=reader.data_records,
            final_receipt=reader.final_receipt,
        )


def default_encrypted_path(source: str | Path) -> Path:
    src = Path(source)
    return src.with_name(src.name + ".dncrypt")


__all__ = [
    "DEFAULT_CHUNK_SIZE",
    "LOCAL_CONTAINER_SCHEMA",
    "LocalContainerHeader",
    "LocalDecryptionResult",
    "LocalEncryptionResult",
    "LocalVerificationResult",
    "LocalContainerDecryptReader",
    "LocalContainerEncryptWriter",
    "decrypt_path",
    "default_encrypted_path",
    "encrypt_path",
    "verify_container",
]