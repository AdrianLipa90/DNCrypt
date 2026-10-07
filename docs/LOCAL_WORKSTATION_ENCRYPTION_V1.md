# DNCrypt Local Workstation Encryption v1

Status: `IMPLEMENTATION_CANDIDATE / LOCAL-FIRST / FROZEN-V0.2-AEAD`

## Purpose

This layer makes the existing DNCrypt cryptographic anchor directly usable on a workstation for ordinary files and directories.

The local runtime path is:

```text
local file/directory
-> DNCrypt local streaming container
-> DNCrypt frozen v0.2 message protection
-> .dncrypt file
```

Decryption is the inverse and does **not** require an AI service, OpenAI API, network service, repository connection, NOEMA, or GREMLIN.

The implementation deliberately does not introduce a new cipher. Confidentiality and integrity remain anchored in:

- 256-bit DNCrypt master key;
- ChaCha20-Poly1305;
- fresh per-record 256-bit HKDF salt;
- fresh per-record 96-bit nonce;
- HKDF-SHA3-512;
- authenticated DNCrypt v0.2 metadata.

The adaptive/genetic/36D research layers do not derive local master keys, salt, nonce, or admission.

## Quick use on Windows

From a DNCrypt clone with Python 3.10+ and the repository dependencies installed:

```powershell
py tools\dncrypt_local.py init --profile private --backend auto
py tools\dncrypt_local.py doctor --profile private

py tools\dncrypt_local.py encrypt "C:\Research\paper.tex" --profile private
py tools\dncrypt_local.py verify "C:\Research\paper.tex.dncrypt" --profile private
py tools\dncrypt_local.py decrypt "C:\Research\paper.tex.dncrypt" --profile private
```

`auto` on Windows uses `Windows DPAPI CurrentUser + a passphrase-derived optional-entropy secret`.
The encrypted key blob is bound both to the current Windows user and to the passphrase.

For a portable profile that can move to another machine/OS, use:

```powershell
py tools\dncrypt_local.py init --profile portable --backend passphrase
```

The portable profile wraps the random 256-bit DNCrypt master key with a key derived using scrypt and ChaCha20-Poly1305.

The installed entry point is equivalent:

```powershell
dncrypt-local encrypt "C:\Research\paper.tex" --profile private
```

## Files and directories

A regular file becomes one streaming `.dncrypt` container.

A directory is streamed through a TAR representation directly into encrypted DNCrypt records. No plaintext TAR staging file is created.

Directory symlinks, hard links and special filesystem objects are rejected in v1. Extraction is confined to one fixed `payload` root and rejects traversal, absolute paths, Windows drive/ADS-style `:` paths, links, devices, FIFOs and sparse members.

## Container design

The public container header contains only:

- container format/protocol identifiers;
- random container id;
- file-vs-directory kind;
- bounded chunk size;
- public DNCrypt genome and surface state;
- header commitment.

The original basename is inside the encrypted metadata record. File content and directory member names are encrypted.

The public header therefore does **not** reveal the original basename. Ciphertext size still leaks an approximation of plaintext/archive size, as ordinary file encryption normally does.

Each encrypted record has authenticated AAD containing:

```text
container_id
header_commitment
record_index
record_kind
plaintext_size
```

Records are additionally chained using the frozen DNCrypt `parent_receipt` field:

```text
metadata
-> data[0]
-> data[1]
-> ...
-> final
```

The final encrypted record commits to:

- SHA-256 of the complete plaintext stream;
- complete plaintext byte count;
- number of data records.

This provides fail-closed detection of reordering, truncation, record insertion/removal, ciphertext mutation, header substitution and wrong-key use.

## Atomicity

Encryption and regular-file decryption write to a sibling temporary file and `fsync` before the final atomic rename.

The default is no overwrite. `--force` can replace an existing regular file/container, but directory decryption never replaces an existing directory.

Directory decryption extracts into a temporary sibling directory and only publishes the completed `payload` tree after the encrypted stream and final record have verified.

## Key profiles

### Windows default: DPAPI + passphrase

`--backend auto` on Windows creates a random DNCrypt master key and protects it with Windows DPAPI CurrentUser using a secret optional-entropy value derived from the user passphrase with bounded scrypt parameters.

This is stronger than storing a raw key or a plain DPAPI blob that any same-user process can request to unwrap without a second secret.

It is still not an HSM boundary. While encryption/decryption is running, the DNCrypt master key necessarily exists transiently in the local Python process.

### Plain DPAPI

`--backend dpapi` is available for convenience but is weaker against a malicious process already running as the same Windows user, because such a process may be able to invoke DPAPI under that user context.

### Portable passphrase

`--backend passphrase` is OS-portable and does not depend on the Windows account. It uses bounded scrypt parameters plus ChaCha20-Poly1305 to wrap the random DNCrypt master key.

The passphrase itself is never stored by DNCrypt.

## Threat boundary

This layer is designed to protect encrypted-at-rest content when the adversary does not possess the local DNCrypt master key/passphrase.

It does **not** claim to protect plaintext from:

- malware or an administrator that can inspect the process while a file is being decrypted;
- a same-user process that captures the passphrase through OS-level compromise;
- screen capture, keylogging or clipboard capture outside DNCrypt;
- a program to which the user intentionally supplies plaintext;
- prior copies of plaintext already synced/uploaded elsewhere.

For stronger isolation from a same-user application, run DNCrypt in a separate OS account, sandbox/VM, or future admitted native/HSM backend.

## Original plaintext

DNCrypt v1 does not delete the original after encryption.

This is intentional. "Secure erase" is not reliably implementable for SSDs, copy-on-write filesystems, snapshots or cloud-synced storage by merely overwriting a pathname.

After verifying a `.dncrypt` container, the user can remove the original according to the actual storage/backup threat model.

## Network boundary

`local_keystore.py`, `local_container.py` and `local_cli.py` contain no network/HTTP/OpenAI client dependency. Runtime encrypt/decrypt/verify is local-only.

A `.dncrypt` file can be copied or uploaded like any other ciphertext. Whoever receives only that container and not the local key/profile secret cannot use DNCrypt to recover plaintext.

## Evidence status

This is a practical local-workstation integration around the frozen v0.2 AEAD anchor. It is not an independent cryptographic certification.

The novel adaptive/relational DNCrypt layers remain outside the confidentiality claim. Independent cryptanalysis and hardened native/HSM key custody remain separate gates.