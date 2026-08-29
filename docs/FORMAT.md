# Shadow file format

This documents the on-disk format of `.shadow` files. The current write
format is **v3**; v1 and v2 files remain readable. All integers are little
endian. The code is the authority — each format version lives in its own
independent module under `crates/shadow-crypt-core/src/` (`v1/`, `v2/`,
`v3/`), and the versions deliberately share no code.

## Container preamble

Every shadow file, regardless of version, starts with:

| field   | size    | value               |
|---------|---------|---------------------|
| magic   | 6 bytes | `"SHADOW"`          |
| version | 1 byte  | 1, 2, or 3          |

Readers dispatch on the version byte; unknown versions are rejected.

## v3

One v3 file is: header, then a stream of encrypted content chunks. The
cipher is XChaCha20-Poly1305 (16-byte tag); the key is derived from the
password with Argon2id using the salt and parameters in the header.

### Header

| field                      | size     | notes                                |
|----------------------------|----------|--------------------------------------|
| magic (`"SHADOW"`)         | 6 bytes  |                                      |
| version (3)                | 1 byte   |                                      |
| header_length              | 4 bytes  | total serialized header length       |
| salt                       | 16 bytes | Argon2id salt, fresh per file        |
| kdf_memory                 | 4 bytes  | KiB                                  |
| kdf_iterations             | 4 bytes  |                                      |
| kdf_parallelism            | 4 bytes  |                                      |
| kdf_key_length             | 1 byte   | bytes (32 for all current profiles)  |
| nonce_prefix               | 16 bytes | prefix of every content-chunk nonce  |
| chunk_size                 | 4 bytes  | plaintext bytes per chunk            |
| metadata_nonce             | 24 bytes | nonce of the metadata envelope       |
| metadata_ciphertext_length | 2 bytes  |                                      |
| metadata_ciphertext        | variable | AEAD-encrypted metadata envelope     |

Writers use a 1 MiB chunk size; readers accept any declared size in
`1..=64 MiB` (the bound caps the per-chunk allocation a crafted file can
request). Readers additionally bound the KDF parameters (memory ≤ 8 GiB,
iterations ≤ 1000, parallelism ≤ 256, key ≤ 64 bytes) before deriving,
so a crafted header cannot demand excessive memory or CPU.

### Header binding (associated data)

Every AEAD operation in a v3 file authenticates the fixed header fields as
associated data: magic, version, salt, the three KDF parameters, key length,
nonce_prefix, chunk_size, and metadata_nonce, in serialization order,
followed by a domain tag:

- metadata envelope: `"shadow-crypt/v3/metadata"`
- content chunks: `"shadow-crypt/v3/content"`

Tampering with any bound field fails decryption, and a ciphertext produced
for one domain can never authenticate in the other. The length fields are
deliberately excluded: shifting them changes which bytes are interpreted as
ciphertext, which already fails authentication.

### Metadata envelope (plaintext layout, before encryption)

| field        | size     | present              |
|--------------|----------|----------------------|
| flags        | 1 byte   | always               |
| filename_len | 2 bytes  | always               |
| filename     | variable | always (UTF-8)       |
| mtime_secs   | 8 bytes  | flags bit 0 (signed) |
| mtime_nanos  | 4 bytes  | flags bit 0          |
| mode         | 4 bytes  | flags bit 1          |

Flags bit 2 marks the content as an archive (a directory tree); `filename`
is then the directory name. Unknown flag bits and trailing bytes are
rejected — any extension to this layout is a new format version.

### Content stream

The content is a sequence of AEAD chunks of `chunk_size` plaintext bytes;
only the final chunk may be shorter (including empty — an empty file is one
final empty chunk, so every stream has at least one chunk). Each chunk's
24-byte nonce is:

```text
nonce_prefix (16 bytes) || counter (7 bytes, LE) || final flag (1 byte)
```

The counter makes reordering fail authentication; the final flag makes
truncation at a chunk boundary fail (the last present chunk was not sealed
as final, so opening it as final does not authenticate).

## Archive payload

A directory tree is serialized as one byte stream and travels as the
*content* of a v3 file whose metadata envelope carries the archive flag, so
it inherits the container's encryption, authentication, and streaming. The
layout carries its own magic and version and is independent of the
container version:

```text
magic: "SHDWARC" + version byte 1          (8 bytes)
entries, each:
  entry_type: u8                           (1 = file, 2 = directory, 0 = end)
  for file/directory entries:
    path_len: u16, path: UTF-8             ('/'-separated relative path)
    flags: u8                              (bit 0 mtime, bit 1 mode)
    mtime_secs: i64, mtime_nanos: u32      (if flagged)
    mode: u32                              (if flagged)
  for file entries:
    content_len: u64, content bytes
terminator: entry_type 0; nothing may follow
```

Directories appear before their contents. Paths are validated on both
encode and parse: relative, `/`-separated, at most 4096 bytes, no `..`, `.`,
or empty components, no backslashes.

## Legacy versions (read-only)

- **v1** encrypts the filename and content as two independent AEAD messages;
  header fields are *not* authenticated.
- **v2** authenticates the fixed header fields as associated data with
  domain separation between filename and content (preventing
  ciphertext-swapping within a file), but still encrypts the content as a
  single message and stores a bare filename ciphertext.

Both are decrypted and listed but never written. Their exact layouts are
documented in `crates/shadow-crypt-core/src/v1/header.rs` and
`v2/header.rs`.
