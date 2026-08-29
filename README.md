# Shadow Crypt

[![Crates.io](https://img.shields.io/crates/v/shadow-crypt.svg)](https://crates.io/crates/shadow-crypt)
[![Documentation](https://docs.rs/shadow-crypt/badge.svg)](https://docs.rs/shadow-crypt)
[![CI](https://github.com/simon-amadeus/shadow-crypt/actions/workflows/ci.yml/badge.svg)](https://github.com/simon-amadeus/shadow-crypt/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/crates/l/shadow-crypt.svg)](#license)

Password-based file encryption with filename obfuscation.

`shadow` turns files and directories into anonymously named `.shadow` containers.
`unshadow` restores them. `shadows` lists them.

## Features

- **Strong cryptography** — XChaCha20-Poly1305 authenticated encryption, Argon2id key derivation
- **Nothing leaks** — filenames, timestamps, and permissions travel inside an encrypted metadata envelope; a directory becomes a single archive that hides even its file count and sizes
- **Tamper-evident** — headers are bound to the ciphertext as AEAD associated data; chunk counters make reordering, truncation, and extension fail authentication
- **Any size** — streaming encryption and decryption with bounded memory
- **Safe by default** — crash-safe atomic writes, no overwrites without `--force`, no data destroyed before its replacement is verified, path-traversal-proof extraction
- **Pure Rust** — no C or system libraries; builds with Cargo alone

## Installation

```bash
cargo install shadow-crypt
```

Or from source: `git clone` this repository and `cargo install --path .`

## Usage

```bash
# Encrypt files (prompts for a password)
shadow notes.txt photos*.jpg

# Encrypt a directory into a single archive
shadow photos/

# Encrypt and delete the originals afterwards
shadow --delete taxes/

# Decrypt
unshadow mzpuTgQmBPJfTAJh.shadow

# List encrypted files in a directory (no password needed)
shadows

# ...including their original filenames (prompts for the password)
shadows --names
```

For scripting: `--password-file`, `--output-dir`, `--quiet`, `shadows --json`,
and distinct exit codes (see `--help`).

Key derivation cost is chosen by profile: `standard` (OWASP-recommended, the
default) or `paranoid` (1 GiB memory, for high-value archives). Files record
their parameters, so any profile decrypts with any build. See `shadow --profiles`.

## Documentation

- [📖 Format specification](docs/FORMAT.md)
- [🛡️ Threat model](docs/THREAT_MODEL.md)
- [📝 Changelog](CHANGELOG.md)
- [📚 API documentation](https://docs.rs/shadow-crypt)

## Contributing

Contributions are welcome! Please open issues or submit pull requests on [GitHub](https://github.com/simon-amadeus/shadow-crypt).

## License

Licensed under MIT OR Apache-2.0.

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for full license texts.
