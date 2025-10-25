# Shadow Crypt

[![Crates.io](https://img.shields.io/crates/v/shadow-crypt.svg)](https://crates.io/crates/shadow-crypt)
[![Documentation](https://docs.rs/shadow-crypt-core/badge.svg)](https://docs.rs/shadow-crypt-core)
[![Shell Documentation](https://docs.rs/shadow-crypt-shell/badge.svg)](https://docs.rs/shadow-crypt-shell)
[![CI](https://github.com/simon-amadeus/shadow-crypt/actions/workflows/ci.yml/badge.svg)](https://github.com/simon-amadeus/shadow-crypt/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/crates/l/shadow-crypt.svg)](#license)

Password-based file encryption with filename obfuscation.

## Features

- **Strong Algorithms**: XChaCha20-Poly1305 cipher, Argon2id key derivation
- **Zero Knowledge**: Sensitive data is never stored, never logged
- **Memory Safety**: Zeroizes sensitive data in memory after use
- **No Dependencies**: Pure Rust implementation

## Installation
- Ensure you have [Rust and Cargo](https://www.rust-lang.org/tools/install) installed.

### Using Cargo (Recommended)

```bash
cargo install shadow-crypt
```

### From Source

```bash
git clone git@github.com:simon-amadeus/shadow-crypt.git
cd shadow-crypt
cargo install --path .
```

## Usage

### Encrypt Files
```bash
shadow file1.txt file*.jpg
```

### Decrypt Files
```bash
unshadow mzpuTgQmBPJfTAJh.shadow RzxZGbTQAxxBseaI.shadow
```

### List Encrypted Files
```bash
shadows
```

## Documentation

- [📝 Changelog](docs/CHANGELOG.md)
- [📚 API Documentation](https://docs.rs/shadow-crypt)

## Contributing

Contributions are welcome! Please open issues or submit pull requests on [Github](https://github.com/simon-amadeus/shadow-crypt).

## License

Licensed under MIT OR Apache-2.0.

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for full license texts.