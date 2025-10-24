# Shadow Crypt

Password-based file encryption with filename obfuscation.

## Features

- **Strong Algorithms**: XChaCha20-Poly1305 cipher, Argon2id key derivation
- **Zero Knowledge**: Passwords are never stored
- **Memory Safety**: Zeroizes sensitive data in memory after use

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

### Show Encrypted File Info

```bash
shadows
```

Display information about all `.shadow` files in the current directory.

## Contributing

Contributions are welcome! Please open issues or submit pull requests on [Github](https://github.com/simon-amadeus/shadow-crypt).

## License

Licensed under MIT OR Apache-2.0.