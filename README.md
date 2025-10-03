# Shadow

Modern file encryption with XChaCha20-Poly1305 and AES-256-GCM.

## Install

```bash
cargo install shadow-crypt
```

## Usage

```bash
# Encrypt files
shadow document.txt
shadow *.pdf

# Decrypt files  
unshadow document.txt.shadow
unshadow *.shadow

# List encrypted files
shadows
```

## Advanced Options

```bash
# Obfuscate filenames for privacy
shadow --obfuscate secret.txt

# Remove source files after encryption
shadow --remove-source *.log

# Choose encryption algorithm
shadow --algorithm aes-gcm file.txt    # for compatibility
shadow --algorithm xchacha20 file.txt  # for maximum security (default)
```

## Tools

- `shadow` - Encrypt files and directories
- `unshadow` - Decrypt files and restore original names
- `shadows` - List and browse encrypted files
- `shadowview` - View encrypted files without decryption *(in development)*
- `shadowedit` - Edit encrypted files in-place *(in development)*

## Security Features

- **XChaCha20-Poly1305** and **AES-256-GCM** encryption algorithms
- **Argon2id** password-based key derivation
- **Authenticated encryption** with tamper detection
- **Filename obfuscation** for metadata privacy
- **Secure password prompting** (never displayed)
- **Versioned file format** for future compatibility

## File Format

Encrypted files use the `.shadow` extension and contain:
- Cryptographic headers with algorithm info and salt
- Encrypted content with authentication
- Optional obfuscated filename metadata

## License

MIT or Apache 2.0