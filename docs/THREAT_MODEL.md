# Threat model

What shadow-crypt defends against, what it deliberately does not, and the
design decisions behind both. The format details are in
[FORMAT.md](FORMAT.md).

## Setting

You encrypt files on a machine you trust, then the `.shadow` outputs travel
somewhere you don't: cloud storage, backup media, email, a stolen laptop's
disk. Two adversaries matter:

1. **An observer** who obtains your `.shadow` files and wants to learn or
   alter their contents.
2. **A sender** who crafts a malicious `.shadow` file and gets you to
   decrypt or list it.

## What is protected

**Confidentiality.** Content, original filename, timestamps, and permissions
are all encrypted (XChaCha20-Poly1305, key derived from your password with
Argon2id). Output names are random, so a `.shadow` file reveals nothing
about what it holds. A directory archive additionally hides the file count
and the individual names and sizes inside it. Each file gets a fresh salt
and key, so files encrypted in one session cannot be correlated by their
headers.

**Integrity and authenticity.** Every header field that influences
decryption is authenticated as AEAD associated data, with distinct domains
for metadata and content — header tampering and ciphertext-swapping between
domains or files fail authentication. Content chunk nonces carry a counter
and a final-chunk flag, so reordering, truncating, or extending the stream
fails too. Anything that fails authentication is reported as wrong password
or corrupted file; no partial plaintext is released.

**Offline password guessing is expensive.** Argon2id with OWASP-recommended
parameters by default (or 1 GiB memory cost with `--profile paranoid`), and
password strength is enforced at encryption time (zxcvbn score ≥ 3/4).
The password is the wall: there is no recovery, and no secret other than it.

## Malicious input is expected

Decrypting and listing treat every byte of a `.shadow` file as hostile:

- KDF parameters from headers are bounded (memory ≤ 8 GiB, iterations
  ≤ 1000, parallelism ≤ 256) before any derivation, so a crafted file
  cannot demand absurd memory or CPU. Declared chunk sizes are capped at
  64 MiB before allocation.
- Decrypted paths are sanitized before any filesystem write: no absolute
  paths, no `..`, no backslashes, no Windows drive prefixes or `:`
  components. Extraction refuses a symlinked output root. A malicious
  archive cannot write outside the chosen output directory.
- Restored permissions drop setuid/setgid/sticky bits, so a hostile file
  cannot plant a privilege-escalation primitive.
- All parsers are fuzzed (`cargo fuzz`); structural violations are errors,
  never best-effort guesses.

## Local safety

The tool assumes it may crash, be interrupted, or be pointed at the wrong
place at any time:

- Output is written to a temporary file, fsynced, and atomically renamed
  into place — a crash never leaves a truncated file that looks complete.
- Nothing is overwritten without `--force`, and even `--force` destroys the
  existing file only after its replacement has fully authenticated.
- `--delete` removes originals only after the encrypted output is committed
  to disk, and refuses entirely if anything was skipped during archiving or
  the output landed inside the input directory.
- Passwords, keys, and plaintext buffers are zeroized in memory after use.

## Out of scope

- **A compromised machine.** A keylogger, malicious process, or root
  attacker on the encrypting or decrypting host sees your password and
  plaintext. No file format can help there.
- **Forensic deletion.** `--delete` is a normal filesystem remove; on SSDs
  and journaling filesystems the plaintext may remain recoverable until
  overwritten.
- **Perfect memory hygiene.** Zeroization is best-effort: the OS may swap
  pages or write core dumps before buffers are wiped.
- **Container-level metadata.** The size and modification time of the
  `.shadow` file itself are visible, and a single-file (non-archive)
  container's size approximates its plaintext size.
- **Deniability.** `.shadow` files are recognizable as such (magic bytes);
  the format hides content, not its own existence.
