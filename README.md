# x3dh

A pure Rust implementation of the **Extended Triple Diffie-Hellman (X3DH)** key agreement protocol, as specified by Signal, built on the **X25519** elliptic curve.

X3DH establishes a shared secret between two parties (here called Alice and Bob) asynchronously — Bob can be offline when Alice initiates. The resulting shared secret can then be used to bootstrap a Double Ratchet session for forward-secure messaging.

## Protocol Overview

X3DH uses four Diffie-Hellman exchanges to derive a shared secret:

| Exchange | Alice's key | Bob's key |
|----------|-------------|-----------|
| DH1 | Alice's static identity key | Bob's signed prekey |
| DH2 | Alice's ephemeral key | Bob's static identity key |
| DH3 | Alice's ephemeral key | Bob's signed prekey |
| DH4 | Alice's ephemeral key | Bob's one-time prekey |

The four DH outputs are concatenated (with a 32-byte `0xFF` padding prefix per the spec) to form the key material. Both parties independently compute the same value, producing an identical shared secret without any direct key exchange at send time.

Bob's signed prekey carries an Ed25519 signature from his identity key, which Alice verifies before computing her side — preventing key substitution attacks.

## Key Types

| Key | Type | Lifetime |
|-----|------|----------|
| Identity key | Ed25519 signing key → X25519 static | Permanent |
| Signed prekey | X25519 static | Rotates periodically |
| One-time prekey (OPK) | X25519 static | Single use |
| Ephemeral key | X25519 static (Alice only) | Per-session |

## Project Structure

```
src/
├── main.rs          — entry point, runs the test handshake
├── key_structs.rs   — key bundle types (PublishInitialKeys, SignedPrekeyBundle, etc.)
├── generate_keys.rs — key generation helpers (identity, signed prekey, OPKs)
├── exchange.rs      — bundle publishing logic
└── test.rs          — end-to-end X3DH handshake test (Alice ↔ Bob)
```

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| [`x25519-dalek`](https://crates.io/crates/x25519-dalek) | 2.0.1 | X25519 Diffie-Hellman (static & ephemeral secrets) |
| [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek) | 2.2.0 | Ed25519 signing/verification for prekey signatures |
| [`hkdf`](https://crates.io/crates/hkdf) | 0.13.0 | HKDF key derivation (HMAC-based Extract-and-Expand) |
| [`sha2`](https://crates.io/crates/sha2) | 0.11.0 | SHA-256/512 hash functions (used by HKDF) |
| [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305) | 0.10.1 | ChaCha20-Poly1305 AEAD encryption |
| [`rand_core`](https://crates.io/crates/rand_core) | 0.6 | Cryptographically secure RNG via `OsRng` |
| [`hex`](https://crates.io/crates/hex) | 0.4.3 | Hex encoding/decoding for key inspection |
| [`tokio`](https://crates.io/crates/tokio) | 1.52.3 | Async runtime (multi-thread + macros) |

## Running

```bash
cargo run
```

This executes the end-to-end handshake test: Alice and Bob each independently derive their shared secret, and the test asserts they are equal.

```bash
cargo test
```

## References

- [Signal X3DH Specification](https://signal.org/docs/specifications/x3dh/)
- [The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
