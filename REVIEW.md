# Review record

Reviewed: NoxCrypt 1.0.0, the tree that adds this file.
Library: libncrypt, git submodule pinned to `1e71786` (the 1.0.0
release), verified byte-identical to the upstream tag.
Date: 2026-11-01.

This is the project's own review. It is not an independent audit,
not a formal verification, and not a penetration test. Its purpose
is to state exactly what was examined, what was found, and how a
reader can repeat the checks, so that trust can be placed
deliberately.

Bugs fixed during development, before this review, are not recorded
here. This document describes the review of the released tree.

## Scope

Every file that can touch untrusted input was in scope:

- `src/armor.c`: base64, PEM armor, the streaming reader and writer.
  Reached by `import`, `decrypt`, `verify`, `export -k` input, and
  every armored document.
- `src/packet.c`: magic and packet framing. The first code an
  untrusted document meets.
- `src/identity.c`: key generation, public key parsing, fingerprint
  derivation, self-signature verification, secret expansion.
- `src/secret.c`: passphrase wrapping and unlocking of secret keys.
- `src/cipher.c`: recipient wraps, the hybrid combiner, payload
  chunking, and the whole decrypt path.
- `src/sign.c`: detached signatures and verification.
- `src/keyring.c`: directory scanning, name filtering, listing.
- `src/passphrase.c`: terminal handling and passphrase files.
- `src/util.c`: byte order, RNG, file helpers, Argon2id wrapper.
- `src/nox.c`: argument parsing, file creation, exit codes.
- `vendor/libncrypt/*`: consumed as a submodule. Its own review is
  the upstream project's; this review checked the pin and the call
  sites against its documented contracts.

Out of scope: anything outside the repository, the build system's
own supply chain beyond the submodule pin, and the cryptographic
core algorithms themselves (see Limitations).

## Method

- Line-by-line reading of every file above, with the index
  arithmetic and length checks of each untrusted-input decoder
  written out symbolically and re-derived: packet framing, identity
  value layout and comment length, recipient sizes, chunk sizes,
  armor line handling, keyring name filtering.
- Every AEAD call checked for what its additional data binds. Every
  RNG call site enumerated: file keys, payload and wrap nonces,
  ephemeral X25519 keys, encapsulation seeds, salts, and the ML-DSA
  hedging bytes.
- Failure paths re-read for state left behind: output files,
  terminal echo, signal handlers, buffers that hold secrets.
- Call sites checked against libncrypt's documented contracts
  (buffer sizes, seed wiping, return value conventions, context
  strings for ML-DSA).
- Tooling, on this tree:
  - GCC 12.2, `-Wall -Wextra -std=c11` plus
    `-D_FORTIFY_SOURCE=2 -fstack-protector-strong`: warning clean.
  - GCC `-fanalyzer`: two reports, both traced and dismissed as
    false positives (an unreachable branch in `nox_read_all`'s
    realloc path, and a `FILE*` leak on a `tcgetattr` failure that
    cannot happen after the same function already opened the
    terminal successfully). Neither is reachable with any input.
  - The unit suite and the full CLI suite under AddressSanitizer,
    UndefinedBehaviorSanitizer, and LeakSanitizer: clean.
  - Mutation fuzzing under AddressSanitizer: byte flips and
    truncations over valid public keys, secret keys, ciphertexts,
    and signatures, and their armored forms, driven through
    `import`, `decrypt`, and `verify`. 1200 binary and 400 armored
    runs on the released tree, no crashes and no hangs.
  - The libncrypt upstream test suite run against the submodule
    copy: the Monocypher 4.0.3 vector set, 503 post-quantum checks,
    and 323 ACVP known-answer checks, all passing.
  - `make test` (unit plus CLI round-trips and failure paths) run
    repeatedly, including under the sanitizers.

## Findings

| Id | Severity | Finding | Disposition |
|----|----------|---------|-------------|
| F-01 | Medium | The streaming reader dropped up to three leading bytes when input began with an `EF BB` pair that was not a UTF-8 BOM. The BOM probe queued the bytes for replay, then the format-detection branch overwrote the queue. A document with three arbitrary prefix bytes decrypted or imported where it had to be rejected. | Fixed. The probe now queues and appends instead of overwriting. Regression tests cover binary and armored input with a non-BOM prefix, BOM-prefixed binary and armored input, and short `EF`/`EF BB` inputs. Fuzzing was extended over armored inputs. |
| F-02 | Low | The ciphertext chunk-skip path allocated a buffer of the attacker-supplied packet length; a zero-length packet made `malloc(0)`, whose `NULL` return was misreported as out of memory. Behavior was fail-closed, the diagnostic was wrong. | Fixed with an explicit zero-length case. |
| F-03 | Low | Output files were created directly with their final mode, so plaintext or secret-key bytes sat at that mode, typically 0644, for the whole duration of a write. | Fixed. Output is written to a temporary file created 0600; the final mode is applied only when the content is complete, immediately before the atomic rename. Permission checks for secret and public outputs are part of the test suite. |

## Examined and found sound

- Packet framing: length checks, type 0 rejection, critical-bit
  handling, trailing-byte rejection at every level.
- The identity decoder: comment length bounds, UTF-8 rules, key
  count, usage-bit validation, key ordering, self-signature
  coverage of the full public body, and rejection of bytes inside
  the value after the last required signature.
- The hybrid combiner: both shared secrets hashed with their full
  transcripts and the recipient fingerprint; an all-zero X25519
  result rejected; ML-KEM implicit rejection backed by AEAD.
- Downgrade enforcement: the recipient flavor a decryptor accepts is
  derived from its own key set, in both directions, and the
  signature verifier requires exactly the signing set of the
  identity.
- Chunk semantics: authenticated index and final flag, the
  non-final-then-final retry, the exact-size rule for non-final
  chunks, and truncation rejection. A failed AEAD read does not
  advance the stream, so the retry is sound.
- Keyring: file names filtered to 64 hex characters plus the
  expected extension, ambiguous prefixes rejected, directory mode
  tightened before use, key files written atomically.
- Passphrase handling: echo restored on errors and signals, buffers
  wiped, passphrase files rejected rather than truncated, empty
  passphrases refused.
- Argon2id parameter validation: memory and time caps applied to
  untrusted parameters in both the secret-key header and the
  passphrase recipient.
- Output integrity: `-o`, `--pub`, and `--sec` writes are temp plus
  rename, so a failed command leaves the destination untouched.

## Observations that are not defects

- Temporary output names are predictable. Creation is `O_EXCL` with
  `O_NOFOLLOW` in the destination directory, the content is never
  more sensitive than the destination itself, and the file is
  renamed or discarded within the same command.
- Importing a key replaces an existing entry with the same
  fingerprint. Fingerprints are content addresses, so this replaces
  a key with its own re-encoding, and a tampered file fails the
  self-signature check.
- An identity without an encryption key parses and is listed, but
  cannot be a recipient. Signing and encryption are separate
  capabilities; the format permits a signature-only identity.
- `nox list` searches comments by substring while key selection in
  other commands is hex-only. Documented behavior, kept on purpose.
- Constant-time comparison is applied where secrets are compared.
  Public data such as framing and fingerprint selectors compares
  with early exit, which leaks nothing worth leaking.

## Limitations

- This review is internal. No independent party has audited the
  code, and no formal verification of the cryptographic
  implementations exists.
- No statistical timing measurements were made (no dudect-style
  testing). The constant-time properties of the primitives rest on
  Monocypher's record and the FIPS reference cores' analysis.
- The fuzzing was mutation-based over a structured corpus, not
  coverage-guided. It bounds, but does not eliminate, the risk of a
  decoding defect in a path the corpus does not reach.
- Everything was tested on x86-64 Linux with GCC 12 and Clang. No
  big-endian, 32-bit, or non-Linux runs were made. The code assumes
  two's-complement arithmetic, as the reference cores do.
- The lattice cores inherit the reference implementations'
  documented secret-dependent branches in rejection loops, which
  FIPS 203 and FIPS 204 analyze; they were not "fixed".

## Repeating the checks

```
make test                       # unit tests, CLI round-trips, failure paths
gcc -fanalyzer -O1 -std=c11 -Wall -Wextra \
    -Iinclude -Isrc -Ivendor/libncrypt -c src/*.c
# sanitizer build of the binary, then:
ASAN_OPTIONS=detect_leaks=1 sh tests/test.sh   # after pointing NOX at it
```

The libncrypt suite runs from the submodule's own `make check`.
