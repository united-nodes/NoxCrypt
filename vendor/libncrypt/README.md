# libncrypt

A small cryptographic library for C99: two source files, two headers, no
dependencies beyond the standard library, no `malloc`, no global state,
and no I/O. It provides the classical primitives of Monocypher 4.0.3 and
the post-quantum algorithms of FIPS 203 and FIPS 204, behind one
`ncrypt_` prefix.

| Layer | Files | Contents |
| --- | --- | --- |
| Classical | `ncrypt.c`, `ncrypt.h` | XChaCha20-Poly1305, BLAKE2b, Argon2, X25519, EdDSA, Ed25519, SHA-512, HMAC, HKDF, Elligator 2 |
| Post-quantum | `ncrypt-pqc.c`, `ncrypt-pqc.h` | ML-KEM-768, ML-DSA-44, and a hybrid public-key encryption construction |

## Status

The library is complete and tested, but **it has not been independently
audited**. Everything below was produced by the project itself: source
review, NIST ACVP vectors, sanitizers, Valgrind, a constant-time harness
and a cross-implementation test. That is a good starting point and no
substitute for a third-party audit. If you need one — for regulatory
reasons, or because a bug would be expensive — commission it before
protecting anything valuable.

What is verified:

- Both layers compile without a single diagnostic under GCC 14 and
  Clang 19 with `-Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
  -Wmissing-prototypes -Wconversion -Wsign-conversion -Wcast-qual -Wvla
  -Wundef -Wwrite-strings -Werror`, for 32-bit and 64-bit targets.
- The classical layer reproduces Monocypher 4.0.3's own test vectors,
  including the Elligator vectors.
- The post-quantum layer matches the NIST ACVP vectors for ML-KEM-768 and
  ML-DSA-44 (key generation, encapsulation, decapsulation, the FIPS 203
  key checks, and both signature directions).
- Signatures and decapsulation interoperate with PQClean through the
  `pqcrypto` Python bindings, in both directions.
- libncrypt and PQClean reach the *same verdict* on forged ciphertexts
  and on mutated signatures — the part of a signature or record an
  attacker controls. See [What has been checked](#what-has-been-checked).
- The test suite is clean under AddressSanitizer, UndefinedBehaviorSanitizer,
  Valgrind memcheck (no leaks, no invalid accesses) and undefined-value
  tracking.
- `make ct` runs a ctgrind-style harness under Valgrind and fails if any
  function branches or indexes on secret data, except for the reviewed
  exceptions listed in `tests/ct.supp`. See [Constant time](#constant-time)
  below for what that does and does not prove.

Details, including the known gaps, are in
[`doc/TESTING.md`](doc/TESTING.md).

## Algorithms

| Algorithm | Standard | Prefix | Notes |
| --- | --- | --- | --- |
| ML-KEM-768 | FIPS 203 | `ncrypt_mlkem768_` | NIST category 3. Includes the FIPS 203 encapsulation key check and decapsulation key check. |
| ML-DSA-44 | FIPS 204 | `ncrypt_mldsa44_` | NIST category 2. Hedged signing by default, deterministic variant available, context strings supported. |
| Hybrid PKE | ML-KEM-768 + XChaCha20-Poly1305 | `ncrypt_pqc_` | KEM/DEM construction; key and nonce derived from the encapsulation. |
| XChaCha20-Poly1305 | RFC 8439 + XChaCha | `ncrypt_aead_` | 256-bit key, 192-bit nonce. |
| BLAKE2b | RFC 7693 | `ncrypt_blake2b` | Keyed and unkeyed, incremental interface. |
| Argon2 (d, i, id) | RFC 9106 | `ncrypt_argon2` | Caller-supplied work area. |
| X25519, EdDSA (BLAKE2b), Ed25519 | RFC 7748, RFC 8032 | `ncrypt_x25519_`, `ncrypt_eddsa_`, `ncrypt_ed25519_` | Includes scalar division (OPRF), conversions, and the EdDSA building blocks. |
| Elligator 2 | — | `ncrypt_elligator_` | Hides public keys as uniform strings; with the "dirty" X25519 key generation. |
| SHA-512, HMAC-SHA-512, HKDF-SHA-512 | FIPS 180-4, RFC 2104, RFC 5869 | `ncrypt_sha512_` | |

The classical layer is Monocypher 4.0.3 with the `crypto_` prefix
renamed to `ncrypt_`; no cryptographic code was changed (the complete
list of differences is in [`doc/PROVENANCE.md`](doc/PROVENANCE.md)). The
Monocypher manual applies to those functions after substituting the
prefix: <https://monocypher.org/manual/>.

## Usage

Copy the four files into your project and compile `ncrypt.c` and
`ncrypt-pqc.c` with the rest of your code, or build the static library:

```
make            # libncrypt.a
make check      # run the test suite
make install    # headers and library under /usr/local (PREFIX=... to change)
```

### Hybrid public-key encryption

```c
#include "ncrypt-pqc.h"
#include <sys/random.h>   /* getrandom(); use the equivalent elsewhere */

/* Recipient: generate a key pair once and keep secret_key. */
uint8_t secret_key[NCRYPT_MLKEM768_SECRET_KEY_SIZE];
uint8_t public_key[NCRYPT_MLKEM768_PUBLIC_KEY_SIZE];
uint8_t key_seed  [NCRYPT_MLKEM768_KEY_SEED_SIZE];
getrandom(key_seed, sizeof key_seed, 0);
ncrypt_pqc_key_pair(secret_key, public_key, key_seed);   /* seed is wiped */

/* Sender: encrypt a message to public_key. */
uint8_t seed  [NCRYPT_PQC_SEED_SIZE];     /* fresh for every message */
uint8_t kem_ct[NCRYPT_PQC_KEM_CT_SIZE];
uint8_t mac   [NCRYPT_PQC_MAC_SIZE];
uint8_t cipher_text[13];
const uint8_t message[13] = "hello, world";
getrandom(seed, sizeof seed, 0);
if (ncrypt_pqc_encrypt(cipher_text, mac, kem_ct, public_key, seed,
                       NULL, 0, message, sizeof message) != 0) {
	/* public_key is malformed; nothing was written */
}

/* Recipient: decrypt. */
uint8_t plain_text[13];
if (ncrypt_pqc_decrypt(plain_text, kem_ct, mac, secret_key,
                       NULL, 0, cipher_text, sizeof cipher_text) != 0) {
	/* forged or corrupted; plain_text is untouched */
}
```

The record to transmit is `kem_ct || mac || cipher_text`; the associated
data (`ad`) is authenticated but not carried, so pass whatever framing
header your protocol uses.

### Signatures

```c
#include "ncrypt-pqc.h"
#include <sys/random.h>

uint8_t secret_key[NCRYPT_MLDSA44_SECRET_KEY_SIZE];
uint8_t public_key[NCRYPT_MLDSA44_PUBLIC_KEY_SIZE];
uint8_t key_seed  [NCRYPT_MLDSA44_KEY_SEED_SIZE];
getrandom(key_seed, sizeof key_seed, 0);
ncrypt_pqc_sign_key_pair(secret_key, public_key, key_seed);

uint8_t rnd[NCRYPT_MLDSA44_RND_SIZE];          /* fresh for every signature */
uint8_t signature[NCRYPT_MLDSA44_SIGNATURE_SIZE];
getrandom(rnd, sizeof rnd, 0);
ncrypt_pqc_sign(signature, secret_key, rnd, message, message_size);

if (ncrypt_pqc_check(signature, public_key, message, message_size) != 0) {
	/* invalid signature */
}
```

`ncrypt_mldsa44_sign` and `ncrypt_mldsa44_check` are the same functions
with an explicit context string.

### Randomness and seeds

The library never reads a random source. Every seed and every `rnd`
argument must come from the operating system's CSPRNG, and every one of
them is overwritten with zeros before the call returns — on every path,
including failures. This makes seed reuse visible in the calling code
instead of silent.

The consequences of a repeated seed differ per function; the table is in
[`doc/API.md`](doc/API.md#randomness). For `ncrypt_pqc_encrypt` it is the
most serious: the same seed and recipient key reproduce the same
keystream.

## Building and testing

```
make check        # Monocypher vectors, behavioural tests, ACVP vectors
make strict       # full warning set, -Werror, library and tests
make sanitize     # the same tests under ASan and UBSan
make valgrind     # the same tests under Valgrind memcheck
make ct           # constant-time harness (Valgrind + tests/ct.supp)
make fuzz         # standalone fuzz sweep under ASan and UBSan
make interop      # cross-check against PQClean (needs `pip install pqcrypto`)
make differential # adversarial inputs: libncrypt's verdict vs PQClean's
```

The analysis targets need Valgrind and a sanitizer-capable compiler; the
last two need `pip install pqcrypto`. The rest needs only a C99 compiler
and `make`.

### What has been checked

Correctness on valid input is pinned by NIST's ACVP vectors. Behaviour on
invalid input is checked three more ways, because that is where a
signature scheme is actually attacked:

- **A second implementation.** `make differential` gives libncrypt and
  PQClean the same forged ciphertexts and mutated signatures and requires
  the same verdict, byte for byte. A decoder that accepts an encoding the
  standard rejects — the classic source of signature malleability — fails
  this test.
- **A second key pair.** Encapsulation is tested in both directions, so a
  self-consistently wrong key generation cannot pass.
- **Sanitizers and a fuzzer.** ASan, UBSan, MemorySanitizer, Valgrind and
  `_FORTIFY_SOURCE=3` are clean, and a libFuzzer campaign aimed at the
  decoders found nothing. The harness is built to mutate *valid* objects,
  because random bytes never reach the decoders at all.

None of this is an audit, and none of it proves the absence of a defect;
`doc/TESTING.md` lists what was not tested.

## Requirements

- A C99 compiler with the exact-width integer types (`stdint.h`). GCC and
  Clang are tested; the code uses an optional empty `asm` barrier on those
  two and plain C99 elsewhere.
- Two's complement integers and an arithmetic right shift on negative
  signed values. C99 leaves both implementation-defined; every compiler in
  use provides them, and C23 requires them. They are used for the
  branch-free sign masks in the lattice code and in the Edwards
  arithmetic.
- About 54 KiB of stack for ML-DSA-44 signing, 37 KiB for key generation,
  35 KiB for verification, 12 KiB for ML-KEM encapsulation, and under
  3 KiB for everything in the classical layer. These are GCC's reported
  `-fstack-usage` frames, with the reference cores fully inlined.

No part of the library allocates, locks, or keeps state between calls, so
all functions may be called concurrently on distinct buffers.

## Constant time

Secrets are the keys, the seeds, the shared secrets, the per-signature
values, and the plaintext. No branch and no memory index in the library
depends on them, with these exceptions, all of which are inherited from
the standards or the reference code and are documented in
[`doc/DESIGN.md`](doc/DESIGN.md#constant-time-discipline):

- **ML-KEM** expands the public matrix by rejection sampling on a seed
  that is part of the public key. FIPS 203 states this is safe.
- **ML-DSA** rejection sampling (`rej_uniform`, `rej_eta`) stops when it
  has enough coefficients, so its iteration count depends on secret
  random bytes; the challenge decoding and the signing rejection loop do
  the same, and FIPS 204's security analysis accounts for both.
- **Argon2d and Argon2id** index memory with data-dependent addresses by
  design. Use Argon2i if that matters to you.
- `ncrypt_aead_read` branches on the result of the tag comparison, and
  `ncrypt_elligator_rev` reports whether a point has a representative.
  Both are single, final branches on values the caller must learn anyway.

`make ct` enforces exactly this list: any new secret-dependent branch or
access anywhere else in the library fails the run. What it cannot see is
compiler-induced leakage (a mask turned into a branch, or a secret spilled
to an address) on some future compiler, or physical side channels such as
power analysis. The hedged ML-DSA variant reduces the latter but does not
remove it.

## Limitations

- ML-KEM-768 and ML-DSA-44 only. The cores support the other FIPS 203 and
  FIPS 204 parameter sets, but the public API fixes these two.
- No HashML-DSA (pre-hash) variant, and no streaming interface for
  signatures: the message must be in memory. For large inputs, sign a hash
  and identify the hash in the context string.
- The hybrid construction provides confidentiality but no sender
  authentication. Sign the record if you need it.
- No X25519/ML-KEM hybrid key exchange is built in; both primitives are
  available, so combining them in your own KDF is a few lines.
- The lattice code is the portable reference implementation: correct and
  constant-time by construction, several times slower than the vectorised
  ones.

## Documentation

| Document | Contents |
| --- | --- |
| [`doc/API.md`](doc/API.md) | Every public function: arguments, sizes, return values, failure behaviour, randomness requirements, wire formats. |
| [`doc/DESIGN.md`](doc/DESIGN.md) | How the library is built and why: seed handling, input checks, the hybrid construction, constant-time discipline, memory hygiene, portability, limitations. |
| [`doc/TESTING.md`](doc/TESTING.md) | The test programs, vector provenance, the constant-time harness, the build configurations that were verified, and what is *not* tested. |
| [`doc/PROVENANCE.md`](doc/PROVENANCE.md) | Upstream sources, exact revisions, and the complete list of local changes. |
| [`doc/REVIEW.md`](doc/REVIEW.md) | Two review passes: what was checked, the twelve findings and their disposition, and the open items. |

## License

libncrypt is released under the **Anonymous Public Domain License,
version 1.0**. The full text is in [`LICENSE`](LICENSE); it is reproduced
there in full and is not summarised away, so read it. In outline:

- The licensor (the "Affirmer", who applies the license anonymously)
  **waives copyright and related rights** in the work, worldwide, for the
  full term, for any purpose, irrevocably — including commercial use and
  use as training data or for other machine-learning work.
- Where a waiver is not effective, a **fallback license** (§4) grants the
  same permissions: royalty-free, non-exclusive, transferable,
  sublicensable, irrevocable, unconditional.
- **No attribution is required.** You need not name anyone, keep any
  notice, or indicate changes. There is no one to name.
- **No warranty.** The work is provided as-is, and the licensor is not
  liable for loss or damage arising from its use, to the extent the law
  allows.

Three limits are worth stating explicitly, because they are limitations of
the license rather than conditions of it (§8(a)):

1. **Patent, trademark, privacy and trade-secret rights are not granted.**
   Only copyright and related rights, and moral rights, are addressed.
2. **It does not clear third-party rights.** This repository contains
   code derived from other projects; those components are public domain
   (CC0-1.0) as described below, and their terms are unaffected by this
   license.
3. **It is not legal advice,** and its effect varies by jurisdiction. If
   you need certainty, take advice.

The license applies to this project's own work — the contents of this
repository — and claims nothing about the third-party components, which
are public domain in their own right:

| Component | Upstream license |
| --- | --- |
| Monocypher 4.0.3 | CC0-1.0, with a BSD-2-Clause fallback |
| CRYSTALS-Kyber and CRYSTALS-Dilithium reference implementations | CC0-1.0, with Apache-2.0 (and, for Dilithium, GPL-2.0) fallbacks |
| FIPS 202 (Keccak) as shipped with both | public domain |
| NIST ACVP test vectors | US Government work |

Every one of those components is available under CC0-1.0 or is already
public domain, so a redistributor of this tree can satisfy them without
conditions and without reproducing an attribution notice. Nothing here is
distributed under GPL. `doc/PROVENANCE.md` records the exact upstream
revisions and, where a fallback notice exists upstream, says where to find
it — a redistributor who prefers a fallback license should take the notice
from the upstream repository, because the notice is a condition of the
fallback and not of CC0.
