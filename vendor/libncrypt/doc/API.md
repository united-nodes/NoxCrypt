# libncrypt API reference

This document is the reference for the post-quantum interface declared
in `ncrypt-pqc.h`. The classical interface in `ncrypt.h` is a
prefix-renamed copy of Monocypher 4.0.3 and is documented at the end by
reference to the Monocypher manual.

Contents:

1. [Conventions](#conventions)
2. [Sizes](#sizes)
3. [ML-KEM-768](#ml-kem-768)
4. [ML-DSA-44](#ml-dsa-44)
5. [Hybrid public-key encryption](#hybrid-public-key-encryption)
6. [High-level aliases](#high-level-aliases)
7. [Randomness](#randomness)
8. [Wire formats](#wire-formats)
9. [Version](#version)
10. [Classical layer](#classical-layer)

## Conventions

The following rules apply to every function in `ncrypt-pqc.h` unless a
function's own section says otherwise.

**Buffer sizes.** Fixed-size arguments are declared with their exact
size in the prototype (for example `uint8_t public_key[1184]`) and the
same value is available as a named constant (`NCRYPT_MLKEM768_PUBLIC_KEY_SIZE`).
C does not check array parameter bounds; the caller is responsible for
providing storage of exactly that size. Variable-length arguments come
with an explicit `size_t` length.

**Null pointers.** A pointer may be null only when its associated length
is zero. Fixed-size arguments must never be null.

**Overlap.** Input and output buffers must not overlap, except that
`ncrypt_pqc_encrypt` and `ncrypt_pqc_decrypt` permit `cipher_text` and
`plain_text` to be the same buffer (in-place operation). Overlapping
buffers in any other combination are undefined behaviour.

**Return values.** Functions returning `int` return exactly `0` on
success and exactly `-1` on failure, never any other value. This is a
guarantee, not a convenience: `mldsa_verdict()` normalises every internal
result, so `if (f(...) == -1)` and `if (f(...) != 0)` are equivalent and
both are safe. Functions returning `void` cannot fail.

**Failure semantics.** When a function fails, its output buffers are left
unmodified. Seeds and randomness inputs are always wiped, on success and
on failure alike. Callers can therefore rely on the following pattern:

```c
if (ncrypt_pqc_decrypt(pt, kem_ct, mac, sk, ad, ad_len, ct, ct_len) != 0) {
	/* pt is untouched; the record was forged or corrupted */
}
```

**Seeds are consumed.** Every `seed` and `rnd` argument is declared
non-`const` because the function overwrites it with zeros before
returning. Pass a copy if the value is needed afterwards. This design,
inherited from Monocypher, makes accidental seed reuse visible in the
code: a wiped seed cannot silently be used twice.

**Memory.** No function allocates memory or keeps state between calls.
The largest stack frame is ML-DSA-44 signing at about 54 KiB (as measured
by GCC's `-fstack-usage` with the reference cores inlined); ML-DSA key
generation needs about 37 KiB, verification about 35 KiB, ML-KEM
encapsulation about 12 KiB, and no classical function exceeds 3 KiB.

**Thread safety.** All functions are reentrant. They read only their
arguments and constant tables.

**Timing.** Operations on secret data are implemented without
secret-dependent branches or memory indices, to the extent that C
permits, and `make ct` checks this under Valgrind after every change. The
exceptions — rejection sampling in ML-KEM and ML-DSA, the ML-DSA signing
rejection loop, Argon2's data-dependent addressing, and the two final
branches on values the caller must learn anyway — are enumerated in
[`DESIGN.md`](DESIGN.md#constant-time-discipline) and in
`tests/ct.supp`. Compiler-induced leakage and physical side channels are
outside what the harness can see.


## Sizes

All sizes are in bytes. The constants are defined in `ncrypt-pqc.h`.

| Constant | Value | Meaning |
| --- | ---: | --- |
| `NCRYPT_MLKEM768_PUBLIC_KEY_SIZE` | 1184 | ML-KEM-768 encapsulation key |
| `NCRYPT_MLKEM768_SECRET_KEY_SIZE` | 2400 | ML-KEM-768 decapsulation key |
| `NCRYPT_MLKEM768_CIPHERTEXT_SIZE` | 1088 | ML-KEM-768 ciphertext |
| `NCRYPT_MLKEM768_SHARED_SECRET_SIZE` | 32 | ML-KEM-768 shared secret |
| `NCRYPT_MLKEM768_KEY_SEED_SIZE` | 64 | Key generation seed (`d || z`) |
| `NCRYPT_MLKEM768_ENCAPS_SEED_SIZE` | 32 | Encapsulation seed (`m`) |
| `NCRYPT_MLDSA44_PUBLIC_KEY_SIZE` | 1312 | ML-DSA-44 verification key |
| `NCRYPT_MLDSA44_SECRET_KEY_SIZE` | 2560 | ML-DSA-44 signing key |
| `NCRYPT_MLDSA44_SIGNATURE_SIZE` | 2420 | ML-DSA-44 signature |
| `NCRYPT_MLDSA44_KEY_SEED_SIZE` | 32 | Key generation seed (`xi`) |
| `NCRYPT_MLDSA44_RND_SIZE` | 32 | Per-signature randomness (`rnd`) |
| `NCRYPT_MLDSA44_MAX_CONTEXT_SIZE` | 255 | Longest permitted context string |
| `NCRYPT_PQC_KEM_CT_SIZE` | 1088 | Same as the ML-KEM ciphertext |
| `NCRYPT_PQC_MAC_SIZE` | 16 | Poly1305 authentication tag |
| `NCRYPT_PQC_SEED_SIZE` | 32 | Same as the encapsulation seed |

## ML-KEM-768

ML-KEM-768 is the key encapsulation mechanism specified in NIST FIPS 203
at the parameter set with `k = 3`. It offers NIST security category 3.
The three functions below implement `ML-KEM.KeyGen_internal`,
`ML-KEM.Encaps_internal`, and `ML-KEM.Decaps_internal` together with the
input checks that FIPS 203 section 7 requires of the outer algorithms.
The randomness that the outer algorithms would draw is supplied by the
caller instead; see [Randomness](#randomness).

### `ncrypt_mlkem768_key_pair`

```c
void ncrypt_mlkem768_key_pair(uint8_t secret_key[2400],
                              uint8_t public_key[1184],
                              uint8_t seed      [64]);
```

Derives a key pair from `seed`. The first 32 bytes of the seed are the
FIPS 203 value `d`, from which the lattice secret is expanded; the last
32 bytes are `z`, which is stored inside the secret key and used for
implicit rejection during decapsulation. Both halves must be uniformly
random and secret. The seed is wiped.

The same seed always produces the same key pair. This is useful for
tests and for deriving keys from a master secret with a KDF, but a seed
that is used for key generation must not be used for anything else.

### `ncrypt_mlkem768_encapsulate`

```c
int ncrypt_mlkem768_encapsulate(uint8_t       ciphertext   [1088],
                                uint8_t       shared_secret[32],
                                const uint8_t public_key   [1184],
                                uint8_t       seed         [32]);
```

Produces a ciphertext for the holder of `public_key` and the 32-byte
shared secret that the holder will recover from it. `seed` is the FIPS
203 value `m`; it must be uniformly random and is wiped.

Before encapsulating, the function performs the FIPS 203 encapsulation
key check: every 12-bit coefficient of the encoded public key must be
smaller than the modulus `q = 3329`. A key that fails the check causes
the function to return `-1` with `ciphertext` and `shared_secret` left
untouched. Public keys produced by `ncrypt_mlkem768_key_pair` always
pass. The check exists to reject keys that were corrupted in transit or
crafted to be non-canonical.

Encapsulation is deterministic in `(public_key, seed)`: reusing a seed
with the same public key reproduces the same ciphertext and shared
secret. Applications must therefore generate a fresh seed for every
call.

### `ncrypt_mlkem768_decapsulate`

```c
int ncrypt_mlkem768_decapsulate(uint8_t       shared_secret[32],
                                const uint8_t ciphertext   [1088],
                                const uint8_t secret_key   [2400]);
```

Recovers the shared secret from a ciphertext.

The function first performs the FIPS 203 decapsulation key check: the
SHA3-256 hash of the public key embedded in `secret_key` must match the
hash stored alongside it. A mismatch indicates a corrupted or
inconsistent secret key; the function returns `-1` and leaves
`shared_secret` untouched.

A malformed or forged ciphertext is deliberately not reported. As FIPS
203 requires, decapsulation always succeeds and yields a shared secret;
when the ciphertext is not the one that was encapsulated, that secret is
a pseudorandom function of `z` and the ciphertext (implicit rejection)
and is unrelated to what the sender holds. Two consequences follow:

- An attacker cannot learn from the return value whether a ciphertext
  was accepted. This is what protects the scheme against chosen
  ciphertext attacks.
- The application must authenticate whatever it derives from the shared
  secret before acting on it. The hybrid functions below do this with an
  AEAD tag.

## ML-DSA-44

ML-DSA-44 is the digital signature algorithm specified in NIST FIPS 204
at the smallest parameter set, offering NIST security category 2 with
2420-byte signatures. The functions implement the "pure" ML-DSA
interface (`ML-DSA.Sign` and `ML-DSA.Verify` with a context string, no
pre-hashing).

### `ncrypt_mldsa44_key_pair`

```c
void ncrypt_mldsa44_key_pair(uint8_t secret_key[2560],
                             uint8_t public_key[1312],
                             uint8_t seed      [32]);
```

Derives a key pair from the 32-byte seed `xi`. The seed must be
uniformly random and secret; it is wiped. Key generation is
deterministic in the seed.

### `ncrypt_mldsa44_sign`

```c
int ncrypt_mldsa44_sign(uint8_t        signature [2420],
                        const uint8_t  secret_key[2560],
                        uint8_t        rnd       [32],
                        const uint8_t *context, size_t context_size,
                        const uint8_t *message, size_t message_size);
```

Signs `message` under `secret_key` using the hedged variant of ML-DSA,
which FIPS 204 designates as the default. `rnd` must hold 32 fresh random
bytes. They are mixed with the secret key and the message into the
per-signature nonce, so that the signature remains secure if either the
random source or the deterministic derivation is weak, and so that two
signatures over the same message differ. Signatures of the same message
therefore vary from call to call. `rnd` is wiped.

`context` is an optional domain-separation string of at most 255 bytes.
It is not included in the signature; the verifier must supply the same
value. Pass `NULL` and `0` for no context. If `context_size` exceeds
`NCRYPT_MLDSA44_MAX_CONTEXT_SIZE`, the function returns `-1`, leaves
`signature` untouched, and still wipes `rnd`. This is the only failure
condition.

`message` may be empty (`NULL`, `0`) and has no upper size limit.

### `ncrypt_mldsa44_sign_deterministic`

```c
int ncrypt_mldsa44_sign_deterministic(uint8_t        signature [2420],
                                      const uint8_t  secret_key[2560],
                                      const uint8_t *context, size_t context_size,
                                      const uint8_t *message, size_t message_size);
```

Identical to `ncrypt_mldsa44_sign` with `rnd` set to 32 zero bytes,
which is the deterministic variant permitted by FIPS 204 section 3.4.
The same key and message always produce the same signature. FIPS 204
notes that the deterministic variant is more exposed to fault attacks
and to some side-channel attacks on the signing device; prefer the
hedged function unless reproducible signatures are a requirement (test
vectors, reproducible builds, or devices with no random source at
signing time). Verification does not distinguish the two variants.

### `ncrypt_mldsa44_check`

```c
int ncrypt_mldsa44_check(const uint8_t  signature [2420],
                         const uint8_t  public_key[1312],
                         const uint8_t *context, size_t context_size,
                         const uint8_t *message, size_t message_size);
```

Returns `0` if `signature` is a valid signature of `message` under
`public_key` with the given `context`, and `-1` otherwise. A context
longer than 255 bytes is rejected with `-1`.

The signature encoding is checked strictly as FIPS 204 requires:
non-canonical hint encodings and out-of-range `z` coefficients are
rejected. As a result ML-DSA-44 signatures are strongly unforgeable; an
attacker who sees a valid signature cannot produce a different valid
signature for the same message.

## Hybrid public-key encryption

`ncrypt_pqc_encrypt` and `ncrypt_pqc_decrypt` combine ML-KEM-768 with
XChaCha20-Poly1305 into a public-key authenticated encryption scheme
(a KEM/DEM construction). The sender needs only the recipient's public
key; there is no sender authentication. See `doc/DESIGN.md` for the
derivation and its rationale.

### `ncrypt_pqc_encrypt`

```c
int ncrypt_pqc_encrypt(uint8_t       *cipher_text,
                       uint8_t        mac             [16],
                       uint8_t        kem_ct          [1088],
                       const uint8_t  their_public_key[1184],
                       uint8_t        seed            [32],
                       const uint8_t *ad,         size_t ad_size,
                       const uint8_t *plain_text, size_t text_size);
```

Encrypts `plain_text` for the holder of `their_public_key`. The function
performs the following steps:

1. Encapsulates a fresh shared secret to `their_public_key` with
   `ncrypt_mlkem768_encapsulate`, using `seed`, and writes the KEM
   ciphertext to `kem_ct`.
2. Derives a 32-byte key and a 24-byte nonce from the shared secret and
   `kem_ct` with keyed BLAKE2b (see `doc/DESIGN.md`).
3. Encrypts `plain_text` with XChaCha20-Poly1305 under that key and
   nonce, authenticating `ad` and the ciphertext, and writes the
   ciphertext to `cipher_text` (same length as the plaintext) and the
   tag to `mac`.

The recipient needs `kem_ct`, `mac`, `cipher_text`, and `ad`. The
associated data is authenticated but not transmitted by this function;
transport it separately or agree on it in advance. `ad` may be empty.

`seed` must be 32 fresh, uniformly random bytes and is wiped. The key
and nonce used in step 3 are functions of the encapsulation, so they are
unique exactly when the encapsulation is. Reusing a seed with the same
recipient key reproduces the same KEM ciphertext, key, and nonce, and
thus the same keystream, which reveals the XOR of the two plaintexts.
This is the single most important requirement of the interface.

Returns `0` on success. Returns `-1` if `their_public_key` fails the
FIPS 203 encapsulation key check; in that case `cipher_text`, `mac`, and
`kem_ct` are untouched and `seed` is wiped.

`cipher_text` may be the same buffer as `plain_text`.

### `ncrypt_pqc_decrypt`

```c
int ncrypt_pqc_decrypt(uint8_t       *plain_text,
                       const uint8_t  kem_ct     [1088],
                       const uint8_t  mac        [16],
                       const uint8_t  secret_key [2400],
                       const uint8_t *ad,          size_t ad_size,
                       const uint8_t *cipher_text, size_t text_size);
```

Reverses `ncrypt_pqc_encrypt`. It decapsulates `kem_ct`, derives the
same key and nonce, verifies `mac` over `ad` and `cipher_text`, and only
then writes the plaintext.

Returns `0` and fills `plain_text` on success. Returns `-1`, with
`plain_text` untouched, when:

- `secret_key` fails the FIPS 203 decapsulation key check, or
- authentication fails, which covers any modification of `kem_ct`,
  `mac`, `cipher_text`, or `ad`, a truncated ciphertext, and a
  ciphertext that was encrypted for a different key.

The two causes are intentionally not distinguished. In particular, a
modified `kem_ct` does not produce an error in the KEM step (implicit
rejection yields a wrong key instead); it is caught by the MAC.

`plain_text` may be the same buffer as `cipher_text`. On failure the
buffer is not modified even in the in-place case.

## High-level aliases

For applications that only need one algorithm choice, the following
functions fix the parameters:

```c
void ncrypt_pqc_key_pair     (uint8_t secret_key[2400], uint8_t public_key[1184], uint8_t seed[64]);
void ncrypt_pqc_sign_key_pair(uint8_t secret_key[2560], uint8_t public_key[1312], uint8_t seed[32]);
void ncrypt_pqc_sign (uint8_t signature[2420], const uint8_t secret_key[2560], uint8_t rnd[32],
                      const uint8_t *message, size_t message_size);
int  ncrypt_pqc_check(const uint8_t signature[2420], const uint8_t public_key[1312],
                      const uint8_t *message, size_t message_size);
```

`ncrypt_pqc_key_pair` is `ncrypt_mlkem768_key_pair`;
`ncrypt_pqc_sign_key_pair` is `ncrypt_mldsa44_key_pair`;
`ncrypt_pqc_sign` is hedged `ncrypt_mldsa44_sign` with an empty context
(it cannot fail, hence the `void` return); `ncrypt_pqc_check` is
`ncrypt_mldsa44_check` with an empty context.

Encryption keys and signing keys are different objects with different
sizes; never derive both from one seed.

## Randomness

libncrypt does not read `/dev/urandom`, `getrandom()`, `BCryptGenRandom()`,
or any other system source. This keeps the library portable and free of
hidden failure modes, but it moves a responsibility to the caller. Every
`seed` and `rnd` argument must come from a cryptographically secure
random number generator provided by the operating system. Examples:

- Linux: `getrandom(buf, len, 0)`, or `/dev/urandom`.
- OpenBSD, FreeBSD, macOS: `arc4random_buf(buf, len)`.
- Windows: `BCryptGenRandom(NULL, buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG)`.

Do not use `rand()`, `random()`, time stamps, or hashes of predictable
values. Do not derive an encapsulation seed from the message. If an
application derives seeds from a master secret with a KDF, each seed
must carry a unique label or counter so that no two calls share a seed.

The consequences of a weak or repeated seed differ by function:

| Function | Seed reuse or predictability results in |
| --- | --- |
| `*_key_pair` | The attacker can recompute the secret key. |
| `ncrypt_mlkem768_encapsulate` | The attacker can recompute the shared secret. |
| `ncrypt_pqc_encrypt` | Keystream reuse between the affected messages; the attacker learns the XOR of the plaintexts and can forge tags for them. |
| `ncrypt_mldsa44_sign` (`rnd`) | Degrades to the deterministic variant. Signatures remain unforgeable but lose the hedging against fault attacks. |

## Wire formats

All encodings are those of FIPS 203 and FIPS 204 and are interoperable
with any conforming implementation:

- ML-KEM-768 encapsulation key: `ByteEncode_12(t) || rho`, 1184 bytes.
- ML-KEM-768 decapsulation key: `dk_PKE || ek || H(ek) || z`, 2400 bytes.
- ML-KEM-768 ciphertext: `ByteEncode_10(c1) || ByteEncode_4(c2)`, 1088 bytes.
- ML-DSA-44 public key: `rho || t1`, 1312 bytes.
- ML-DSA-44 private key: `rho || K || tr || s1 || s2 || t0`, 2560 bytes.
- ML-DSA-44 signature: `c_tilde || z || h`, 2420 bytes.

The hybrid record has no fixed framing. A common layout is
`kem_ct (1088) || mac (16) || cipher_text (n)`, with the associated data
carrying whatever header the protocol needs. The KDF label
`"ncrypt-pqc-v1"` is part of the key derivation and would change if the
construction ever changed, so records from a future version would fail
authentication rather than decrypt incorrectly.

## Version

`NCRYPT_VERSION` in `ncrypt.h` is the library version as a string
(`"1.0.0"`). It changes when the code changes; the wire formats are fixed
by the FIPS standards and do not carry a version. The number is a

## Classical layer

`ncrypt.h` declares the Monocypher 4.0.3 API with the `crypto_` prefix
replaced by `ncrypt_` and the `CRYPTO_` prefix by `NCRYPT_`. Monocypher's
optional Ed25519, SHA-512, HMAC-SHA-512 and HKDF-SHA-512 module is merged
into the same header. Apart from the rename and the changes listed in
`doc/PROVENANCE.md` (none of which touch cryptographic code), the
Monocypher manual is the authoritative reference for these functions:

| Family | Functions | Manual page |
| --- | --- | --- |
| Authenticated encryption | `ncrypt_aead_lock`, `ncrypt_aead_unlock`, `ncrypt_aead_init_*`, `ncrypt_aead_write`, `ncrypt_aead_read` | <https://monocypher.org/manual/aead> |
| Hashing | `ncrypt_blake2b*` | <https://monocypher.org/manual/blake2b> |
| Password hashing | `ncrypt_argon2` | <https://monocypher.org/manual/argon2> |
| Key exchange | `ncrypt_x25519*` | <https://monocypher.org/manual/x25519> |
| Signatures | `ncrypt_eddsa_*` | <https://monocypher.org/manual/eddsa> |
| Ed25519 and SHA-512 | `ncrypt_ed25519_*`, `ncrypt_sha512*` | <https://monocypher.org/manual/ed25519>, <https://monocypher.org/manual/sha512> |
| Hiding keys | `ncrypt_elligator_*`, `ncrypt_x25519_dirty_*` | <https://monocypher.org/manual/elligator>, <https://monocypher.org/manual/x25519> |
| Low level | `ncrypt_chacha20_*`, `ncrypt_poly1305*`, `ncrypt_verify*`, `ncrypt_wipe` | <https://monocypher.org/manual/chacha20>, <https://monocypher.org/manual/poly1305>, <https://monocypher.org/manual/verify>, <https://monocypher.org/manual/wipe> |

Monocypher's caveats carry over unchanged. In particular
`ncrypt_aead_lock` requires a unique nonce per key, `ncrypt_x25519`
output must be hashed before use as a key, and `ncrypt_poly1305` is a
one-time authenticator.
