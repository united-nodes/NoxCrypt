# Design

This document explains how libncrypt is put together and why. It is
written for readers who want to review the code or make an informed
decision about using it; the function-level contract is in
`doc/API.md`.

Contents:

1. [Goals](#goals)
2. [Layout](#layout)
3. [Randomness and seeds](#randomness-and-seeds)
4. [FIPS 202](#fips-202)
5. [ML-KEM-768](#ml-kem-768)
6. [ML-DSA-44](#ml-dsa-44)
7. [Hybrid encryption](#hybrid-encryption)
8. [Constant-time discipline](#constant-time-discipline)
9. [Memory hygiene](#memory-hygiene)
10. [Integer conversions and portability](#integer-conversions-and-portability)
11. [Stack usage](#stack-usage)
12. [Limitations](#limitations)
13. [References](#references)

## Goals

libncrypt exists to give small C programs a post-quantum key
encapsulation mechanism and a post-quantum signature scheme with the
same character as Monocypher: two source files, no dependencies beyond
the C99 standard library, no allocation, no global state, and an
interface small enough to read in one sitting. The design decisions
below follow from four priorities, in order:

1. Correctness against the FIPS 203 and FIPS 204 test vectors.
2. No secret-dependent control flow or memory access.
3. An interface that is hard to misuse.
4. Portability to any conforming C99 compiler.

Performance is not a goal. The lattice code is the portable reference
implementation, which is adequate for handshakes and signatures but is
several times slower than vectorised implementations.

## Layout

```
ncrypt.h, ncrypt.c          classical layer (Monocypher 4.0.3, renamed)
ncrypt-pqc.h, ncrypt-pqc.c  post-quantum layer
tests/                      test programs and vectors
doc/                        this documentation
```

`ncrypt-pqc.c` is one translation unit with four sections, each of which
depends only on the ones above it:

1. FIPS 202: Keccak-f[1600], SHAKE128, SHAKE256, SHA3-256, SHA3-512.
2. ML-KEM-768: the pq-crystals/kyber reference core.
3. ML-DSA-44: the pq-crystals/dilithium reference core.
4. Public API: input checks, seed handling, wiping, and the hybrid
   construction, which calls into `ncrypt.c` for BLAKE2b and
   XChaCha20-Poly1305.

Every symbol in sections 1 to 3 is `static` and carries an `mlkem_`,
`mldsa_`, or FIPS 202 prefix. A program can therefore link libncrypt
next to another copy of Kyber, Dilithium, or a Keccak library without
symbol clashes, and the compiler sees the whole call graph, which lets
it inline the small polynomial helpers without link-time optimisation.

The dependency on `ncrypt.c` is confined to section 4. Sections 1 to 3
could be extracted and used with a different symmetric layer by
replacing the `ncrypt_wipe()` calls.

## Randomness and seeds

The library never reads a system random source. Functions that need
randomness take it as an argument, and every such argument is overwritten
with zeros before the function returns. This is Monocypher's
convention, and it has three properties that a hidden `randombytes()`
call lacks:

- There is no way for random generation to fail silently inside the
  library. The caller obtains randomness from the operating system,
  where failure is observable and can be handled.
- Deterministic testing needs no special build. The ACVP vectors feed
  their `d`, `z`, `m`, `xi`, and `rnd` values straight into the public
  functions.
- Seed reuse is visible at the call site. A wiped buffer cannot be
  passed twice by mistake; it would have to be refilled deliberately.

The cost is that the caller must supply good randomness, which
`doc/API.md` documents in detail.

## FIPS 202

The Keccak code is the compact public domain implementation that both
CRYSTALS reference repositories ship. It keeps the state as 25 64-bit
lanes and processes one rate-sized block per permutation call. The only
change is that two narrowing conversions carry explicit casts.

ML-KEM and ML-DSA use the four functions as FIPS 203 and FIPS 204
prescribe: SHAKE128 for matrix expansion (`XOF`), SHAKE256 for the
pseudorandom functions and the KDF (`PRF`, `H`, `J`, `G` as applicable),
and SHA3-256 and SHA3-512 for hashing in ML-KEM. No other hash is
involved in the post-quantum primitives; BLAKE2b appears only in the
hybrid construction.

## ML-KEM-768

The core is the pq-crystals `ref/` implementation, which is the code the
FIPS 203 vectors were generated against. libncrypt keeps only the
deterministic entry points (`keypair_derand`, `enc_derand`, `dec`).

### Input checks

FIPS 203 section 7 requires two checks that the reference code leaves to
the caller. Both are implemented in the public wrappers:

- **Encapsulation key check** (7.2). The 1152-byte `t` component of the
  public key is decoded into 768 twelve-bit coefficients, and each is
  compared against `q = 3329`. The public key is public, so the check
  uses ordinary branches. Failure returns `-1` without producing a
  ciphertext. Without this check, a non-canonical key would still
  encapsulate, but the resulting ciphertext would be tied to a key
  representation the recipient may not accept, which can leak
  information about the recipient's behaviour.
- **Decapsulation key check** (7.3). The SHA3-256 hash of the embedded
  public key must equal the stored `H(ek)`. Because `H(ek)` is what the
  Fujisaki-Okamoto transform mixes into the shared secret, a mismatch
  would silently produce shared secrets the sender cannot reproduce.
  The comparison uses `ncrypt_verify32()`, and the branch on its result
  reveals only whether the caller's own secret key is self-consistent —
  a value the caller already learns from the return value.

### Implicit rejection

Decapsulation never reports a bad ciphertext. The reference code decrypts
the ciphertext, re-encrypts the result with the coins derived from it,
and compares the re-encryption with the input in constant time. If they
differ, the shared secret is replaced by `J(z || c)`, a pseudorandom
value that depends on the rejection secret `z`. The selection is a
constant-time conditional move.

This design is what makes ML-KEM IND-CCA2 secure. An implementation that
returned an error on mismatch would give an attacker an oracle for
chosen-ciphertext attacks. Applications get the confirmation they need
from the AEAD tag in the hybrid construction, or from whatever
authentication their own protocol provides.

### Rejection sampling

`mlkem_gen_matrix` expands the public seed `rho` into the matrix `A` by
rejection sampling on SHAKE128 output. The loop count depends on `rho`,
which is part of the public key. This is the only data-dependent loop in
ML-KEM and FIPS 203 explicitly identifies it as safe.

## ML-DSA-44

The core is the pq-crystals `ref/` implementation of the final FIPS 204
algorithm, including the domain-separated message representative
(`mu = H(tr || 0 || |ctx| || ctx || M)`).

### Hedged and deterministic signing

FIPS 204 section 3.4 defines the per-signature seed as
`rho' = H(K || rnd || mu)` with `rnd` either 32 random bytes (hedged,
the default) or 32 zero bytes (deterministic). libncrypt exposes both.

The hedged variant is the default because its randomness is a defence,
not a dependency. If `rnd` is perfect, the signature is randomised and
two signatures of one message differ, which limits what a fault
injection or power-analysis attacker can learn from repeated signing.
If `rnd` is weak or repeated, security falls back to that of the
deterministic variant, which is still unforgeable; the derivation
includes `K` and `mu`, so a bad `rnd` cannot produce the nonce reuse
failures that plagued ECDSA. The variant is recorded nowhere in the
signature and the verifier does not need to know it.

The deterministic function is provided for test vectors and for
environments without a random source at signing time. Its documentation
states the fault-attack trade-off.

### Signature encoding checks

Verification decodes the signature with `mldsa_unpack_sig`, which
rejects hint vectors whose indices are out of order or exceed `omega`,
and checks `||z||_inf < gamma1 - beta` before doing any arithmetic.
These checks are what give ML-DSA strong unforgeability and they are the
part of the verifier most exposed to malformed input; the fuzz harness
targets them specifically.

The final comparison between the recomputed challenge and the one in
the signature is done with a constant-time comparison. The values are
public, so this is a matter of uniformity rather than necessity.

### Rejection sampling

The signing loop restarts when `z` or `r0` is out of range, when `ct0`
is too large, or when the hint weight exceeds `omega`. The FIPS 204
security analysis relies on the distribution of the accepted signature
being independent of the secret, and on the number of iterations being
uninformative; the reference implementation follows the specification
exactly, and libncrypt does not alter the loop.

## Hybrid encryption

`ncrypt_pqc_encrypt` and `ncrypt_pqc_decrypt` implement a KEM/DEM
public-key encryption scheme:

```
(kem_ct, ss)   = ML-KEM-768.Encaps(pk; seed)
key || nonce   = BLAKE2b-448(key = ss, msg = "ncrypt-pqc-v1" || kem_ct)
(ct, mac)      = XChaCha20-Poly1305.Seal(key, nonce, ad, pt)
```

Each design decision addresses a specific concern.

**Why a KDF at all.** ML-KEM's shared secret is already uniformly
distributed and could key ChaCha20 directly. Hashing it with `kem_ct`
binds the DEM key to the exact ciphertext the recipient received. If an
attacker replaces `kem_ct` with a different encapsulation to the same
key (which, through implicit rejection, yields an unrelated `ss`), the
derived key changes and the tag fails, as it would anyway; but the
binding also rules out any future scenario in which two different KEM
ciphertexts could yield the same `ss`. The label separates this
derivation from any other use the application may make of `ss`.

**Why the nonce is derived rather than fixed.** A constant nonce would be
safe only as long as the key is used once, and that is exactly the
property the construction relies on the caller to maintain. Deriving both
from the encapsulation does not relax the requirement — a repeated seed
still repeats everything — but it means the design has no fixed nonce to
become a hazard if a future change ever made the key reusable. BLAKE2b's
56-byte output fills the 32-byte key and the 24-byte nonce in one call.

**Why XChaCha20-Poly1305.** It is the AEAD Monocypher provides, it has
no length limits that matter here, and it is keyed by a single 32-byte
value with no key schedule to leak. The 24-byte nonce is larger than
needed given that the nonce is derived, but the cost is nil.

**Why no sender authentication.** A KEM/DEM scheme authenticates nothing
about the sender. Applications that need it should sign the record
(`kem_ct || mac || ct || ad`) with `ncrypt_pqc_sign` and verify the
signature before decrypting, or use a full protocol. Combining the
two primitives into a signcryption interface was considered and
rejected because the correct binding of identities to messages is
protocol-specific.

**Why `ad` is not transmitted.** As with every AEAD, the associated
data is authenticated but not encrypted or carried. This keeps the
function composable with any framing.

**Failure atomicity.** On the encryption side, a bad public key is
detected before any output is written. On the decryption side, the
decapsulation key check runs first and the plaintext buffer is written
only after the tag verifies; Monocypher's `ncrypt_aead_unlock` computes
the tag over the ciphertext before decrypting, so an in-place call that
fails leaves the ciphertext intact. That property is asserted by
`test_hybrid_tamper_in_place()`, which tampers with every component of a
record while the output buffer aliases the input, and it is not taken for
granted: it depends on the ordering inside a different function, so if
that ordering ever changes, the test fails rather than the application.

The verdict returned by decryption is normalised to exactly 0 or -1 by
`mldsa_verdict()`, so the documented contract does not depend on the
value an internal routine happens to return.

## Constant-time discipline

The rule is the one Monocypher follows: no branch and no memory index
depends on a secret. In the post-quantum layer the secrets are the seeds,
the ML-KEM decapsulation key and shared secret, the ML-DSA signing key and
the per-signature values (`rho'`, `y`, `z` before acceptance, `w0`, `cp`),
and the derived AEAD key.

### What is enforced, and how

`tests/test_ct.c` implements the ctgrind technique. Every secret buffer is
marked *undefined* with a Valgrind client request, and every public
function is then called under memcheck. Memcheck reports any branch, any
conditional move, and any load or store whose address depends on an
undefined value. `tests/ct.supp` lists the reports we have reviewed and
accepted; `make ct` fails if anything else is reported. The harness has a
negative control: a deliberately injected secret-dependent branch in a
function that should be constant time is caught, so the check is not
vacuous.

The library work done to satisfy it:

- `mlkem_verify` and `mlkem_cmov` compare and select the shared secret
  with bitwise masks, and an empty `asm` statement on GCC and Clang keeps
  the compiler from turning the mask into a branch or a pointer swap.
- The AEAD tag comparison is Monocypher's `ncrypt_verify16`, and the
  decapsulation key hash comparison is `ncrypt_verify32`.
- The ML-KEM polynomial decoders mask the decoded value before indexing
  the coefficient array, rather than writing `coeffs[i] = t & 0xFFF`.
  Both compute the same numbers; the second form leaves a value-dependent
  index expression in the source, which is exactly the shape that
  compilers have been observed to turn into a value-dependent address.
- The ML-DSA verifier's final challenge comparison is branch-free.
- `mldsa_verdict()` normalises every verifier result to 0 or -1 with
  unsigned arithmetic only, so the mapping itself neither overflows nor
  branches.

### Verdicts

Two functions report a verdict on attacker-supplied input:
`ncrypt_mldsa44_check` (through `ncrypt_pqc_check`) and
`ncrypt_pqc_decrypt`. Both return exactly 0 or -1, and both do so through
`mldsa_verdict()`, which maps any non-zero internal result to -1. The
reason is a contract, not a mechanism: the documentation says "compare
against -1", and an internal routine that returned any other negative
value would be read as success by code that follows the documentation.
The normalisation costs two instructions and removes the dependency.

Signatures are rejected as early as the encoding allows — a malformed
hint or an out-of-range `z` stops verification before the NTT — and that
early exit depends only on public bytes (the signature itself), never on
the secret. Verification is a public-data operation; its timing profile
is not sensitive.

### The exceptions, and why they are acceptable

These remain, are listed in `tests/ct.supp`, and are the subject of a
comment there:

- **ML-KEM matrix expansion.** `mlkem_rej_uniform` rejects 12-bit values
  above `q` while expanding the public seed `rho` into the matrix `A`. The
  loop count depends on `rho`, which is part of the public key. This is
  the only data-dependent loop in ML-KEM, and FIPS 203 identifies it as
  safe.
- **ML-DSA rejection sampling.** `mldsa_rej_uniform` and `rej_eta` squeeze
  SHAKE output until they have 256 coefficients, so the number of
  iterations reflects how many candidate values were rejected. The input
  is a secret seed. The rejection rate is a fixed property of the
  distribution, not of a particular secret, so the timing reveals only
  that a sample was accepted — which the reference implementations and the
  FIPS 204 analysis both treat as acceptable. The same applies to the
  challenge decoding in `mldsa_poly_challenge`, and to the signing loop
  that restarts when `z`, `r0` or the hint weight is out of range: FIPS
  204's security argument assumes the distribution of accepted signatures
  is independent of the secret and that the iteration count is
  uninformative.
- **Argon2.** Argon2d and Argon2id index the work area with
  data-dependent addresses by design; that is what makes them
  GPU-resistant. Argon2i (indexing derived from the pass counter) is
  available and is constant time.
- **Two final branches.** `ncrypt_aead_read` branches on the result of the
  tag comparison, and `ncrypt_elligator_rev` reports whether the point has
  a representative. Both act on a value the caller must learn anyway, and
  both leave the secret itself untouched.

### What this does not cover

- **Compiler-induced leakage on other compilers or versions.** The `asm`
  barriers and the value-masking style raise the cost of the known
  transformations, but C has no way to *specify* constant time. A future
  compiler can defeat any of it.
- **Microarchitectural effects.** Data-dependent timing in the multiplier
  pipelines of some processors, cache behaviour on variable-index table
  lookups in the classical code, and speculative execution are not
  addressed.
- **Physical side channels.** Power, electromagnetic emission and fault
  injection are out of scope. The hedged ML-DSA variant reduces exposure
  to fault attacks but does not remove it.

## Memory hygiene

Every function wipes, before returning, all stack storage that held a
secret or a value derived from one. This covers the reference cores as
well: the upstream code does not wipe, and the ported versions add
`ncrypt_wipe()` calls for the decrypted message polynomial and noise in
ML-KEM, and for the full set of per-signature values in ML-DSA
including those left behind by rejected iterations.

`ncrypt_wipe()` is Monocypher's volatile-write loop. It prevents the
compiler from removing the stores, but it cannot prevent the compiler
from having spilled copies to other stack slots or registers earlier.
This is a limit of what C can express, shared by every library of this
kind.

Caller-provided seeds are wiped for the reasons given under
[Randomness and seeds](#randomness-and-seeds). Caller-provided secret
keys are not: their lifetime belongs to the caller, who should wipe
them with `ncrypt_wipe()` when they are no longer needed.

## Integer conversions and portability

The library is written to C99 and assumes:

- `CHAR_BIT == 8`, and the exact-width types `uint8_t`, `int16_t`,
  `uint16_t`, `int32_t`, `uint32_t`, `int64_t`, and `uint64_t` exist.
- Signed integers use two's complement, and conversion of an
  out-of-range value to a signed type reduces modulo 2^N. C99 leaves
  this implementation-defined; every compiler in current use, and the
  C23 standard, define it this way. The reference lattice code relies
  on it in the Montgomery and Barrett reductions.
- Right shift of a negative signed integer is arithmetic. This is also
  implementation-defined in C99 and universal in practice. It is used
  for the branch-free sign-extension masks in the rounding functions.

Every conversion that narrows or changes signedness is written as an
explicit cast, and the compiler's `-Wconversion -Wsign-conversion`
diagnostics are clean (see `make strict`). Where a cast depends on a
bound that is not obvious, a comment states the bound. The point of this
exercise was not to satisfy the warning; it was to force each conversion
to be examined once and the reasoning recorded.

The code has no alignment requirements, no dependence on byte order (all
serialisation is explicit, byte by byte), no use of `long` or `int` for
sizes, and no variable-length arrays. It compiles without diagnostics for
32-bit targets (`-m32`) and runs the full test suite there, and both
headers compile as C++11 and C++17.

### Stack usage

Measured with GCC 14's `-fstack-usage` at `-O2`, with the reference cores
inlined:

| Operation | Frame |
| --- | ---: |
| ML-DSA-44 sign | 54 KiB |
| ML-DSA-44 key pair | 37 KiB |
| ML-DSA-44 verify | 35 KiB |
| ML-KEM-768 encapsulate | 12 KiB |
| ML-KEM-768 key pair | 9 KiB |
| ML-KEM-768 decapsulate | 4 KiB |
| Argon2 (largest classical) | 2.4 KiB |

ML-DSA needs the space because a signature is computed on four vectors of
four polynomials each, several of which are live at once. On systems with
small thread stacks, run signing on a thread with at least 64 KiB, or
give it its own thread.

## Limitations

- ML-KEM-768 and ML-DSA-44 are the only parameter sets exposed. The
  cores support the others, but the fixed-size interface would need
  separate functions and the test vectors separate files. A static
  check in `ncrypt-pqc.c` rejects any other parameter selection.
- The pre-hash ML-DSA variant (HashML-DSA) is not provided. The pure
  variant with a context string serves the same purpose in new
  designs.
- There is no streaming interface for signing or verification. The
  message must be in memory. For large inputs, sign a hash of the
  message and put the hash algorithm identifier in the context string.
- No X25519 or Ed25519 hybridisation is built in. Applications that want
  a classical fallback can combine an X25519 shared secret with the ML-KEM
  shared secret in a KDF; both primitives are available, and mixing them
  must be done carefully (concatenate both secrets and pass the result
  through a KDF, do not use the KEM secret as the only key).
- The hybrid construction is a KEM/DEM scheme for one recipient. There is
  no key transport, no key rotation, and no state: each message carries its
  own encapsulation.

## References

- NIST FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism
  Standard, August 2024.
- NIST FIPS 204, Module-Lattice-Based Digital Signature Standard,
  August 2024.
- NIST FIPS 202, SHA-3 Standard: Permutation-Based Hash and
  Extendable-Output Functions, August 2015.
- RFC 8439, ChaCha20 and Poly1305 for IETF Protocols; the XChaCha
  extension as implemented by Monocypher.
- RFC 7693, The BLAKE2 Cryptographic Hash and Message Authentication
  Code (MAC).
- pq-crystals/kyber and pq-crystals/dilithium reference implementations
  (revisions in `doc/PROVENANCE.md`).
- Monocypher 4.0.3 manual, <https://monocypher.org/manual/>.
