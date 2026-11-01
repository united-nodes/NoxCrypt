# Source provenance

Where every piece of third-party code in libncrypt comes from, the exact
upstream revision, and what was changed. Keep this file up to date
whenever an upstream component is refreshed. The licensing statement is
in the [README](../README.md#license); the upstream notices that are
relevant to redistribution are reproduced at the end of this file.

## Summary

| Component | Files | Upstream | Revision | Upstream license |
| --- | --- | --- | --- | --- |
| Classical primitives | `ncrypt.c`, `ncrypt.h` | Monocypher 4.0.3 | tag `4.0.3` | CC0-1.0, BSD-2-Clause fallback |
| Classical test program and vectors | `tests/test_classic.c`, `tests/classic_utils.h`, `tests/classic_vectors.h` | Monocypher 4.0.3 test suite | tag `4.0.3` | CC0-1.0, BSD-2-Clause fallback |
| ML-KEM-768 core | `ncrypt-pqc.c` | pq-crystals/kyber, `ref/` | the FIPS 203 final `ref/` tree | CC0-1.0, Apache-2.0 fallback |
| ML-DSA-44 core | `ncrypt-pqc.c` | pq-crystals/dilithium, `ref/` | the FIPS 204 final `ref/` tree | CC0-1.0, Apache-2.0 or GPL-2.0 fallback |
| FIPS 202 core | `ncrypt-pqc.c` | `fips202.c` shipped with both repositories (byte-identical) | as above | public domain |
| ACVP vectors | `tests/vectors/*.txt` | usnistgov/ACVP-Server, `gen-val/json-files/` | — | US Government work |

The upstream revisions above were the ones recorded when the port was
made. Anyone re-deriving the port should pin the exact commits they used;
see [Refreshing an upstream component](#refreshing-an-upstream-component).

## Classical layer (Monocypher)

`ncrypt.c` is Monocypher's `src/monocypher.c` followed by
`src/optional/monocypher-ed25519.c`; `ncrypt.h` is the concatenation of
the two matching headers. The upstream files were compared line by line
against the 4.0.3 tag. The complete list of differences:

- Every `crypto_` identifier is renamed to `ncrypt_`, and every `CRYPTO_`
  macro to `NCRYPT_`. The header guard is `NCRYPT_H`.
- The C++ namespace machinery (`MONOCYPHER_CPP_NAMESPACE`) is removed;
  the headers keep plain `extern "C"` guards.
- The Edwards curve constant `d` is renamed `ed_d`, so that it does not
  shadow the local variable `d` of the SHA-512 compression function, which
  ends up in the same translation unit after the merge.
- The SHA-512 helper `i16` is renamed `kbase`.
- The SHA-512 helper `align` is renamed `gap`, to free the name for the
  merge.
- The Monocypher license header is replaced by a short reference to the
  README and to this file.
- One em dash in a comment is replaced with ASCII.
- `NCRYPT_VERSION` is added to the header.

Nothing else was changed: no cryptographic code, no constant, no
optimisation. The Monocypher manual therefore applies to every `ncrypt_`
function after substituting the prefix.

The Elligator 2 and "dirty" X25519 functions (`ncrypt_elligator_map`,
`ncrypt_elligator_rev`, `ncrypt_elligator_key_pair`,
`ncrypt_x25519_dirty_fast`, `ncrypt_x25519_dirty_small`) are part of that
port. The review that produced this release restored them after they had
been dropped from an intermediate tree: the tests and the documentation
had kept referring to them, so the omission was a defect, not a design
decision.

Monocypher's test vectors (`tests/tis-ci-vectors.h`) and the test program
that consumes them (`tests/tis-ci.c`, `utils.c`, `utils.h`) were imported
into `tests/` with the same renaming, so the classical layer is verified
against exactly the vectors upstream uses.

## ML-KEM-768 (pq-crystals/kyber)

Merged into the ML-KEM section of `ncrypt-pqc.c`, in this order:
`params.h`, `reduce.[ch]`, `ntt.[ch]`, `cbd.[ch]`, `poly.[ch]`,
`polyvec.[ch]`, `verify.[ch]`, `symmetric.h`, `symmetric-shake.c`,
`indcpa.[ch]`, `kem.[ch]`. The parameter set is fixed at ML-KEM-768
(`KYBER_K == 3`).

Changes relative to upstream:

- Every function is `static` and prefixed with `mlkem_` (helpers that
  cannot collide keep their upstream name). Only the `ncrypt_` entry
  points are exported, so the library can be linked next to another copy
  of Kyber or Keccak.
- `randombytes()` and the non-`derand` entry points are removed. The
  deterministic cores `crypto_kem_keypair_derand`, `crypto_kem_enc_derand`
  and `crypto_kem_dec` are kept, as `mlkem_keypair_derand`,
  `mlkem_enc_derand` and `mlkem_dec`.
- Secret intermediates (`buf`, `kr`, `cmp`, the noise polynomials, the
  decrypted message polynomial) are wiped with `ncrypt_wipe()` before
  returning. Upstream wipes nothing.
- Narrowing conversions carry explicit casts. The arithmetic bounds that
  make each cast lossless are stated in comments or in
  [`DESIGN.md`](DESIGN.md#integer-conversions-and-portability).
- The compiler barriers in `mlkem_cmov` and `mlkem_cmov_int16` are kept.
- The FIPS 203 input checks (encapsulation key modulus check and
  decapsulation key hash check, sections 7.2 and 7.3) are implemented in
  the public wrappers. Upstream leaves them to the caller.
- The `KYBER_90S` (AES/SHA-2) variants are not included.
- The entry points return exactly 0 or -1.
- The poly decoders mask the decoded value before indexing the coefficient
  array (`coeffs[i] = t & 0xFFF` became `c = t & 0xFFF; coeffs[i] = c`).
  This is the same arithmetic; it only removes a value-dependent index
  expression. See [`DESIGN.md`](DESIGN.md#constant-time-discipline).

## ML-DSA-44 (pq-crystals/dilithium)

Merged into the ML-DSA section of `ncrypt-pqc.c`: `params.h`,
`reduce.[ch]`, `rounding.[ch]`, `ntt.[ch]`, `poly.[ch]`, `polyvec.[ch]`,
`packing.[ch]`, `symmetric.h`, `symmetric-shake.c`, `sign.[ch]`. The
parameter set is fixed at ML-DSA-44 (`DILITHIUM_MODE == 2`).

Changes relative to upstream:

- Every function is `static` and prefixed with `mldsa_`.
- `randombytes()`, `crypto_sign_keypair`, `crypto_sign` (the combined
  signed-message interface) and `crypto_sign_open` are removed. Key
  generation takes an explicit seed; signing takes an explicit `rnd`.
- The `DBENCH` cycle-count instrumentation is removed.
- The signing routine wipes every local that holds a secret or a
  secret-derived value, including the storage left behind by rejected
  iterations (`z`, `w0`, `w1`, `h`, `cp`, the matrix, and the Keccak
  state). Upstream wipes nothing.
- The context-string length check is kept (`ctxlen > 255` fails), but the
  `siglen` output parameter is dropped, since the signature size is a
  compile-time constant.
- The final challenge comparison in verification is branch-free, and the
  public wrappers normalise every verdict to 0 or -1.
- Narrowing conversions carry explicit casts.
- Decoders that mask a freshly decoded value (`t & 0x3FF` and friends)
  keep the mask on the value rather than on the array index, as in the
  ML-KEM section.

Two upstream commits that changed the `ref/` code during the FIPS 204
finalisation ("adjust the high part in the negative direction when the low
part is zero", and a stricter infinity-norm check) are included: the code
merged here already behaves that way, which the ACVP vectors confirm.

## FIPS 202

The Keccak-f[1600] permutation and the SHAKE128, SHAKE256, SHA3-256 and
SHA3-512 wrappers are the `fips202.c` shipped with both CRYSTALS
repositories, which is byte-identical in the two. It derives from the
public domain SUPERCOP `crypto_hash/keccakc512/simple` implementation and
the public domain TweetFips202. Only the narrowing conversions in
`store64` and `keccak_squeeze` were made explicit.

## ACVP vectors

`tests/vectors/*.txt` are the NIST ACVP vectors, flattened from the
`internalProjection.json` files of these ACVP-Server directories,
restricted to the ML-KEM-768 and ML-DSA-44 parameter sets:

- `ML-KEM-keyGen-FIPS203`
- `ML-KEM-encapDecap-FIPS203`
- `ML-DSA-keyGen-FIPS204`
- `ML-DSA-sigGen-FIPS204`
- `ML-DSA-sigVer-FIPS204`

The flattening script is in [`TESTING.md`](TESTING.md#known-answer-vectors).
The JSON sources are published by NIST under
<https://github.com/usnistgov/ACVP-Server>.

## Refreshing an upstream component

1. Fetch the new upstream tree and record **the commit hash** in the
   summary table above.
2. Re-apply the transformations listed for that component. Work from the
   list, not from the previous port: the list is the contract.
3. Run `make check` (vectors must still pass), `make strict`,
   `make sanitize`, `make ct` and `make interop`.
4. Update this file, including any change in the upstream license.

## Upstream notices

Every upstream component listed above is available under CC0-1.0 (or, for
FIPS 202, is already public domain, and for the ACVP vectors, a work of
the US Government). This project takes all of them under those public
domain terms, which require no attribution and impose no conditions. The
permissive fallback licenses that upstream also offers (BSD-2-Clause for
Monocypher, Apache-2.0 / GPL-2.0 for the CRYSTALS code) are therefore not
relied on, and nothing in this tree is distributed under GPL.

Because of that, the third-party components impose no notice requirement
and carry no attribution obligation here. The project's own code is
released under the [Anonymous Public Domain License 1.0](../LICENSE),
which waives copyright and related rights and requires no attribution
either; see the [README](../README.md#license). Anyone who prefers to
redistribute a particular component under its upstream fallback license
should take the notice from that upstream repository, since the notice is
a condition of the fallback and not of CC0.
