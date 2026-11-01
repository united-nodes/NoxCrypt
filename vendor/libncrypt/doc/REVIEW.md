# Review record

This document records the state of the source as reviewed for the 1.0.0
release.

It covers two passes. The first reviewed the source and fixed what it
found (F-01 to F-08). The second assumed the first had missed something,
and went looking for the classes of defect that survive a read-through:
decoders whose index arithmetic is attacker controlled, failure paths
that leave state behind, verdict values that are not what the
documentation promises, and agreement with a foreign implementation on
inputs no honest peer would send (F-09 and later).

The review is internal. It is not a formal verification, or independent
audit. Its purpose is to say exactly what has been looked at, so that a
reader can decide what to trust.

## Scope and method

- `ncrypt.c` / `ncrypt.h` were compared mechanically against Monocypher
  4.0.3, after applying the prefix rename, to confirm that they contain
  no other change. That diff is the whole story for this layer; it is
  reproduced as a list in [`PROVENANCE.md`](PROVENANCE.md). Monocypher has
  a long record of public review, and a rename adds no attack surface.
- `ncrypt-pqc.c` was read in full. The reference cores were compared
  against the pq-crystals `ref/` trees, and every deviation was examined
  individually. The public API and the hybrid construction were reviewed
  line by line against the contracts in [`API.md`](API.md) and
  [`DESIGN.md`](DESIGN.md).
- `ncrypt-pqc.h` was checked against the implementation: size constants,
  prototypes, documented behaviour.
- The test programs and the `Makefile` were reviewed for coverage gaps;
  the gaps that remain are listed in [`TESTING.md`](TESTING.md).
- Tooling: GCC 14 and Clang 19 with the full warning set and `-Werror`;
  GCC's `-fanalyzer`; Clang's static analyser; cppcheck; AddressSanitizer;
  UBSan; MemorySanitizer; `_FORTIFY_SOURCE=3`; Valgrind memcheck; the
  constant-time harness; a cross-implementation test and a differential
  test against PQClean; and a libFuzzer campaign.

Second pass, specifically:

- Every decoder that consumes attacker-controlled bytes was re-read with
  the index arithmetic written out symbolically and its bounds checked by
  hand: `mldsa_unpack_sig` (hint indices and cumulative counts),
  `mldsa_polyz_unpack`, `mldsa_polyeta_unpack`, `mldsa_polyt0_unpack`,
  `mldsa_polyt1_unpack`, the ML-KEM decoders, and the canonicality checks
  in front of them.
- Every early return in the public API was checked for (a) outputs left
  unwritten, (b) seeds and keys wiped, and (c) the exact return value.
- The ordering of checks in verification was checked: the `z` infinity
  norm is tested before `z` enters the NTT, so a malicious encoding
  cannot reach the arithmetic with out-of-range coefficients even if a
  later check fails.
- Rounding and hint logic was checked against FIPS 204 including the
  commit that changed the behaviour when the low part is zero, and against
  PQClean on boundary inputs.
- Failure atomicity was re-examined for the *in-place* case (output buffer
  aliased with the input), which the previous test suite never exercised.
- A differential test now compares libncrypt's verdict with PQClean's on
  forged ciphertexts and mutated signatures (F-11).

## Findings, and their disposition

| Id | Severity | Finding | Disposition |
| --- | --- | --- | --- |
| F-01 | High | The Elligator 2 functions (`ncrypt_elligator_map`, `ncrypt_elligator_rev`, `ncrypt_elligator_key_pair`) and the dirty X25519 key generation (`ncrypt_x25519_dirty_fast`, `ncrypt_x25519_dirty_small`) had been dropped from `ncrypt.c`, but were still referenced by the tests, the header documentation and the manual. `test_classic.c` therefore did not compile, so the classical layer had no test coverage at all, and the documented API did not exist. | Restored verbatim from Monocypher 4.0.3; declared in `ncrypt.h`; the five functions now have their own test vectors (which pass) and a ctgrind entry. The duplicate helper left behind by the removal was removed. |
| F-02 | Medium | The header did not declare the functions above, which is also what produced the only warnings in the library build (four `-Wunused-const-variable` diagnostics for the field constants they need). | Fixed by F-01. The library now builds without a diagnostic under GCC and Clang. |
| F-03 | Low | Four implicit narrowing conversions in `mlkem_polyvec_decompress` cast the result of a shift rather than its operands; Clang's `-Wconversion` flagged them. | Explicit `(uint16_t)` casts added. |
| F-04 | Low | The ML-KEM polynomial decoders wrote the length mask into the array subscript (`r->coeffs[2*i] = x & 0xFFF`). That is a value-dependent index expression in the source, and it is one of the shapes compilers have been observed to turn into a value-dependent address. | Rewritten to mask the value first, then index. Identical arithmetic; see `PROVENANCE.md` and `DESIGN.md`. |
| F-05 | Low | The ML-DSA verifier's final comparison branched on the challenge, unlike every other comparison in the library. The value is public, so this was not a leak, but it was an inconsistency that made the constant-time harness noisy. | Made branch-free. |
| F-06 | Low | The test programs did not build under the project's own warning set (`-Wmissing-prototypes` in `test_classic.c`, `-Wunused-function` and one `-Wsign-conversion` in `tests/utils.h`), so `make strict` was only ever applied to the library while `TESTING.md` claimed otherwise. | Fixed, and `make strict` now compiles the tests too. |
| F-07 | Low | Documentation was inaccurate in several places: it described the deleted APIs, gave vector counts and a stack figure that did not match the code, claimed `-Werror` cleanliness that the tree did not have, and claimed two rounds of review of a tree that did not match the release. | `README.md` and all of `doc/` were rewritten from the code and from measured output. |
| F-08 | Informational | No constant-time verification existed; the claim rested on review alone. | `tests/test_ct.c` and `tests/ct.supp` add a Valgrind-based harness that fails on any secret-dependent branch outside a reviewed list, with a negative control. |
| F-09 | Low | The public verifiers returned the internal routine's value directly. Every internal path returns -1 today, so nothing was broken, but the documented contract is "0 or -1" and callers are told to compare against -1: a future internal change to any other negative value would have been read as success by such a caller. No test would have noticed, because every test compared against `!= 0`. | `mldsa_verdict()` now maps any non-zero result to exactly -1, branch-free in unsigned arithmetic, on both `ncrypt_mldsa44_check` and `ncrypt_pqc_decrypt`. A test now checks the exact value on a dozen distinct failure paths, not just its non-zeroness. |
| F-10 | Low | The hybrid decryption failure path was not covered by a test. The code was correct — `ncrypt_aead_read` authenticates before it decrypts, so a failed tag leaves even an aliased buffer untouched — but that ordering is a property of a different function, in a different file, and nothing asserted it. The previous in-place test only covered success, and the tamper test only covered separate buffers. | `test_hybrid_tamper_in_place()` checks that a modified ciphertext, tag, encapsulation or associated data fails *and* leaves the in-place buffer byte-identical, and that the restored record still decrypts. |
| F-11 | Informational | Nothing compared libncrypt with another implementation on inputs an attacker chooses. The ACVP vectors fix the output for valid inputs; the interop test used honest inputs only. A decoder that is laxer than the standard (accepting a non-canonical hint or `z` encoding) or an implicit-rejection secret that differs from everyone else's would have passed everything. | `tests/differential.py` (`make differential`) runs forged ciphertexts and 400 mutated signatures through both libncrypt and PQClean and requires identical verdicts, byte for byte. `make interop` also gained the reverse KEM direction (libncrypt encapsulates, PQClean decapsulates), which is the direction that would expose a self-consistent-but-wrong key generation. |
| F-12 | Low | The fuzz harness could not reach the deep verification paths: random bytes never survive the decoders, so the campaign saturated at 423 edges in the top-level checks. Its own message buffer was also shorter than the length it passed to the API in one case, which ASan correctly flagged — as a harness bug, once the harness was made to reach that code. | The harness now mutates a well-formed signature and a well-formed public key, which reaches the `z` decoder, the hint decoder, the NTT and the hint application. Buffer fixed. A 250 000-execution libFuzzer campaign under ASan and UBSan found nothing in the library. |

## Observations that are not defects

- **Encapsulation key check uses public branches.** The public key is
  public and the branch reveals only whether it is well formed, which the
  return value already says.
- **The decapsulation key check precedes implicit rejection.** A corrupted
  secret key yields `-1` rather than a rejected shared secret. FIPS 203
  section 7.3 permits either; the explicit error is more useful and does
  not weaken the implicit rejection of ciphertexts, which is what the
  security proof needs.
- **Secret-dependent branches in the lattice rejection loops.** These are
  inherited from the reference code and are part of what FIPS 203 and FIPS
  204 analyse. They are documented, enumerated in `tests/ct.supp`, and not
  "fixed", because changing them would change the algorithms.
- **Mixed indentation in `ncrypt-pqc.c`.** The reference cores keep their
  two-space upstream style; the FIPS 202 section and the public API use
  tabs as in `ncrypt.c`. Reformatting the cores would make future upstream
  diffs much harder to read, so the difference stays.
- **One large translation unit.** Accepted. It is what lets the library be
  dropped into a project as two `.c` files, and the internal linkage lets
  the compiler inline the small polynomial helpers without link-time
  optimisation.

## What a second pass found, and what it means

The second pass found no remotely exploitable defect. It found two places
where a *guarantee the documentation made* was not enforced by anything
(F-09, F-10), one blind spot in the test strategy (F-11), and one blind
spot in the fuzzing (F-12). That is the shape one should expect: a code
base that has been ported faithfully from audited reference code, and
then reviewed once, tends to be correct in the paths that were exercised
and unverified in the paths that were not.

It also shows the limits of reading. Nothing in the second pass would
have been found by reading alone — F-09 needs a hostile reading of a
contract, F-10 needs an adversarial test, F-11 needs a second
implementation, F-12 needs the fuzzer to be aimed. The corresponding
lesson is recorded in `TESTING.md`: a test that only checks `!= 0`, or
that only exercises the happy path of an aliased buffer, is a test that
cannot fail for the reasons that matter.

## Open items

- No independent audit, and no statistical timing measurement (dudect or
  similar). Both are recommended before high-assurance use. This is the
  largest remaining risk by a wide margin.
- No big-endian or non-GCC/Clang testing.
- No proof of the arithmetic. The lattice code matches a reference
  implementation on NIST's vectors and on 1 600 adversarial inputs, which
  is strong evidence and not a proof.
- The license is the Anonymous Public Domain License 1.0, in `LICENSE`.
  It waives copyright and related rights, falls back to an equivalent
  license where a waiver is ineffective, and requires no attribution.
  Nothing in it touches the third-party components, which are public
  domain (CC0-1.0) and are described separately in the README and
  `PROVENANCE.md`.

## Verification of this record

Everything claimed above was run on the released tree; see the table in
[`TESTING.md`](TESTING.md#compiler-sanitizer-and-target-configurations).
The claims about warnings are checkable with `make strict`, the
constant-time claims with `make ct`, the vector coverage with
`make check`, and the agreement with a foreign implementation with
`make interop && make differential`.
