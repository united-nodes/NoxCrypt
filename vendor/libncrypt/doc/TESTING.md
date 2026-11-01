# Testing

What the test suite covers, how to run it, how the vectors were produced,
and — just as important — what is *not* covered. Everything is driven from
the `Makefile`. A C99 compiler and `make` are enough for the standard run;
the analysis targets need Valgrind and a sanitizer-capable compiler, and
say so when they are missing.

Contents:

1. [Running the tests](#running-the-tests)
2. [Test programs](#test-programs)
3. [Known-answer vectors](#known-answer-vectors)
4. [Constant-time verification](#constant-time-verification)
5. [Interoperability](#interoperability)
6. [Differential testing](#differential-testing)
7. [Fuzzing](#fuzzing)
8. [Compiler, sanitizer and target configurations](#compiler-sanitizer-and-target-configurations)
9. [What is not tested](#what-is-not-tested)
10. [Release checklist](#release-checklist)

## Running the tests

```
make check        # build the library and run the three test programs
make strict       # compile library and tests with the full warning set, -Werror
make sanitize     # the test suite under AddressSanitizer and UBSan
make valgrind     # the test suite under Valgrind memcheck
make ct           # the constant-time harness under Valgrind
make fuzz         # standalone fuzz sweep under ASan and UBSan
make interop      # cross-check against PQClean (needs `pip install pqcrypto`)
make differential # adversarial inputs, libncrypt verdict vs PQClean's
```

`make check` prints a summary line per program and exits non-zero on the
first failure. Expected output:

```
./test_classic
	chacha20
	...
OK: ncrypt_verify64
./test_pqc
test_pqc: 483 checks, 0 failures
./test_kat tests/vectors
test_kat: 323 checks, 0 failures
all tests passed
```

Every run is reproducible: the tests use fixed seeds and fixed pseudo-random
streams, and nothing reads the system random source.

## Test programs

### `tests/test_classic.c`

The vector test that ships with Monocypher 4.0.3, renamed to the `ncrypt_`
prefix and reduced to one self-contained program. It pushes every vector in
`tests/classic_vectors.h` through the classical layer: ChaCha20 (DJB, IETF,
XChaCha20), HChaCha20, Poly1305, the AEAD, BLAKE2b (keyed and unkeyed),
SHA-512, HMAC-SHA-512, HKDF-SHA-512, Argon2 (d, i and id), X25519, EdDSA,
Ed25519, Elligator 2 in both directions, and `ncrypt_verify16/32/64`. It
also checks `ncrypt_wipe()`, the dirty-key X25519 functions, scalar
division, and the EdDSA/X25519 conversions.

Passing this program is the evidence that the port did not disturb the
classical layer.

### `tests/test_pqc.c`

Behavioural tests for the post-quantum API that do not depend on external
vectors:

| Group | What is checked |
| --- | --- |
| `mlkem_roundtrip` | Key generation, encapsulation and decapsulation agree; seeds are wiped. |
| `mlkem_determinism` | Same seeds give the same keys and ciphertexts; different seeds differ. |
| `mlkem_implicit_rejection` | Single-bit modifications of the ciphertext decapsulate without error, to a secret that differs from the sender's and is stable across calls; the rejection secret depends on `z`. |
| `mlkem_malformed_keys` | A public key with a coefficient `>= q` is rejected with no output written; a decapsulation key with a wrong `H(ek)` is rejected; correct keys pass. |
| `mldsa_roundtrip` | Sign and verify for empty, short and long messages, with and without a context; `rnd` is wiped. |
| `mldsa_hedged_vs_deterministic` | Deterministic signing is reproducible; hedged signatures differ between calls and from the deterministic one; zero `rnd` reproduces the deterministic signature; all verify. |
| `mldsa_context` | A signature verifies only with the exact context; 255 bytes works; 256 bytes is rejected by sign and verify, with `rnd` wiped and the signature untouched. |
| `mldsa_tamper` | Flipping bytes in `c_tilde`, `z` or `h` fails; reordered hint indices and non-zero bytes in the unused hint area fail; a modified or truncated message fails; a wrong public key fails; the untouched signature still verifies. |
| `hybrid_roundtrip` | Encrypt and decrypt with and without associated data; seed wiped. |
| `hybrid_in_place` | `plain_text == cipher_text` works in both directions. |
| `hybrid_tamper` | Modifying `kem_ct`, `mac`, `cipher_text` or `ad`, truncating, or using another recipient's key all fail and leave the plaintext untouched. |
| `hybrid_tamper_in_place` | The same failures with `plain_text == cipher_text`: the buffer must be byte-identical afterwards, and the restored record must still decrypt. This is the case an application is most likely to use and the one where a half-written plaintext would look like success. |
| `verdict_is_zero_or_minus_one` | Every failure path returns exactly -1, and every success path exactly 0 — checking the value, not just its non-zeroness, since callers are documented to compare against -1. Covers a bad challenge, an out-of-range `z`, a malformed hint, a short message, a bad tag, an inconsistent secret key and a malformed public key. |
| `hybrid_failure_leaves_outputs` | A malformed public key makes encryption fail with all three outputs untouched and the seed wiped. |
| `hybrid_seed_dependence` | Two encryptions of the same message under different seeds differ in `kem_ct`, `mac` and ciphertext. |

### `tests/test_kat.c`

Runs the NIST ACVP vectors in `tests/vectors/` through the public API.

| Vector file | Cases | Function under test |
| --- | ---: | --- |
| `mlkem768_keygen.txt` | 25 | `ncrypt_mlkem768_key_pair` from `d \|\| z`; compares `ek` and `dk`. |
| `mlkem768_encap.txt` | 25 | `ncrypt_mlkem768_encapsulate` from `m`; compares `c` and `k`. |
| `mlkem768_decap.txt` | 10 | `ncrypt_mlkem768_decapsulate`; compares `k`, including implicit-rejection cases. |
| `mlkem768_ekcheck.txt` | 10 | Encapsulation key check: the return value must match `testPassed`. |
| `mlkem768_dkcheck.txt` | 10 | Decapsulation key check: the same. |
| `mldsa44_keygen.txt` | 25 | `ncrypt_mldsa44_key_pair` from `seed`; compares `pk` and `sk`. |
| `mldsa44_siggen.txt` | 60 | Deterministic and hedged signing, external interface (30 cases). The 30 internal-interface cases need `ML-DSA.Sign_internal`, which is not exposed, and are reported as skipped. |
| `mldsa44_sigver.txt` | 30 | `ncrypt_mldsa44_check`; `testPassed` must match. The 15 internal-interface cases are skipped, as above. |

The program checks that it actually ran the expected number of cases in
each file, so a vector file that fails to parse cannot quietly reduce
coverage to zero.

### `tests/test_ct.c`

The constant-time harness; see
[Constant-time verification](#constant-time-verification).

### `tests/fuzz_pqc.c`

The fuzz harness; see [Fuzzing](#fuzzing).

### `tests/interop.py` and `tests/differential.py`

Python scripts that compare libncrypt with PQClean; see
[Interoperability](#interoperability) and
[Differential testing](#differential-testing).

## Known-answer vectors

The vectors are the `internalProjection.json` files from the
usnistgov/ACVP-Server repository, directory `gen-val/json-files/`, limited
to the ML-KEM-768 and ML-DSA-44 test groups and flattened into a plain
`name = HEX` text format (one blank line between cases), so that the test
program needs no JSON parser. Record the commit you used when you refresh
them; the field names follow ACVP's (`ek`, `dk`, `c`, `k`, `m`, `d`, `z`,
`seed`, `pk`, `sk`, `message`, `context`, `rnd`, `signature`,
`deterministic`, `interface`, `reason`, `testPassed`), with `count`
holding the ACVP `tcId`.

The script that regenerates the files from the five JSON documents:

```python
import json, sys

def flat(path, out, want, keep, group_filter=lambda g: True):
    doc = json.load(open(path))
    with open(out, "w") as f:
        for g in doc["testGroups"]:
            if g.get("parameterSet") != want or not group_filter(g):
                continue
            for t in g["tests"]:
                f.write("count = %d\n" % t["tcId"])
                for k in keep:
                    v = g.get(k, t.get(k))
                    if v is None:
                        continue
                    if isinstance(v, bool):
                        v = "true" if v else "false"
                    f.write("%s = %s\n" % (k, v))
                f.write("\n")

A = sys.argv[1]  # directory holding the ACVP json files
V = sys.argv[2]  # tests/vectors
flat(A + "/ML-KEM-keyGen-FIPS203.json", V + "/mlkem768_keygen.txt",
     "ML-KEM-768", ["d", "z", "ek", "dk"])
flat(A + "/ML-KEM-encapDecap-FIPS203.json", V + "/mlkem768_encap.txt",
     "ML-KEM-768", ["ek", "m", "c", "k"], lambda g: g["function"] == "encapsulation")
flat(A + "/ML-KEM-encapDecap-FIPS203.json", V + "/mlkem768_decap.txt",
     "ML-KEM-768", ["dk", "c", "k", "reason"], lambda g: g["function"] == "decapsulation")
flat(A + "/ML-KEM-encapDecap-FIPS203.json", V + "/mlkem768_ekcheck.txt",
     "ML-KEM-768", ["ek", "reason", "testPassed"], lambda g: g["function"] == "encapsulationKeyCheck")
flat(A + "/ML-KEM-encapDecap-FIPS203.json", V + "/mlkem768_dkcheck.txt",
     "ML-KEM-768", ["dk", "reason", "testPassed"], lambda g: g["function"] == "decapsulationKeyCheck")
flat(A + "/ML-DSA-keyGen-FIPS204.json", V + "/mldsa44_keygen.txt",
     "ML-DSA-44", ["seed", "pk", "sk"])
flat(A + "/ML-DSA-sigGen-FIPS204.json", V + "/mldsa44_siggen.txt",
     "ML-DSA-44", ["deterministic", "interface", "sk", "message", "context", "rnd", "signature"],
     lambda g: g.get("preHash", "pure") == "pure")
flat(A + "/ML-DSA-sigVer-FIPS204.json", V + "/mldsa44_sigver.txt",
     "ML-DSA-44", ["interface", "pk", "message", "context", "signature", "reason", "testPassed"],
     lambda g: g.get("preHash", "pure") == "pure")
```

Booleans are written in lower case (`true`/`false`), as in the JSON
source, and `test_kat.c` compares against those spellings.

## Constant-time verification

`tests/test_ct.c` is a ctgrind-style harness. It builds key pairs and
messages normally, then marks every secret buffer as *undefined* with
`VALGRIND_MAKE_MEM_UNDEFINED` and runs each public function under
Valgrind's memcheck. Memcheck reports:

- **"Conditional jump or move depends on uninitialised value(s)"** — a
  branch or conditional move whose outcome depends on a secret.
- **"Use of uninitialised value"** — a load or store at an address that
  depends on a secret.

Public data (public keys, ciphertexts, signatures, messages) is left
defined, so branching on it is not reported: only secrets matter.

The reviewed exceptions are in `tests/ct.supp`, each with a comment
explaining why the branch is acceptable. `make ct` runs

```
valgrind -q --error-exitcode=42 --suppressions=tests/ct.supp ./test_ct
```

and therefore fails on any report that is *not* one of them. The set is
the same at `-O0`, `-O1` and `-O2`, so the harness is not sensitive to the
optimisation level. As a negative control, injecting a secret-dependent
branch into `ncrypt_blake2b_keyed` makes `make ct` fail, so the check
cannot silently pass by being vacuous.

What the suppressions cover, and why (the full argument is in
[`DESIGN.md`](DESIGN.md#constant-time-discipline)):

| Function | Why the branch is acceptable |
| --- | --- |
| `mlkem_rej_uniform` | Rejection sampling on `rho`, which is part of the public key. FIPS 203 identifies it as safe. |
| `ncrypt_mlkem768_decapsulate`, `..._encapsulate` | The FIPS 203 key checks act on public components and report a value the caller already gets. |
| `mldsa_rej_uniform`, `rej_eta`, `mldsa_poly_uniform*` | Rejection sampling; the rejection rate is a property of the distribution, not of a particular secret. |
| `mldsa_poly_challenge` | Challenge decoding: the number of squeezed bytes follows from the challenge. |
| `mldsa_poly_chknorm`, `mldsa_polyvecl_chknorm` | The signing rejection loop, whose iteration count FIPS 204's analysis accounts for. |
| `mldsa_make_hint`, `mldsa_use_hint`, `mldsa_pack_sig`, `mldsa_signature_internal` | Hint handling, whose shape follows from the coefficients it encodes. |
| `mldsa_verify_internal` | Verification works on public data. |
| `ncrypt_aead_read`, `ncrypt_pqc_decrypt` | The tag comparison; the result is the return value. |
| `ncrypt_elligator_rev`, `ncrypt_elligator_key_pair` | Whether a point has a representative; the retry loop is meant to leak its retry count, which is why the tweak is random. |
| `ncrypt_argon2`, `xor_block` | Argon2d and Argon2id index memory with data-dependent addresses by design. |

The library changes that made this list as short as it is are in
[`PROVENANCE.md`](PROVENANCE.md) (the value-masking decoders) and in
`DESIGN.md`.

The harness is a regression test, not a proof: it sees the code the
compiler generated on this machine with this compiler, and it cannot see
microarchitectural effects or physical side channels.

## Interoperability

`tests/interop.py` (`make interop`) checks the library against PQClean
through the `pqcrypto` Python bindings, which are unrelated code:

- PQClean encapsulates to a libncrypt key, libncrypt decapsulates, and the
  shared secrets match.
- libncrypt signs, PQClean verifies, and the reverse, both with and
  without a context string.
- A tampered signature is rejected on both sides.

This complements the ACVP vectors: those pin the output to NIST's
implementation, while this shows that an independent implementation
accepts it. The script skips itself, with a message, when `pqcrypto` is
not installed.

Both directions of the KEM are checked, deliberately. En/decapsulating
only with keys that libncrypt itself generated would still pass if key
generation were self-consistently wrong — the shared secret would match
locally and with nobody else. Encapsulating to a PQClean key, and letting
PQClean decapsulate, rules that out.

## Differential testing

`tests/differential.py` (`make differential`) is the adversarial
counterpart. It feeds libncrypt and PQClean the same hostile inputs and
requires the same answer, byte for byte:

- 60 forged or bit-flipped ML-KEM ciphertexts. Both sides must decapsulate
  without error (implicit rejection) and land on the *same* fallback
  secret. A diverging fallback secret would be invisible in every other
  test and would break interoperability exactly when a record is damaged.
- 400 mutated ML-DSA signatures, in four flavours: scattered bit flips,
  arbitrary bytes inside the `z` encoding, arbitrary bytes inside the
  hint encoding, and reordered bytes within one `z`. Both sides must
  accept or reject each one identically. This is what pins the decoder
  to the standard: a laxer hint or `z` decoder would show up here as
  libncrypt accepting something PQClean rejects — that is signature
  malleability, and historically a rich source of CVEs in this class of
  code.
- A non-canonical ML-KEM public key, which must be refused.

The run is deterministic (`SEED` at the top of the script), so a failure
is reproducible from its case number. `make differential ROUNDS=10`
repeats the whole sweep with a different stream each time, roughly
5 seconds per round.

Neither script replaces the ACVP vectors: vectors check exact output for
valid input, these check the verdict for invalid input.

## Fuzzing

`tests/fuzz_pqc.c` exercises the paths that consume untrusted input: the
ML-KEM encapsulation key check, decapsulation with arbitrary ciphertexts
and corrupted secret keys, ML-DSA verification with arbitrary signatures
(in particular the hint and `z` decoders), and hybrid decryption. It
derives fixed key pairs once, uses the low two bits of the first input
byte to choose a target, and overlays the rest of the input on an
otherwise valid object of that kind.

With clang and libFuzzer:

```
clang -std=c99 -O1 -g -fsanitize=fuzzer,address,undefined \
      tests/fuzz_pqc.c ncrypt.c ncrypt-pqc.c -o fuzz_pqc
mkdir -p corpus && ./fuzz_pqc corpus -max_len=4096
```

Without libFuzzer, `make fuzz` builds the same harness with
`-DFUZZ_STANDALONE`, which provides a `main()` that runs a built-in sweep
(64 selector values at input lengths from 1 byte to 4 KiB, deterministic
fill) and then processes any files named on the command line, so a corpus
from a libFuzzer run can be replayed on a machine without clang. The sweep
runs under ASan and UBSan and must finish silently.

## Compiler, sanitizer and target configurations

Configurations that were built and run on the 1.0.0 tree, on x86-64 Linux:

| Configuration | Result |
| --- | --- |
| GCC 14.2, `-O0`, `-O2`, `-O3`, `-Os` | all tests pass |
| Clang 19.1, `-O2` | all tests pass |
| `make strict` (library **and** tests, `-Wconversion -Wsign-conversion -Wcast-qual -Wvla -Wundef -Wwrite-strings -Werror`) | no diagnostics |
| `make sanitize` (ASan + UBSan, `-fno-sanitize-recover=all`) | pass, no reports |
| `make valgrind` (memcheck, `--leak-check=full --track-origins=yes`) | pass, no errors, no leaks |
| `make ct` (constant-time harness) | pass, no unsuppressed report |
| `make fuzz` (standalone sweep under ASan + UBSan) | clean |
| `make differential` (1 600 mutants, 240 ciphertexts) | 0 disagreements with PQClean |
| MemorySanitizer (clang, origin tracking) on all four programs | clean |
| `-D_FORTIFY_SOURCE=3` build | clean |
| GCC `-fanalyzer` | one report, traced to a false positive (see below) |
| libFuzzer, 250 000 executions under ASan + UBSan, mutating valid objects | no findings |
| `-m32` build, full test suite | pass |
| `g++ -std=c++11` and `-std=c++17`, both headers | compile cleanly |

The sanitizer build is the most valuable of these: beyond memory errors,
UBSan's `signed-integer-overflow` and `shift` checks cover the modular
arithmetic, which is where a port of lattice code is most likely to have
gone wrong. MemorySanitizer is second: it reads every byte of output as
undefined until proven otherwise, so it catches a read of uninitialised
stack that memcheck misses when the stack happens to be zeroed.

`-fanalyzer` reports one path ("use of uninitialized value" in
`load32_littleendian`, reached from `cbd2` via `mlkem_poly_frombytes`).
It is a false positive, and an instructive one: the analyzer loses track
of the loop that fills `r->coeffs[0..255]` in `mlkem_poly_frombytes` and
then attributes the gap to the next value it sees. The loop writes every
element, the structure has no padding, and MemorySanitizer — which tracks
this precisely — is silent. It is recorded rather than suppressed, because
a report that is dismissed without being understood is how a real one
gets missed.

## What is not tested

Being explicit about the gaps is more useful than a long list of passes.

- **An independent audit.** Everything here was produced by the project.
  No third party has reviewed the code or the test suite.
- **Constant time on other compilers and hardware.** The harness runs one
  compiler on one machine, and no statistical timing measurement (dudect,
  for instance) has been made. Microarchitectural leakage and physical
  side channels are out of scope.
- **Other platforms.** Big-endian targets and non-GCC/Clang compilers have
  not been exercised. The code contains no endianness assumptions, but
  that is an assertion, not a result.
- **Internal-interface ACVP vectors.** The `internal` sigGen and sigVer
  cases need `ML-DSA.Sign_internal` and `Verify_internal`, which are not
  exposed.
- **Other parameter sets.** Only ML-KEM-768 and ML-DSA-44 are tested.
- **Long-running fuzzing.** `make fuzz` is a bounded sweep, and the
  libFuzzer campaign behind the 250 000-execution figure above ran for
  about six minutes. Real campaigns run for weeks. What was done here
  raises confidence; it does not close the question.
- **Differential coverage beyond 2 000 cases.** `make differential` is a
  sweep, not exhaustive. A bug that needs a specific multi-byte pattern
  to trigger could survive it.
- **Memory-failure paths.** There are none: the library never allocates.

## Release checklist

Before tagging a release:

1. `make clean && make strict && make check && make sanitize &&
   make valgrind && make ct && make fuzz && make interop &&
   make differential ROUNDS=10` all succeed.
2. `make check` also passes with `CFLAGS=-O0`, `-O3`, `-Os`, `CC=clang`,
   and `CFLAGS=-m32`.
3. The version string in `ncrypt.h` and the README agree.
4. `doc/PROVENANCE.md` lists the upstream revisions actually merged.
5. `grep -rP '[^\x00-\x7F]' --include='*.c' --include='*.h'
   --include=Makefile .` reports nothing. The C sources are ASCII only;
   the Markdown documents use em dashes, which is fine.
