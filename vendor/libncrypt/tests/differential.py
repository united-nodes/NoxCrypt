#!/usr/bin/env python3
"""Differential test against an independent implementation.

The known-answer vectors in tests/vectors pin libncrypt's *output* to
NIST's, and tests/interop.py checks that two implementations agree on
honest inputs.  Neither says much about inputs an attacker chooses.
This script does that: it feeds forged ciphertexts and mutated
signatures to libncrypt and to PQClean (through the `pqcrypto`
bindings) and requires the two to reach the same verdict, byte for
byte, every time.

What it catches that the other tests cannot:

  - a decoder that accepts an encoding the standard rejects, or
    rejects one it accepts (the hint and z encodings are attacker
    controlled, and a laxer decoder is a source of signature
    malleability and of out-of-bounds coefficients);
  - an implicit-rejection path that returns a different fallback
    secret from everyone else's, which would silently break
    interoperability for corrupted records instead of failing loudly;
  - a verifier whose verdict is a value other than 0 or -1, which a
    caller testing `!= 0` would not notice but a caller testing
    `== -1` would read as success.

It needs `pip install pqcrypto` and a C compiler.  The run is
deterministic: the pseudo-random stream is seeded, so a failure is
reproducible from the reported case number.

    make differential        # or: python3 tests/differential.py [rounds]
"""

import ctypes
import os
import random
import subprocess
import sys
import tempfile

KEM_PK, KEM_SK, KEM_CT, SS = 1184, 2400, 1088, 32
SIG_PK, SIG_SK, SIG = 1312, 2560, 2420
CTILDE, Z_REGION, HINT_REGION = 32, 32 + 4 * 576, 84   # ML-DSA-44 layout

SEED = 20261031
KEM_ROUNDS = 60
SIG_ROUNDS = 400

failures = 0


def check(name, ok, detail=""):
    global failures
    if not ok:
        print("FAIL " + name + ("  " + detail if detail else ""))
        failures += 1


def build(root):
    out = os.path.join(tempfile.mkdtemp(), "libncrypt.so")
    subprocess.run(["cc", "-shared", "-fPIC", "-O2", "-std=c99", "-o", out,
                    os.path.join(root, "ncrypt.c"),
                    os.path.join(root, "ncrypt-pqc.c")], check=True)
    return ctypes.CDLL(out)


def declare(lib):
    ptr, data = ctypes.c_void_p, ctypes.c_char_p
    sz, i = ctypes.c_size_t, ctypes.c_int

    lib.ncrypt_mlkem768_key_pair.argtypes = [ptr, ptr, ptr]
    lib.ncrypt_mlkem768_key_pair.restype = None
    lib.ncrypt_mlkem768_encapsulate.argtypes = [ptr, ptr, ptr, ptr]
    lib.ncrypt_mlkem768_encapsulate.restype = i
    lib.ncrypt_mlkem768_decapsulate.argtypes = [ptr, ptr, ptr]
    lib.ncrypt_mlkem768_decapsulate.restype = i

    lib.ncrypt_mldsa44_key_pair.argtypes = [ptr, ptr, ptr]
    lib.ncrypt_mldsa44_key_pair.restype = None
    lib.ncrypt_mldsa44_sign.argtypes = [ptr, ptr, ptr, data, sz, data, sz]
    lib.ncrypt_mldsa44_sign.restype = i
    lib.ncrypt_mldsa44_check.argtypes = [ptr, ptr, data, sz, data, sz]
    lib.ncrypt_mldsa44_check.restype = i


def buf(n, fill=b""):
    b = (ctypes.c_ubyte * n)()
    if fill:
        b[:len(fill)] = fill
    return b


def raw(b):
    return bytes(bytearray(b))


def kem_rounds(lib, rng, kenc, kdec):
    """Forged and mutated ciphertexts: both sides must agree exactly."""
    sk, pk = buf(KEM_SK), buf(KEM_PK)
    lib.ncrypt_mlkem768_key_pair(sk, pk, buf(64, b"\x01" * 64))

    for n in range(KEM_ROUNDS):
        if n % 2:
            ct = bytearray(rng.getrandbits(8) for _ in range(KEM_CT))
        else:
            ct = bytearray(bytes(kenc(raw(pk))[0]))
            for _ in range(rng.randint(1, 6)):
                ct[rng.randrange(KEM_CT)] ^= 1 << rng.randrange(8)
        ct = bytes(ct)

        mine = buf(SS)
        rc = lib.ncrypt_mlkem768_decapsulate(mine, ct, sk)
        theirs = bytes(kdec(raw(sk), ct))

        check("ML-KEM forged ciphertext %d: return value" % n, rc == 0,
              "returned %d, FIPS 203 requires implicit rejection" % rc)
        check("ML-KEM forged ciphertext %d: secret" % n, raw(mine) == theirs,
              "%s != %s" % (raw(mine).hex()[:16], theirs.hex()[:16]))

    # A malformed public key must be refused before anything is written.
    bad_pk = buf(KEM_PK, b"\xff\xff" + b"\x00" * (KEM_PK - 2))
    ct, ss = buf(KEM_CT), buf(SS)
    check("ML-KEM: non-canonical public key is rejected",
          lib.ncrypt_mlkem768_encapsulate(ct, ss, bad_pk, buf(32)) == -1)


def sig_rounds(lib, rng, verify, invalid):
    """Mutated signatures: the verdicts must agree on every case."""
    sk, pk = buf(SIG_SK), buf(SIG_PK)
    lib.ncrypt_mldsa44_key_pair(sk, pk, buf(32, b"\x02" * 32))
    msg = b"differential test message"

    good = buf(SIG)
    lib.ncrypt_mldsa44_sign(good, sk, buf(32, b"\x03" * 32), None, 0,
                            msg, len(msg))
    base = raw(good)
    check("ML-DSA: the unmodified signature verifies",
          lib.ncrypt_mldsa44_check(good, pk, None, 0, msg, len(msg)) == 0)
    try:
        verify(raw(pk), msg, base)
    except invalid:
        check("ML-DSA: PQClean accepts the unmodified signature", False)

    for n in range(SIG_ROUNDS):
        m = bytearray(base)
        kind = n % 4
        if kind == 0:                      # scattered bit flips
            for _ in range(rng.randint(1, 4)):
                m[rng.randrange(SIG)] ^= 1 << rng.randrange(8)
        elif kind == 1:                    # single arbitrary byte in z
            m[rng.randrange(CTILDE, Z_REGION)] = rng.getrandbits(8)
        elif kind == 2:                    # single arbitrary byte in the hint
            m[rng.randrange(Z_REGION, SIG)] = rng.getrandbits(8)
        else:                              # reordered bytes inside one z
            p = rng.randrange(CTILDE, Z_REGION - 9)
            m[p:p + 9] = base[p:p + 9][::-1]
        m = bytes(m)

        mine = lib.ncrypt_mldsa44_check(m, pk, None, 0, msg, len(msg))
        try:
            verify(raw(pk), msg, m)
            theirs = 0
        except invalid:
            theirs = -1

        check("ML-DSA mutant %d (kind %d): libncrypt verdict is 0 or -1"
              % (n, kind), mine in (0, -1), "returned %d" % mine)
        check("ML-DSA mutant %d (kind %d): verdict agrees with PQClean"
              % (n, kind), (mine == 0) == (theirs == 0),
              "libncrypt %d, PQClean %d" % (mine, theirs))



def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 1

    try:
        from pqcrypto import InvalidSignatureError
        from pqcrypto.kem.ml_kem_768 import decaps as kdec, encaps as kenc
        from pqcrypto.sign.ml_dsa_44 import verify
    except ImportError:
        print("SKIP: the pqcrypto package is not installed "
              "(pip install pqcrypto)")
        return 0

    lib = build(root)
    declare(lib)
    rng = random.Random(SEED)

    for _ in range(rounds):
        kem_rounds(lib, rng, kenc, kdec)
        sig_rounds(lib, rng, verify, InvalidSignatureError)

    print("differential: %d ML-KEM ciphertexts, %d ML-DSA mutants, "
          "%d disagreement(s)" % (KEM_ROUNDS * rounds, SIG_ROUNDS * rounds,
                                  failures))
    if failures:
        print("differential: FAILED")
        return 1
    print("differential: libncrypt and PQClean agree on every case")
    return 0


if __name__ == "__main__":
    sys.exit(main())
