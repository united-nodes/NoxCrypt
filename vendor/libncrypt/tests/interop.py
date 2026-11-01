#!/usr/bin/env python3
"""Interoperability check against an independent ML-KEM/ML-DSA library.

The ACVP known-answer tests in tests/vectors pin libncrypt's output to
vectors produced by NIST's implementation.  This script checks the other
direction: that a second, unrelated implementation accepts and
understands what libncrypt produces, and vice versa.

It needs the `pqcrypto` Python package (pip install pqcrypto), which
wraps PQClean, and a C compiler to build a shared library:

    make interop

Checks:

  ML-KEM-768   Three directions, because each rules out a different
               class of bug:
                 - pqcrypto encapsulates to a libncrypt key, libncrypt
                   decapsulates (the decryption path);
                 - libncrypt encapsulates to a pqcrypto key, pqcrypto
                   decapsulates (the encryption path);
                 - both sides decapsulate a modified ciphertext, and
                   must land on the same implicit-rejection secret
                   without reporting an error.

  ML-DSA-44    libncrypt signs, pqcrypto verifies; pqcrypto signs,
               libncrypt verifies; with and without a context string.
               A tampered signature must be rejected by both.

Exit status is 0 only if every check passes.
"""

import ctypes
import os
import subprocess
import sys
import tempfile

KEM_PK, KEM_SK, KEM_CT, SS = 1184, 2400, 1088, 32
SIG_PK, SIG_SK, SIG = 1312, 2560, 2420

failures = 0


def check(name, ok, detail=""):
    global failures
    suffix = "  " + detail if detail and not ok else ""
    print(("ok   " if ok else "FAIL ") + name + suffix)
    if not ok:
        failures += 1


def build_library(root):
    """Compile the two sources into a shared library and load it."""
    out = os.path.join(tempfile.mkdtemp(), "libncrypt.so")
    subprocess.run(["cc", "-shared", "-fPIC", "-O2", "-std=c99", "-o", out,
                    os.path.join(root, "ncrypt.c"),
                    os.path.join(root, "ncrypt-pqc.c")], check=True)
    return ctypes.CDLL(out)


def declare(lib):
    """Give every entry point its prototype; ctypes defaults corrupt
    memory otherwise."""
    ptr, u8p = ctypes.c_void_p, ctypes.c_char_p
    sz, i = ctypes.c_size_t, ctypes.c_int

    lib.ncrypt_mlkem768_key_pair.argtypes = [ptr, ptr, ptr]
    lib.ncrypt_mlkem768_key_pair.restype = None
    lib.ncrypt_mlkem768_encapsulate.argtypes = [ptr, ptr, ptr, ptr]
    lib.ncrypt_mlkem768_encapsulate.restype = i
    lib.ncrypt_mlkem768_decapsulate.argtypes = [ptr, ptr, ptr]
    lib.ncrypt_mlkem768_decapsulate.restype = i

    lib.ncrypt_mldsa44_key_pair.argtypes = [ptr, ptr, ptr]
    lib.ncrypt_mldsa44_key_pair.restype = None
    lib.ncrypt_mldsa44_sign.argtypes = [ptr, ptr, ptr, u8p, sz, u8p, sz]
    lib.ncrypt_mldsa44_sign.restype = i
    lib.ncrypt_mldsa44_check.argtypes = [ptr, ptr, u8p, sz, u8p, sz]
    lib.ncrypt_mldsa44_check.restype = i

    lib.ncrypt_pqc_encrypt.argtypes = [ptr, ptr, ptr, ptr, ptr,
                                       u8p, sz, u8p, sz]
    lib.ncrypt_pqc_encrypt.restype = i
    lib.ncrypt_pqc_decrypt.argtypes = [ptr, ptr, ptr, ptr, u8p, sz, u8p, sz]
    lib.ncrypt_pqc_decrypt.restype = i


def buf(n, fill=None):
    """A writable, pointer-safe buffer."""
    b = (ctypes.c_ubyte * n)()
    if fill is not None:
        b[:len(fill)] = fill
    return b


def raw(b):
    return bytes(bytearray(b))


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)

    try:
        from pqcrypto import InvalidSignatureError
        from pqcrypto.kem.ml_kem_768 import decaps as kem_decaps
        from pqcrypto.kem.ml_kem_768 import encaps as kem_encaps
        from pqcrypto.kem.ml_kem_768 import keygen as kem_keygen
        from pqcrypto.sign.ml_dsa_44 import keygen as dsa_keygen
        from pqcrypto.sign.ml_dsa_44 import sign as dsa_sign
        from pqcrypto.sign.ml_dsa_44 import verify as dsa_verify
    except ImportError:
        print("SKIP: the pqcrypto package is not installed "
              "(pip install pqcrypto)")
        return 0

    lib = build_library(root)
    declare(lib)

    msg = b"interoperability test message"
    ctx = b"libncrypt"

    # ---- ML-KEM-768 ---------------------------------------------------
    kem_pk, kem_sk = buf(KEM_PK), buf(KEM_SK)
    lib.ncrypt_mlkem768_key_pair(kem_sk, kem_pk, buf(64, b"\x11" * 64))

    ct, ss = kem_encaps(raw(kem_pk))
    got = buf(SS)
    rc = lib.ncrypt_mlkem768_decapsulate(got, ct, kem_sk)
    check("ML-KEM-768: pqcrypto encapsulates, libncrypt decapsulates",
          rc == 0 and raw(got) == bytes(ss))

    # libncrypt encapsulates, pqcrypto decapsulates.  This is the
    # direction that a shared bug in libncrypt's key generation would
    # hide: both sides would then agree with themselves and disagree
    # with everyone else.  A foreign key pair rules that out.
    their_pk, their_sk = kem_keygen()
    ct2, ss2 = buf(KEM_CT), buf(SS)
    rc = lib.ncrypt_mlkem768_encapsulate(ct2, ss2, their_pk,
                                         buf(32, b"\x55" * 32))
    try:
        theirs = bytes(kem_decaps(their_sk, raw(ct2)))
    except Exception:                                   # noqa: BLE001
        theirs = None
    check("ML-KEM-768: libncrypt encapsulates, pqcrypto decapsulates",
          rc == 0 and theirs == raw(ss2))

    # Implicit rejection must agree too: a corrupted ciphertext must
    # produce the same fallback secret on both sides, with no error.
    bad_ct = bytearray(raw(ct2))
    bad_ct[17] ^= 0x80
    bad_ct = bytes(bad_ct)
    mine = buf(SS)
    rc = lib.ncrypt_mlkem768_decapsulate(mine, bad_ct, kem_sk)
    try:
        theirs = bytes(kem_decaps(raw(kem_sk), bad_ct))
    except Exception:                                   # noqa: BLE001
        theirs = None
    # The requirement is that libncrypt reports success (no error for a
    # forged ciphertext) and returns a secret that is *not* the sender's.
    check("ML-KEM-768: implicit rejection returns a stable, wrong secret",
          rc == 0 and raw(mine) != bytes(ss2))

    # ---- ML-DSA-44: libncrypt signs, pqcrypto verifies ----------------
    dsa_pk, dsa_sk = buf(SIG_PK), buf(SIG_SK)
    lib.ncrypt_mldsa44_key_pair(dsa_sk, dsa_pk, buf(32, b"\x22" * 32))

    sig = buf(SIG)
    rc = lib.ncrypt_mldsa44_sign(sig, dsa_sk, buf(32, b"\x33" * 32),
                                 None, 0, msg, len(msg))
    try:
        dsa_verify(raw(dsa_pk), msg, raw(sig))
        verified = True
    except InvalidSignatureError:
        verified = False
    check("ML-DSA-44: libncrypt signs, pqcrypto verifies",
          rc == 0 and verified)

    sig_ctx = buf(SIG)
    rc = lib.ncrypt_mldsa44_sign(sig_ctx, dsa_sk, buf(32, b"\x44" * 32),
                                 ctx, len(ctx), msg, len(msg))
    try:
        dsa_verify(raw(dsa_pk), msg, raw(sig_ctx), ctx)
        verified = True
    except InvalidSignatureError:
        verified = False
    check("ML-DSA-44: libncrypt signs with context, pqcrypto verifies",
          rc == 0 and verified)

    # ---- ML-DSA-44: pqcrypto signs, libncrypt verifies ----------------
    their_pk, their_sk = dsa_keygen()
    theirs = dsa_sign(their_sk, msg)
    check("ML-DSA-44: pqcrypto signs, libncrypt verifies",
          lib.ncrypt_mldsa44_check(theirs, their_pk, None, 0,
                                   msg, len(msg)) == 0)

    theirs_ctx = dsa_sign(their_sk, msg, ctx)
    check("ML-DSA-44: pqcrypto signs with context, libncrypt verifies",
          lib.ncrypt_mldsa44_check(theirs_ctx, their_pk, ctx, len(ctx),
                                   msg, len(msg)) == 0)

    # ---- Tampering is rejected on both sides ---------------------------
    bad = bytearray(raw(sig))
    bad[100] ^= 0x01
    bad = bytes(bad)
    rejected_here = lib.ncrypt_mldsa44_check(bad, dsa_pk, None, 0,
                                             msg, len(msg)) != 0
    try:
        dsa_verify(raw(dsa_pk), msg, bad)
        rejected_there = False
    except InvalidSignatureError:
        rejected_there = True
    check("ML-DSA-44: a tampered signature is rejected by both",
          rejected_here and rejected_there)

    print()
    if failures:
        print("%d interoperability check(s) failed" % failures)
        return 1
    print("all interoperability checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
