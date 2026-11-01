#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
NOX="$ROOT/nox"
TMP="$ROOT/tests/tmp"
PASS="$TMP/pass"
PASS2="$TMP/pass2"

rm -rf "$TMP"
mkdir -p "$TMP/home" "$TMP/home2"
echo 'correct horse battery staple' > "$PASS"
echo 'other passphrase' > "$PASS2"

NOX_HOME="$TMP/home"
export NOX_HOME
# --home also works; keep env for child paths we print ourselves

die() { echo "FAIL: $*" >&2; exit 1; }

FP=$("$NOX" --home "$TMP/home" --faketime 1700000000 gen -c 'alice@example.com' --passphrase-file "$PASS")
[ ${#FP} -eq 64 ] || die "fingerprint length"
[ "$(stat -c %a "$TMP/home/.nox/$FP.sec")" = 600 ] || die "keyring secret key is not 0600"
[ "$(stat -c %a "$TMP/home/.nox")" = 700 ] || die "keyring dir is not 0700"

"$NOX" --home "$TMP/home" list | grep -q "$FP" || die "list missing fp"
"$NOX" --home "$TMP/home" list | grep -q 'alice@example.com' || die "list missing comment"
"$NOX" --home "$TMP/home" list alice | grep -q "$FP" || die "list query comment"
"$NOX" --home "$TMP/home" list "${FP%????????????????????????????????????????????????????????}" >/dev/null 2>&1 || true
PRE=$(printf '%s' "$FP" | cut -c1-8)
"$NOX" --home "$TMP/home" list "$PRE" | grep -q "$FP" || die "list query prefix"

echo 'hello noxcrypt' > "$TMP/msg"
dd if=/dev/zero bs=70000 count=1 2>/dev/null | tr '\0' 'x' > "$TMP/big"

"$NOX" --home "$TMP/home" encrypt -r "$PRE" -o "$TMP/msg.nox" "$TMP/msg"
"$NOX" --home "$TMP/home" decrypt -i "$PRE" --passphrase-file "$PASS" -o "$TMP/msg.out" "$TMP/msg.nox"
cmp "$TMP/msg" "$TMP/msg.out" || die "encrypt/decrypt mismatch"

"$NOX" --home "$TMP/home" encrypt -r "$FP" -a -o "$TMP/msg.asc" "$TMP/msg"
grep -q 'BEGIN NOX MESSAGE' "$TMP/msg.asc" || die "armor header"
"$NOX" --home "$TMP/home" decrypt -i "$FP" --passphrase-file "$PASS" -o "$TMP/msg.out2" "$TMP/msg.asc"
cmp "$TMP/msg" "$TMP/msg.out2" || die "armored encrypt/decrypt mismatch"

"$NOX" --home "$TMP/home" encrypt -r "$PRE" -o "$TMP/big.nox" "$TMP/big"
"$NOX" --home "$TMP/home" decrypt -i "$PRE" --passphrase-file "$PASS" -o "$TMP/big.out" "$TMP/big.nox"
cmp "$TMP/big" "$TMP/big.out" || die "chunked encrypt/decrypt mismatch"

: > "$TMP/empty"
"$NOX" --home "$TMP/home" encrypt -r "$PRE" -o "$TMP/empty.nox" "$TMP/empty"
"$NOX" --home "$TMP/home" decrypt -i "$PRE" --passphrase-file "$PASS" -o "$TMP/empty.out" "$TMP/empty.nox"
cmp "$TMP/empty" "$TMP/empty.out" || die "empty file mismatch"

"$NOX" --home "$TMP/home" encrypt -p --passphrase-file "$PASS2" -a -o "$TMP/pw.asc" "$TMP/msg"
"$NOX" --home "$TMP/home" decrypt -p --passphrase-file "$PASS2" -o "$TMP/pw.out" "$TMP/pw.asc"
cmp "$TMP/msg" "$TMP/pw.out" || die "passphrase encrypt/decrypt mismatch"

if "$NOX" --home "$TMP/home" decrypt -p --passphrase-file "$PASS" -o "$TMP/pw.bad" "$TMP/pw.asc" 2>"$TMP/err"; then
    die "wrong passphrase succeeded"
fi
grep -q . "$TMP/err" || die "wrong passphrase produced no error"

# ---- security regressions ------------------------------------------------

# A failed decrypt must leave the previous output file untouched.
echo 'PRECIOUS DATA' > "$TMP/clobber.out"
if "$NOX" --home "$TMP/home" decrypt -p --passphrase-file "$PASS" \
        -o "$TMP/clobber.out" "$TMP/pw.asc" 2>/dev/null; then
    die "wrong-passphrase decrypt succeeded"
fi
grep -q 'PRECIOUS DATA' "$TMP/clobber.out" ||
    die "failed decrypt destroyed the output file"

# Secret keys written with -S / export -s -o are mode 0600, whatever the umask.
FP_SEC=$(umask 077; "$NOX" --home "$TMP/sechome" --faketime 1700000000 gen \
    -c 'secfile' --passphrase-file "$PASS" -S "$TMP/exp.sec")
PRE_SEC=$(printf '%s' "$FP_SEC" | cut -c1-8)
[ "$(stat -c %a "$TMP/exp.sec")" = 600 ] || die "gen -S secret file is not 0600"
(umask 000; "$NOX" --home "$TMP/sechome" export -s -o "$TMP/exp2.sec" "$PRE_SEC")
[ "$(stat -c %a "$TMP/exp2.sec")" = 600 ] || die "export -s secret file is not 0600"
(umask 000; "$NOX" --home "$TMP/sechome" export -o "$TMP/exp.pub" "$PRE_SEC")
[ "$(stat -c %a "$TMP/exp.pub")" = 666 ] || die "export pub file mode"

# A pre-existing keyring directory with loose permissions is tightened.
mkdir -p "$TMP/loosehome/.nox"
chmod 0777 "$TMP/loosehome/.nox"
"$NOX" --home "$TMP/loosehome" gen -c 'loose' --passphrase-file "$PASS" >/dev/null
[ "$(stat -c %a "$TMP/loosehome/.nox")" = 700 ] ||
    die "keyring dir was not tightened to 0700"

# A passphrase file line that does not fit is an error, not a silent truncation.
head -c 2000 /dev/zero | tr '\0' 'a' > "$TMP/longpass"
if "$NOX" --home "$TMP/home" gen --passphrase-file "$TMP/longpass" >/dev/null 2>&1; then
    die "over-long passphrase file accepted"
fi

# Conflicting selectors are refused instead of silently picking one.
if "$NOX" --home "$TMP/home" decrypt -i "$PRE" -p --passphrase-file "$PASS" \
        -o "$TMP/cross" "$TMP/pw.asc" 2>/dev/null; then
    die "decrypt accepted -i together with -p"
fi
if "$NOX" --home "$TMP/home" verify -k "$TMP/alice.pub" -i "$PRE" \
        "$TMP/msg.sig" "$TMP/msg" >/dev/null 2>&1; then
    die "verify accepted -k together with -i"
fi

# A comment that is not valid UTF-8 is refused before the passphrase prompt.
if "$NOX" --home "$TMP/home" gen -c "$(printf 'bad \377 comment')" \
        --passphrase-file "$PASS" >/dev/null 2>&1; then
    die "gen accepted a non-UTF-8 comment"
fi

# An identity file whose comment length field overflows the 1024-byte
# comment is rejected without corrupting memory (was a stack overflow).
printf '\116\117\130\001\000\001\000\000\000\017\000\000\000\000\000\000\000\000\377\377AAAAA' \
    > "$TMP/evil.pub"
if "$NOX" --home "$TMP/home2" import "$TMP/evil.pub" >/dev/null 2>&1; then
    die "oversized-comment identity accepted by import"
fi
if "$NOX" --home "$TMP/home" verify -k "$TMP/evil.pub" "$TMP/msg.sig" "$TMP/msg" >/dev/null 2>&1; then
    die "oversized-comment identity accepted by verify"
fi

"$NOX" --home "$TMP/home" sign -i "$PRE" --passphrase-file "$PASS" -a -o "$TMP/msg.sig" "$TMP/msg"
grep -q 'BEGIN NOX SIGNATURE' "$TMP/msg.sig" || die "sig armor"
GOOD=$("$NOX" --home "$TMP/home" verify "$TMP/msg.sig" "$TMP/msg")
[ "$GOOD" = "Good signature" ] || die "verify output was '$GOOD'"

echo 'tampered' > "$TMP/msg.bad"
if "$NOX" --home "$TMP/home" verify "$TMP/msg.sig" "$TMP/msg.bad" >/dev/null 2>&1; then
    die "tampered message verified"
fi

"$NOX" --home "$TMP/home" export -a -o "$TMP/alice.pub" "$PRE"
"$NOX" --home "$TMP/home" export -s -a -o "$TMP/alice.sec" "$PRE"
grep -q 'BEGIN NOX PUBLIC KEY' "$TMP/alice.pub" || die "export pub armor"
grep -q 'BEGIN NOX SECRET KEY' "$TMP/alice.sec" || die "export sec armor"

"$NOX" --home "$TMP/home2" import "$TMP/alice.pub"
"$NOX" --home "$TMP/home2" list | grep -q "$FP" || die "import pub"
"$NOX" --home "$TMP/home2" import --passphrase-file "$PASS" "$TMP/alice.sec" >/dev/null
"$NOX" --home "$TMP/home2" encrypt -r "$PRE" -o "$TMP/h2.nox" "$TMP/msg"
"$NOX" --home "$TMP/home2" decrypt -i "$PRE" --passphrase-file "$PASS" -o "$TMP/h2.out" "$TMP/h2.nox"
cmp "$TMP/msg" "$TMP/h2.out" || die "imported secret cannot decrypt"

# pipes
printf 'piped' | "$NOX" --home "$TMP/home" encrypt -r "$PRE" -a | \
    "$NOX" --home "$TMP/home" decrypt -i "$PRE" --passphrase-file "$PASS" > "$TMP/pipe.out"
[ "$(cat "$TMP/pipe.out")" = "piped" ] || die "pipe round-trip"

# public round-trip via re-export
"$NOX" --home "$TMP/home2" export -o "$TMP/alice2.pub" "$FP"
"$NOX" --home "$TMP/home" export -o "$TMP/alice1.pub" "$FP"
cmp "$TMP/alice1.pub" "$TMP/alice2.pub" || die "public export not stable"

"$NOX" --home "$TMP/home2" delete "$PRE"
if "$NOX" --home "$TMP/home2" list | grep -q "$FP"; then
    die "delete left the key"
fi

# ---- algorithm profiles ------------------------------------------------

# One keyring per profile, each with a full signing and encryption
# round-trip.  Prints the fingerprint of the key it made.
run_profile() {
    name=$1
    opts=$2
    want=$3
    home="$TMP/$name"

    mkdir -p "$home"
    fp=$("$NOX" --home "$home" --faketime 1700000100 gen $opts \
         -c "$name key" --passphrase-file "$PASS") || die "$name: gen"
    [ ${#fp} -eq 64 ] || die "$name: fingerprint length"
    pre=$(printf '%s' "$fp" | cut -c1-8)

    "$NOX" --home "$home" list | grep -q "^$fp" || die "$name: list fingerprint"
    "$NOX" --home "$home" list | grep -q "$want" || die "$name: list profile"
    "$NOX" --home "$home" list | grep -q "^  \"$name key\"$" || die "$name: list comment"
    "$NOX" --home "$home" list | grep -q "$(date -u -d @1700000100 +%Y-%m-%d)" ||
        die "$name: list date"

    "$NOX" --home "$home" encrypt -r "$pre" -o "$TMP/$name.nox" "$TMP/big"
    "$NOX" --home "$home" decrypt -i "$pre" --passphrase-file "$PASS" \
        -o "$TMP/$name.out" "$TMP/$name.nox"
    cmp "$TMP/big" "$TMP/$name.out" || die "$name: encrypt/decrypt mismatch"

    "$NOX" --home "$home" sign -i "$pre" --passphrase-file "$PASS" \
        -o "$TMP/$name.sig" "$TMP/msg"
    [ "$("$NOX" --home "$home" verify "$TMP/$name.sig" "$TMP/msg")" = "Good signature" ] ||
        die "$name: verify"

    "$NOX" --home "$home" export -a -o "$TMP/$name.pub" "$pre"
    "$NOX" --home "$TMP/$name-ro" import "$TMP/$name.pub" > /dev/null
    "$NOX" --home "$TMP/$name-ro" list | grep -q '(no secret key)' ||
        die "$name: public-only key not marked"
    "$NOX" --home "$TMP/$name-ro" list | grep -q "$want" ||
        die "$name: profile lost on import"

    echo "$fp"
}

FP_ECC=$(run_profile ecc "-A ecc" "ecc: Ed25519 + X25519")
FP_PQC=$(run_profile pqc "-A pqc" "pqc: ML-DSA-44 + ML-KEM-768")
FP_MIX=$(run_profile mixed "--sig ed25519 --kem mlkem768" "mixed: Ed25519 + ML-KEM-768")

# A key only reads the recipient flavor that matches its own algorithms.
if "$NOX" --home "$TMP/ecc" decrypt -i "$FP_ECC" --passphrase-file "$PASS" \
        -o "$TMP/cross" "$TMP/msg.nox" 2>/dev/null; then
    die "ecc key decrypted a hybrid message"
fi
if "$NOX" --home "$TMP/home" decrypt -i "$PRE" --passphrase-file "$PASS" \
        -o "$TMP/cross" "$TMP/ecc.nox" 2>/dev/null; then
    die "hybrid key decrypted an ecc message"
fi
if "$NOX" --home "$TMP/pqc" decrypt -i "$FP_PQC" --passphrase-file "$PASS" \
        -o "$TMP/cross" "$TMP/mixed.nox" 2>/dev/null; then
    die "pqc key decrypted a mixed message"
fi

# Bad selections are refused before anything is written.
if "$NOX" --home "$TMP/home" gen -A bogus --passphrase-file "$PASS" >/dev/null 2>&1; then
    die "gen accepted an unknown profile"
fi
if "$NOX" --home "$TMP/home" gen --sig ed25519 --passphrase-file "$PASS" >/dev/null 2>&1; then
    die "gen accepted --sig without --kem"
fi
if "$NOX" --home "$TMP/home" gen --sig x25519 --kem mlkem768 \
        --passphrase-file "$PASS" >/dev/null 2>&1; then
    die "gen accepted an encryption algorithm as --sig"
fi

# ---- info and version --------------------------------------------------

"$NOX" --home "$TMP/home" info | grep -q "^nox " || die "info version"
"$NOX" --home "$TMP/home" info | grep -q "Robert Yates Stanford" || die "info author"
"$NOX" --home "$TMP/home" info | grep -q "1 public key, 1 secret key" ||
    die "info keyring counts"
"$NOX" --version | grep -q "^nox " || die "--version"
"$NOX" gen --help | grep -q "^Usage: nox gen" || die "gen --help"
"$NOX" info --help | grep -q "^Usage: nox info" || die "info --help"
"$NOX" list --help | grep -q "^Usage: nox list" || die "list --help"

echo "test.sh: ok"
