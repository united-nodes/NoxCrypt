# NoxCrypt Format Specification

Format: NoxCrypt v1
Status: draft, implemented by nox 1.0.0
Date: 2026-11-01
Review record: [REVIEW.md](../REVIEW.md)

This document specifies the NoxCrypt version 1 wire format in full. A
v1 generator MUST emit only the packet types and algorithms listed
here, and MUST NOT set the critical bit on any packet. A v1 parser
MUST reject input it does not understand rather than guess. When this
text and the code disagree, that is a bug in one of them; the test
suite and the review record describe which one was right.

Contents:

1. [Goals and model](#1-goals-and-model)
2. [File framing](#2-file-framing)
3. [Domain separation](#3-domain-separation)
4. [Identity](#4-identity)
5. [Secret key](#5-secret-key)
6. [Encrypted message](#6-encrypted-message)
7. [Detached signature](#7-detached-signature)
8. [ASCII armor](#8-ascii-armor)
9. [Keyring](#9-keyring)
10. [Command line](#10-command-line)
11. [Cryptographic primitives](#11-cryptographic-primitives)
12. [Limits](#12-limits)
13. [Security notes](#13-security-notes)

## 1. Goals and model

NoxCrypt is a small Linux tool for hybrid (classical plus
post-quantum) encryption and signatures. It follows the Unix
tradition of age and minisign: one subcommand per job, pipes, plain
files, auditable C, and no network protocol.

The model, in seven sentences:

- An identity holds at least one signing algorithm (Ed25519 or
  ML-DSA-44) and at least one encryption algorithm (X25519 or
  ML-KEM-768). The generator offers the profiles `hybrid` (all four),
  `ecc` (Ed25519 + X25519), `pqc` (ML-DSA-44 + ML-KEM-768), and a
  hand-picked `mixed` pair.
- Which algorithms an identity holds decides how it is addressed. The
  generator emits exactly one recipient flavor per identity: `0x0005`
  when it holds both X25519 and ML-KEM-768, `0x0001` when it holds
  only X25519, `0x0003` when it holds only ML-KEM-768.
- A decryptor only accepts the flavor its own key set implies. A
  hybrid identity never unwraps a single-algorithm recipient, and a
  single-algorithm identity never unwraps a hybrid recipient.
- ML-KEM-768 never encrypts bytes. Its shared secret is hashed into a
  key that wraps the random file key under XChaCha20-Poly1305; the
  hybrid flavor mixes an ephemeral X25519 Diffie-Hellman into that
  hash first.
- A passphrase recipient (`0x0006`) is exclusive. If it is present it
  is the only recipient.
- Secret keys are always wrapped with Argon2id and XChaCha20-Poly1305.
  Unprotected private key material never reaches disk or stdout.
- Randomness comes from the operating system: `getrandom(2)` on
  Linux, blocking until the pool is initialized.

## 2. File framing

Every binary document begins with a 4-byte magic:

```
0x4E 0x4F 0x58 0x01      "NOX" || format version
```

Version `0x01` is this specification. Any other value in the fourth
byte is rejected.

The rest of the file is a sequence of packets. A document contains
exactly one top-level packet after the magic, with one exception: a
ciphertext is an Encrypted Header packet followed by Chunk packets.
Trailing bytes after the top-level packet, or after the final Chunk,
are an error.

### 2.1 Packet

```
type    u16     bit 15 is the critical flag, bits 14..0 the type
length  u32     number of bytes in value
value   bytes   exactly `length` bytes
```

Type `0` is reserved and illegal. If `length` exceeds the remaining
input, the document is truncated and MUST be rejected.

If bit 15 is set and the packet type is unknown, parsing fails. If
bit 15 is clear and the type is unknown, a v1 parser skips the
packet. A v1 generator MUST NOT set bit 15 and MUST NOT emit unknown
types.

### 2.2 Packet types

| Type     | Name               | Where it appears                        |
|----------|--------------------|-----------------------------------------|
| `0x0001` | Identity           | public key file (top-level)             |
| `0x0002` | Secret             | secret key file (top-level)             |
| `0x0003` | Encrypted Header   | ciphertext (top-level, then Chunks)     |
| `0x0004` | Detached Signature | signature file (top-level)              |
| `0x0010` | Public Key         | inside Identity                         |
| `0x0011` | Secret Key         | inside unlocked Secret plaintext        |
| `0x0012` | Signature          | inside Identity, Detached Signature     |
| `0x0013` | Recipient          | inside Encrypted Header                 |
| `0x0014` | Chunk              | ciphertext payload                      |

### 2.3 Algorithms

| Id       | Name        | Role                                       |
|----------|-------------|--------------------------------------------|
| `0x0001` | X25519      | encryption key, X25519 file-key wrap       |
| `0x0002` | Ed25519     | signatures                                 |
| `0x0003` | ML-KEM-768  | encryption key, ML-KEM file-key wrap       |
| `0x0004` | ML-DSA-44   | signatures                                 |
| `0x0005` | Hybrid      | X25519 + ML-KEM-768 file-key wrap          |
| `0x0006` | Argon2id    | passphrase file-key wrap                   |

Which wrap appears is decided by the recipient identity, never by a
preference of the sender. `0x0001` and `0x0003` exist for identities
that carry a single encryption algorithm. An identity holding both
X25519 and ML-KEM-768 MUST be wrapped with `0x0005`, and a decryptor
holding both MUST NOT unwrap `0x0001` or `0x0003`. A message MAY mix
recipients of different flavors, up to the recipient limit.

### 2.4 Usage bits (Public Key, Secret Key)

```
bit 0  0x01  ENCRYPT
bit 1  0x02  SIGN
bit 2  0x04  AUTH
```

X25519 and ML-KEM-768 MUST carry usage `0x01` and nothing else.
Ed25519 and ML-DSA-44 MUST NOT set ENCRYPT and MUST set at least one
of SIGN or AUTH. The generator writes Ed25519 as `SIGN|AUTH`
(`0x06`) and ML-DSA-44 as `SIGN` (`0x02`).

### 2.5 Secret encodings

| Value  | Meaning                                   |
|--------|-------------------------------------------|
| `0x01` | seed (what the generator always writes)   |
| `0x02` | expanded secret (accepted on import)      |

Seed lengths: X25519 32, Ed25519 32, ML-KEM-768 64, ML-DSA-44 32.
Expanded lengths: X25519 32, Ed25519 64, ML-KEM-768 2400, ML-DSA-44
2560.

A secret is always checked against its public half after expansion:
the public key is recomputed and compared. A mismatch is a hard
error. libncrypt wipes seeds handed to its key generation and
encapsulation functions, so a caller that needs to keep a seed copies
it first.

## 3. Domain separation

Every hash input and every AEAD additional-data input starts with a
UTF-8 constant, used without a terminating NUL:

| Constant                       | Used for                          |
|--------------------------------|-----------------------------------|
| `noxcrypt/v1/identity`         | identity self-signatures          |
| `noxcrypt/v1/fingerprint`      | fingerprint hash                  |
| `noxcrypt/v1/signature`        | detached signatures               |
| `noxcrypt/v1/secret`           | secret-key wrapping AD            |
| `noxcrypt/v1/header`           | file-key wrapping AD              |
| `noxcrypt/v1/payload`          | chunk AEAD AD                     |
| `noxcrypt/v1/x25519-wrap`      | X25519 DH transcript hash         |
| `noxcrypt/v1/mlkem768-wrap`    | ML-KEM transcript hash            |
| `noxcrypt/v1/hybrid-wrap`      | combination of the two wraps      |

## 4. Identity

A public key file is:

```
magic || Identity packet
```

`Identity.value`:

```
created      u64     Unix seconds
comment_len  u16     byte length of comment
comment      bytes   UTF-8, no NUL, no CR, no LF, at most 1024 bytes
PublicKey packets    one or more, contiguous
optional unknown non-critical packets
Signature packets    one per SIGN key, same order as those keys
```

`comment_len` is a 16-bit field, but values above 1024 are invalid
and MUST be rejected before the comment is copied anywhere. The
Identity packet (and therefore `Identity.value`) is at most 65536
bytes. A public key file MUST NOT contain bytes after the Identity
packet, and `Identity.value` MUST end at the last required Signature
packet. Extra bytes inside the value are rejected.

`PublicKey.value`:

```
alg     u16
usage   u8
key     bytes    length fixed by alg:
                 X25519, Ed25519: 32
                 ML-KEM-768: 1184
                 ML-DSA-44: 1312
```

`Signature.value` (inside an identity):

```
alg     u16
sig     bytes    Ed25519: 64, ML-DSA-44: 2420
```

Each SIGN key signs, in order:

```
"noxcrypt/v1/identity" || Identity.value[0 .. body)
```

where `body` is everything in `Identity.value` before the first
Signature packet.

Public Key packets appear in a fixed order, signing keys first, with
unused algorithms left out:

1. Ed25519, usage `0x06`
2. ML-DSA-44, usage `0x02`
3. X25519, usage `0x01`
4. ML-KEM-768, usage `0x01`

The order is covered by the fingerprint, so it is part of the format
and not a choice of the encoder. The generator writes one Signature
packet per SIGN key, in the same order. An identity with no SIGN key
is invalid. An identity with no ENCRYPT key parses, but nothing can
be encrypted to it.

The four combinations the CLI generates are named after their key
sets: `hybrid` (all four), `ecc` (Ed25519 + X25519), `pqc`
(ML-DSA-44 + ML-KEM-768), and `mixed` (one signing plus one
encryption algorithm chosen by hand).

### 4.1 Fingerprint

The fingerprint is BLAKE2b-256 of

```
"noxcrypt/v1/fingerprint" || concatenated PublicKey packets
```

It is displayed as 64 lowercase hex characters. Commands that select
a key accept a prefix of at least 8 hex characters and fail when the
prefix matches more than one key.

## 5. Secret key

A secret key file is:

```
magic || Secret packet
```

Secret keys are always passphrase-protected. `Secret.value`:

```
t           u32     Argon2id passes
m           u32     Argon2id memory in KiB
p           u32     Argon2id lanes
outlen      u32     must be 32
salt_len    u8      must be 16
salt        16
nonce       24      XChaCha20-Poly1305 nonce
mac         16
ciphertext  rest    AEAD of the secret plaintext
```

v1 writes `t = 3`, `m = 65536`, `p = 1`. The parameters travel in
the document so a reader can open files written with other
parameters. Because those bytes are attacker controlled, a parser
MUST enforce caps: warn on stderr (and MAY continue) when `t < 3` or
`m < 16384`; reject `m > 2^21`; reject `t > 64`. With the memory cap,
the time cap bounds the total KDF work at `2^27` KiB-passes, roughly
680 times the v1 default, which keeps a hostile document from tying
up a decoder for hours.

The wrapping key is Argon2id(passphrase, salt, t, m, p) with a
32-byte output. The AEAD additional data is:

```
"noxcrypt/v1/secret" || magic || Secret.value[0 .. 33)
```

That is the KDF parameters and the salt. The nonce and MAC are not
part of the AD.

The decrypted plaintext is:

```
Identity.value (exactly as in the public file) ||
SecretKey packet for each public key, same order
```

`SecretKey.value`:

```
alg        u16
usage      u8     must match the corresponding Public Key
encoding   u8     0x01 seed, 0x02 expanded
material   bytes  length from section 2.5
```

After unlock, every secret is expanded and checked against its
public key, as described in section 2.5. The parser MUST verify the
identity self-signatures over the embedded `Identity.value`, so a
tampered plaintext fails even if the AEAD somehow passed.

## 6. Encrypted message

```
magic || Encrypted Header packet || Chunk packets
```

`Encrypted Header.value`:

```
payload_nonce   24     XChaCha20-Poly1305 extended nonce
Recipient packets
```

The header is at most 256 KiB. There are at most 16 recipients. If
any recipient uses algorithm `0x0006`, it MUST be the only one.
Unknown non-critical packets in the header are skipped. A Recipient
packet with an unknown algorithm is skipped unless the critical bit
is set, in which case parsing fails. A sender MAY therefore address
one message to identities of different profiles: each becomes its
own Recipient packet.

The 32-byte file key is random and is wrapped once per recipient.
The wrapping AEAD additional data is:

```
"noxcrypt/v1/header" || magic || payload_nonce
```

Every ephemeral X25519 key pair and every encapsulation seed below
is fresh, drawn from the OS CSPRNG for each recipient of each
message.

### 6.1 Hybrid recipient (`0x0005`)

Used for identities that hold both X25519 and ML-KEM-768.

`Recipient.value` (1226 bytes):

```
alg          u16     0x0005
fingerprint  32      recipient identity fingerprint
eph_pk       32      ephemeral X25519 public key
kem_ct       1088    ML-KEM-768 ciphertext
nonce        24
mac          16
wrapped      32      AEAD ciphertext of the file key
```

Sender derivation:

1. Generate an ephemeral X25519 key pair; `eph_pk` is the public half.
2. `raw = X25519(eph_sk, recipient_x25519_pk)`. An all-zero `raw`
   aborts the encryption.
3. `xk = BLAKE2b-256("noxcrypt/v1/x25519-wrap" || eph_pk || recipient_x25519_pk || raw)`
4. Encapsulate to the recipient ML-KEM-768 public key, producing
   `kem_ct` and shared secret `ss`.
5. `kk = BLAKE2b-256("noxcrypt/v1/mlkem768-wrap" || kem_ct || recipient_mlkem_pk || ss)`
6. `wk = BLAKE2b-256("noxcrypt/v1/hybrid-wrap" || xk || kk || fingerprint)`
7. AEAD-lock the file key under `wk` with the header AD.

The recipient computes the same values with `(recipient_x25519_sk,
eph_pk)` and ML-KEM decapsulation, then unlocks. Both hashes bind
the full transcripts, so a substituted key or ciphertext cannot move
undetected between recipients. A hybrid identity MUST NOT be
unwrapped through an `0x0001` or `0x0003` recipient even when its
key material could.

### 6.2 X25519 recipient (`0x0001`)

Used for identities whose only encryption algorithm is X25519.

`Recipient.value` (138 bytes):

```
alg          u16     0x0001
fingerprint  32      recipient identity fingerprint
eph_pk       32      ephemeral X25519 public key
nonce        24
mac          16
wrapped      32      AEAD ciphertext of the file key
```

Sender derivation:

1. Generate an ephemeral X25519 key pair.
2. `raw = X25519(eph_sk, recipient_x25519_pk)`. An all-zero `raw`
   aborts the encryption.
3. `wk = BLAKE2b-256("noxcrypt/v1/x25519-wrap" || eph_pk || recipient_x25519_pk || raw)`
4. AEAD-lock the file key under `wk` with the header AD.

The recipient repeats step 2 with `(recipient_x25519_sk, eph_pk)`.
Both sides hash the same three inputs in the same order: the
ephemeral public key, the recipient static public key, and the raw
shared secret.

### 6.3 ML-KEM-768 recipient (`0x0003`)

Used for identities whose only encryption algorithm is ML-KEM-768.

`Recipient.value` (1194 bytes):

```
alg          u16     0x0003
fingerprint  32      recipient identity fingerprint
kem_ct       1088    ML-KEM-768 ciphertext
nonce        24
mac          16
wrapped      32      AEAD ciphertext of the file key
```

Sender derivation:

1. Encapsulate to the recipient ML-KEM-768 public key, producing
   `kem_ct` and shared secret `ss`.
2. `wk = BLAKE2b-256("noxcrypt/v1/mlkem768-wrap" || kem_ct || recipient_mlkem_pk || ss)`
3. AEAD-lock the file key under `wk` with the header AD.

The recipient decapsulates and repeats step 2. ML-KEM contributes
key material only; the payload is always protected by
XChaCha20-Poly1305. A malformed encapsulation key is rejected by the
sender at encryption time. Decapsulation of a forged ciphertext
yields an unrelated secret (FIPS 203 implicit rejection), which then
fails the AEAD check.

### 6.4 Passphrase recipient (`0x0006`)

`Recipient.value` (107 bytes):

```
alg        u16     0x0006
t m p      u32     Argon2id parameters, same layout as Secret
outlen     u32     32
salt_len   u8      16
salt       16
nonce      24
mac        16
wrapped    32
```

The file key is AEAD-locked under Argon2id(passphrase) with the
header additional data. The KDF parameter caps of section 5 apply
here as well. A v1 writer always uses `t = 3`, `m = 65536`, `p = 1`.

### 6.5 Payload chunks

The payload is XChaCha20-Poly1305 in streaming mode, initialized
with the file key and `payload_nonce`. The stream rekeys after every
chunk, so a chunk removed from the middle fails to authenticate in
its new position. Truncation is caught by the final-chunk flag.

`Chunk.value`:

```
mac          16
ciphertext   rest    at most 65536 bytes of plaintext
```

Additional data for the chunk with index `i`, counting from zero:

```
"noxcrypt/v1/payload" || i (u64 big-endian) || last (u8)
```

`last` is `0x01` for the final chunk of the message and `0x00` for
every other chunk. Non-final chunks MUST carry exactly 65536
plaintext bytes. The final chunk MAY be empty, which is how the
empty file and files whose length is a multiple of 65536 are
encoded. A reader MUST try a chunk as non-final first and as final
only if that fails, MUST reject a non-final chunk whose plaintext
size is not 65536, and MUST reject bytes after the final chunk. A
ciphertext with no final chunk is truncated and rejected.

## 7. Detached signature

```
magic || Detached Signature packet
```

`Detached Signature.value`:

```
created       u64
fingerprint   32      signer identity
Signature packets     one per SIGN key of that identity, same order
```

Let `H = BLAKE2b-256(message)`, computed by streaming the message;
the message never has to fit in memory. Each SIGN key signs:

```
"noxcrypt/v1/signature" || created || fingerprint || H
```

Ed25519 signs that message directly (PureEdDSA, no prehash).
ML-DSA-44 signs it as pure ML-DSA with an empty context string and
hedged randomness: the signer mixes 32 fresh random bytes into each
signature as FIPS 204 recommends, so signing the same message twice
produces different signature bytes that both verify. The
deterministic variant is not used by v1 writers; verifiers accept
either, since verification is identical.

A signer emits one Signature packet per SIGN key of its identity, in
identity order, and nothing else: one packet for an ecc or pqc
identity, two for a hybrid one. A verifier MUST require exactly the
SIGN keys of the identity it checks against, no more and no fewer.
A signature that drops ML-DSA-44 from a hybrid identity, or that
carries an algorithm the identity does not have, is rejected. On
success the CLI prints exactly:

```
Good signature
```

## 8. ASCII armor

Armored documents are PEM-style RFC 4648 base64 (with `+` and `/`,
padded with `=`), wrapped at 64 columns:

```
-----BEGIN NOX KIND-----
<blank line>
<base64 body>
-----END NOX KIND-----
```

`KIND` is one of `PUBLIC KEY`, `SECRET KEY`, `MESSAGE`, `SIGNATURE`.
Writers are strict: the blank line, the 64-column body, the newline
after the last body line, and the END line are always exactly as
shown, so armored output is reproducible byte for byte.

Readers are lenient:

- Leading and trailing whitespace is ignored.
- A UTF-8 BOM before the armor is skipped.
- Header lines between BEGIN and the first blank line are ignored.
- A body that starts without the blank line is accepted: the first
  base64-looking line after BEGIN is treated as the body.
- Missing base64 padding is tolerated. Whitespace may appear
  anywhere inside the body.

A document that is neither binary (magic `NOX\x01`) nor armor is
rejected. Writing a binary document to a terminal is refused unless
`--armor` is set; plaintext produced by `decrypt` is exempt, since
the terminal is a legitimate output for text.

## 9. Keyring

Default directory: `$NOX_HOME/.nox` when `NOX_HOME` is set,
otherwise `~/.nox`. The directory is created with mode `0700`,
including missing parents. An existing directory with looser
permissions MUST be tightened to `0700` before keys are written; a
tool that cannot tighten it MUST refuse to run.

Each identity is two files, mode `0600`:

```
<64-hex-fingerprint>.pub
<64-hex-fingerprint>.sec
```

Writes are atomic: a key file is created under a temporary name in
the same directory and renamed into place, so a crash leaves either
the old or the new file, never a half-written one. Key file names
that do not match 64 hex characters plus `.pub` or `.sec` are
ignored by every keyring command.

`nox list` prints one block per identity: fingerprint and UTC
creation date on the first line, profile with algorithms on the
second, comment in double quotes on the third. Identities whose
secret half is absent are marked `(no secret key)`. Blocks are
sorted by fingerprint, since directory order is arbitrary. A query
matches a fingerprint prefix or a substring of the comment.

## 10. Command line

```
nox [--faketime UNIX] [--home DIR] COMMAND [OPTIONS]
```

Global options come before the command name.

| Command   | Purpose                                                  |
|-----------|----------------------------------------------------------|
| `gen`     | generate an identity, always passphrase-wrapped          |
| `encrypt` | `-r` fingerprint, `-R` public file, or `-p` passphrase   |
| `decrypt` | `-i` identity, or `-p` for a passphrase ciphertext       |
| `sign`    | detached signature                                       |
| `verify`  | prints `Good signature` on success                       |
| `list`    | list the keyring                                         |
| `export`  | `-s` for the secret half                                 |
| `import`  | public or secret; a secret key needs its passphrase      |
| `delete`  | remove both halves of a key                              |
| `info`    | version, author, algorithms, keyring summary             |

`gen` selects algorithms with `-A hybrid|ecc|pqc`, or with
`--sig ALG --kem ALG` for a hand-picked pair. Giving neither is the
same as `-A hybrid`. There are no algorithm flags at use time:
`encrypt`, `sign`, and `verify` read what the identity holds.

Selected keys are named by a fingerprint prefix of at least 8 hex
characters. `decrypt -i` and `-p` are exclusive. `verify -k` and
`-i` are exclusive. When a command could act on exactly one secret
key, the key may be left unnamed; with several, it cannot.

Standard input and standard output are used wherever a path is
omitted or given as `-`.

Output files (`-o`, `--pub`, `--sec`) are created under a temporary
name in the destination directory with mode `0600`, written
completely, given their final mode, and renamed. A command that
fails part way leaves the previous content of the output file
untouched. Secret key output keeps mode `0600`; all other output
gets the usual `0666` masked by the umask.

Passphrases are read from `/dev/tty` with echo off. Terminal
attributes are restored on success, on error, and on the usual
terminating signals. `--passphrase-file` reads the first line of a
file; a line longer than 1023 bytes is an error, not a truncation.
Empty passphrases are rejected. `gen` asks twice and refuses a
mismatch.

Exit status: `0` on success, `1` on any operation failure (bad
passphrase, no matching key, unauthenticated input, malformed
file), `2` on a usage error (unknown command or option). A missing
operand is reported as `1`.

## 11. Cryptographic primitives

All primitives come from libncrypt, consumed as a git submodule
pinned to its 1.0.0 release. libncrypt is a namespace-renamed port
of Monocypher 4.0.3 plus ML-KEM-768 and ML-DSA-44 cores derived from
the FIPS 203 / FIPS 204 reference implementations. No other
dependency exists; liboqs is not used.

- XChaCha20-Poly1305 (`ncrypt_aead_lock`, `ncrypt_aead_unlock`,
  `ncrypt_aead_init_x`, `ncrypt_aead_write`, `ncrypt_aead_read`)
- X25519 (`ncrypt_x25519`, `ncrypt_x25519_public_key`)
- Ed25519 (`ncrypt_ed25519_key_pair`, `ncrypt_ed25519_sign`,
  `ncrypt_ed25519_check`), PureEdDSA without prehash
- BLAKE2b (`ncrypt_blake2b*`), used at 32-byte output
- Argon2id (`ncrypt_argon2`)
- ML-KEM-768 (`ncrypt_mlkem768_key_pair`, `ncrypt_mlkem768_encapsulate`,
  `ncrypt_mlkem768_decapsulate`)
- ML-DSA-44 (`ncrypt_mldsa44_key_pair`, `ncrypt_mldsa44_sign`,
  `ncrypt_mldsa44_check`), pure with empty context, hedged signing
  randomness

Entry points that exist in the library but MUST NOT be called by a
v1 implementation: `ncrypt_ed25519_ph_*` (prehashed Ed25519),
`ncrypt_x25519_to_eddsa`, `ncrypt_elligator_*`,
`ncrypt_x25519_dirty_*`, `ncrypt_pqc_encrypt`,
`ncrypt_pqc_decrypt`, and `ncrypt_mldsa44_sign_deterministic`.
X25519 keys and Ed25519 keys are never converted into one another.

## 12. Limits

| Limit                         | Value         |
|-------------------------------|---------------|
| Identity.value                | 65536 bytes   |
| Comment                       | 1024 bytes    |
| Keys per identity             | 8             |
| Signing keys (generator)      | 2             |
| Encryption keys (generator)   | 2             |
| Recipients per message        | 16            |
| Encrypted Header.value        | 256 KiB       |
| Chunk plaintext               | 65536 bytes   |
| Passphrase                    | 1023 bytes    |
| Argon2id m                    | 8*p .. 2^21 KiB |
| Argon2id t                    | 1 .. 64       |

## 13. Security notes

- Parsers fail closed. There is no recovery mode that ignores a
  broken required packet, no type 0, and no critical-bit surprises
  from a v1 generator.
- Hybrid documents require their post-quantum half. Stripping
  ML-KEM from a hybrid recipient, or ML-DSA-44 from a hybrid
  signature, yields a document that is rejected, not a weaker one
  that happens to work.
- Every AEAD call authenticates the transcript it depends on: the
  recipient hashes cover the ephemeral key, the KEM ciphertext, and
  the recipient public keys; the chunk AD covers the chunk index and
  the final flag; the wrapping ADs cover the magic and the nonce.
- An `ecc` identity provides no protection against a quantum
  computer. That is what the name means. Choose it deliberately.
- Streaming decryption writes plaintext as chunks authenticate. A
  failure late in the file cannot un-write earlier chunks. Callers
  that need all-or-nothing semantics should let the CLI write to a
  file (it renames only on success) or redirect to a temporary file.
- Argon2id defaults (t=3, m=65536, p=1) are a desktop parameter set.
  They raise the cost of guessing; they do not rescue a weak
  passphrase.
- This specification is a draft and the implementation has not seen
  an independent audit. See [REVIEW.md](../REVIEW.md) for what has
  been checked, by whom, and with what tools.
