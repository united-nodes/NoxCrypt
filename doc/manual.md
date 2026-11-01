# NoxCrypt manual

This is the long form of the `nox(1)` man page: what the tool is
for, how the pieces fit together, and which parts deserve care. The
wire format is specified in [SPEC.md](SPEC.md), which is the document
to read if you want to implement a compatible tool. What was checked
about this implementation, and with what tools, is recorded in
[REVIEW.md](REVIEW.md).

## What NoxCrypt is

NoxCrypt encrypts files and streams to a public key and signs data
with a secret key. Two ideas shape it:

- Every key pair is hybrid by default. An identity carries an
  Ed25519 and an ML-DSA-44 signing key plus an X25519 and an
  ML-KEM-768 encryption key. A message stays readable only while
  both the classical and the post-quantum assumption hold.
- Everything else stays small. No configuration file, no daemon, no
  key server, no network code, no plugin system. One subcommand does
  one thing, plain files go in and out, and a pipe is a first-class
  citizen.

The short version: it is `age` plus `minisign`, with post-quantum
algorithms, a keyring under `~/.nox`, and a passphrase on every
secret key.

## Building and installing

The one dependency is libncrypt, consumed as a git submodule pinned
to its 1.0.0 release. A recursive clone fetches it; otherwise check
it out first:

```
git clone --recursive https://github.com/RYSF13/NoxCrypt
cd NoxCrypt
git submodule update --init     # no-op after a recursive clone
make                            # builds ./nox
make test                       # unit tests plus a CLI round-trip
make install                    # honors PREFIX, DESTDIR, BINDIR, MANDIR
```

The build needs a C11 compiler and nothing else. The post-quantum
code is inside the submodule, so liboqs is not required. If `make`
complains that libncrypt is not checked out, run the submodule
command shown above. The test suite spends a few seconds in Argon2id
on purpose.

## Identities

An identity is one key pair. Generating one writes two files into
the keyring and prints the fingerprint:

```
$ nox gen -c 'alice@example.com'
nox: fingerprint  7f3c9d02...8b41
nox: algorithms   hybrid: Ed25519 + ML-DSA-44 + X25519 + ML-KEM-768
nox: public key   /home/alice/.nox/7f3c9d02....pub
nox: secret key   /home/alice/.nox/7f3c9d02....sec
7f3c9d02...8b41
```

The fingerprint is 64 hex characters: BLAKE2b-256 over the public
key packets, in the order the file stores them. It does not depend
on the comment or the creation date, so it is stable across every
re-encoding. The comment and the date are covered by the identity's
self-signatures, so a comment cannot be swapped without breaking the
public key.

Commands that need a key accept any unambiguous prefix of at least
eight hex characters. Eight characters are 32 bits, fine for picking
a key from your own keyring and useless as a global identifier.
Export the full fingerprint when two machines have to agree on one.

A comment is at most 1024 bytes of UTF-8 with no line breaks and no
NUL bytes. It is validated before the passphrase is asked for, so a
rejected comment costs you nothing.

## Algorithm profiles

`gen` writes one of four kinds of identity.

| Profile  | Signing             | Encryption          | Notes                      |
|----------|---------------------|---------------------|----------------------------|
| `hybrid` | Ed25519 + ML-DSA-44 | X25519 + ML-KEM-768 | the default                |
| `ecc`    | Ed25519             | X25519              | classical only, tiny keys  |
| `pqc`    | ML-DSA-44           | ML-KEM-768          | post-quantum only          |
| mixed    | one, by `--sig`     | one, by `--kem`     | e.g. Ed25519 + ML-KEM-768  |

```
nox gen -A hybrid -c 'default'
nox gen -A ecc    -c 'classical fallback'
nox gen -A pqc    -c 'nothing classical'
nox gen --sig ed25519 --kem mlkem768 -c 'curious mixture'
```

Key sizes, for capacity planning: ML-DSA-44 signatures are 2420
bytes, ML-KEM-768 public keys are 1184 bytes and its ciphertexts are
1088 bytes. An encrypted message carries one recipient packet per
recipient, so a hybrid recipient costs about 1.2 KiB of header.

Which profile to pick depends on what you are protecting against:

- **hybrid** is the right default. An attacker must break a
  classical assumption and a post-quantum one. A ciphertext recorded
  today stays unreadable while either half holds.
- **ecc** exists because the classical algorithms are small, fast,
  and well studied, and because some environments want the smaller
  keys. A recorded ciphertext from an `ecc` key becomes readable the
  day a quantum computer arrives.
- **pqc** drops the classical assumptions entirely. Use it when
  trust in discrete-log cryptography is the concern. Budget the
  space, and note that it is the only profile whose keys are not
  also protected by anything classical.
- **mixed** is a migration and research tool, and proof that the
  format does not care which pair you picked. Its strength is the
  strength of its weaker half. Ed25519 with ML-KEM-768 gives
  post-quantum confidentiality and classical authentication.

A key pair cannot be converted between profiles, because the
fingerprint covers exactly which algorithms are present. Generate a
new identity and tell your correspondents.

### Why ML-KEM never encrypts anything by itself

ML-KEM-768 is a KEM. It turns a public key into a shared secret plus
a ciphertext of that secret, and it has no notion of a message.
NoxCrypt therefore never uses it to protect data directly. For an
ML-KEM-only recipient the sequence is:

1. Generate a random 32-byte file key.
2. Encapsulate to the recipient's public key, getting a ciphertext
   and a 32-byte shared secret.
3. Hash the transcript:
   `wk = BLAKE2b-256("noxcrypt/v1/mlkem768-wrap" || ct || pk || ss)`.
4. Wrap the file key with XChaCha20-Poly1305 under `wk`.

The payload is then encrypted with XChaCha20-Poly1305 in streaming
mode under the file key. The hybrid recipient adds an ephemeral
X25519 Diffie-Hellman, and the two derived keys are combined with a
third BLAKE2b call before the file key is wrapped:

```
wk = BLAKE2b-256("noxcrypt/v1/hybrid-wrap" || xk || kk || fingerprint)
```

Both derivations are specified byte by byte in
[SPEC.md](SPEC.md), sections 6.1 to 6.3.

### Recipient selection is not a preference

When you encrypt to a key, the tool looks at what the key holds and
picks the matching recipient flavor. It does not fall back:

- both X25519 and ML-KEM-768 present: combined recipient;
- X25519 only: X25519 recipient;
- ML-KEM-768 only: ML-KEM recipient.

The same rule applies when decrypting, and the rule is strict in
both directions. An identity holding both keys refuses a message
addressed to its X25519 key alone, and an `ecc` identity refuses a
combined recipient, even in the hypothetical case where the key
material would allow it. This closes the usual downgrade attack, in
which an attacker strips the strong half of a message and hopes the
recipient's software accepts the rest.

One message can carry recipients of different kinds, so sending one
file to a hybrid, an `ecc`, and a `pqc` correspondent works in a
single pass.

## The keyring

The keyring lives in `$NOX_HOME/.nox`, or `$HOME/.nox` if
`NOX_HOME` is unset, or wherever `--home` points. The directory is
created with mode 0700, including missing parents. A directory that
already exists with looser permissions is tightened to 0700 before
anything is written; the command fails if that is not possible.
Each identity is two files:

```
7f3c9d02...8b41.pub    public key,   mode 0600
7f3c9d02...8b41.sec    secret key,   mode 0600
```

Both are NoxCrypt documents. The `.sec` file is never plaintext: the
secret seeds are wrapped with Argon2id and XChaCha20-Poly1305 under
your passphrase, and the passphrase is asked for every time the
secret key is used.

Keyring writes are atomic. A key file is written to a temporary name
in the same directory and renamed into place, so a crash or a full
disk leaves the old file intact rather than a truncated one.

`nox list` shows what is in there:

```
$ nox list alice
7f3c9d02...8b41  2026-09-10
  hybrid: Ed25519 + ML-DSA-44 + X25519 + ML-KEM-768
  "alice@example.com"
```

A key imported from a public key file has no `.sec` half and says
so:

```
  ecc: Ed25519 + X25519 (no secret key)
```

Backing up the keyring means copying `~/.nox`, or the `.sec` files
you care about. Because `.sec` files are locked, a backup is only as
sensitive as its passphrase, as long as the two are not stored
together.

Moving a key to another machine is `export -s` on one side and
`import` on the other. Secret keys are exported exactly as they sit
on disk, still locked, so the transport does not need to be trusted
for confidentiality. It should still be your own channel, not a
paste into a group chat.

## Passphrases

Every secret key is protected by a passphrase, and there is no way
to store one without it. The passphrase is read from `/dev/tty` with
echo disabled, twice for `gen`, once for everything else. Terminal
settings are restored on errors and on the usual signals, so a
Ctrl-C does not leave your terminal with echo off.

Scripts use `--passphrase-file`, which reads the first line of a
file. A line longer than 1023 bytes is an error rather than a silent
truncation, because a truncated passphrase would be a wrong
passphrase with a confusing failure. Be aware that the passphrase is
then sitting in a file, which may be the very thing you were trying
to protect.

The key derivation is Argon2id with t=3, m=65536 KiB, p=1: about
64 MiB of memory and a fraction of a second per guess. That makes
bulk guessing expensive and does nothing about `hunter2`. Four or
five random words beat a short complicated string.

Passphrases cannot be changed. Generate a new identity, move what
needs moving, and tell your correspondents. This is deliberate for a
v1 tool; the secret file format would allow re-wrapping, but the CLI
does not offer it yet.

## Messages

Encryption to a key:

```
nox encrypt -r 7f3c9d02 -a -o note.nox.asc note.txt
nox decrypt -i 7f3c9d02 -o note.txt note.nox.asc
```

Encryption to several keys, including keys not in your keyring:

```
nox encrypt -r 7f3c9d02 -R bob.pub -R carol.pub -o note.nox note.txt
```

Passphrase-only encryption, when no recipient key exists:

```
nox encrypt -p -a -o secret.nox.asc secret.txt
nox decrypt -p -o secret.txt secret.nox.asc
```

A passphrase recipient is always the only recipient. Mixing one with
public keys is refused, and so is naming an identity with `-i` for a
passphrase message, because the two protect in different ways and
the mix is always a mistake.

Without `-o`, output goes to stdout, which makes pipes work:

```
tar cf - ~/notes | nox encrypt -r 7f3c9d02 -a | ssh host 'cat > notes.nox'
```

Plaintext is processed in 64 KiB chunks. Each chunk is
authenticated with its index and a final-chunk flag in the
additional data, so reordering and splicing are detected, and a
ciphertext that just stops is rejected instead of being accepted as
a shorter message.

`decrypt` writes plaintext as it authenticates. If chunk 12 of 20
fails, chunks 1 to 11 are already out of the door. With `-o FILE`,
though, the CLI writes to a temporary file next to FILE and renames
it only when the whole message has authenticated. A failed decrypt
therefore leaves the previous content of FILE untouched. The same
guarantee covers `encrypt -o`, `gen --pub/--sec`, and `export -o`.

Output files created by `-o` get the usual mode for data (0666
masked by umask). Files that hold a secret key (`gen --sec`,
`export -s -o`) are always created 0600, whatever the umask says.

Binary output to a terminal is refused unless `--armor` is given.
Armor is PEM-like: `-----BEGIN NOX MESSAGE-----`, base64 in
64-column lines, `-----END NOX MESSAGE-----`. The kinds are
`PUBLIC KEY`, `SECRET KEY`, `MESSAGE`, and `SIGNATURE`. Reading
armor is lenient about whitespace, headers, and missing padding; a
leading UTF-8 BOM is skipped. Writing it is strict, so armored files
are reproducible byte for byte.

## Signatures

```
nox sign -i 7f3c9d02 -o note.sig note.txt
nox verify -k alice.pub note.sig note.txt
```

A detached signature contains the creation time, the signer's
fingerprint, and one signature packet per signing key of the
identity. The message is streamed through BLAKE2b-256 and never has
to fit in memory, so signing a 100 GB file does not use 100 GB of
RAM, and signing from a pipe works:

```
nox sign -i 7f3c9d02 < archive.tar > archive.sig
```

ML-DSA-44 signs with hedged randomness, as FIPS 204 recommends.
Signing the same file twice produces different signature bytes that
both verify. Do not be surprised by this; it is a property of the
signature scheme, not of your file.

Verification checks every signing key that the public identity
lists, and fails when the signature carries a different set. For a
hybrid identity, both Ed25519 and ML-DSA-44 must verify; a signature
that drops the post-quantum half is rejected. On success the tool
prints one line and nothing else:

```
Good signature
```

Nothing is printed on failure, and the exit status is non-zero.
Without `-k` or `-i`, the fingerprint inside the signature selects
the key from the keyring. Giving both is an error.

## Import and export

`nox export` writes a key from the keyring to a file or stdout.
`nox import` reads a public or secret key file and stores it. Both
accept armored and raw input. An exported public key is the identity
as it was created, self-signature included, so two machines that
import the same key agree on its fingerprint and its comment.

```
nox export -a -o alice.pub 7f3c9d02
nox import alice.pub
nox export -s -a -o alice.sec 7f3c9d02
nox import --passphrase-file ~/.nox-pass alice.sec
```

Importing a secret key unlocks it first, so a wrong passphrase fails
before anything is written to the keyring. Importing a key that
already exists replaces it atomically with the same fingerprint,
which matters only when the encodings differ.

## Scripting

Exit status is 0 on success, 1 on any operation failure, and 2 for a
usage error. A missing operand counts as an operation failure:

```
if nox verify -k alice.pub note.sig note.txt 2>/dev/null; then
    echo "authentic"
fi
```

`--faketime` replaces the clock for anything that writes a
timestamp, which makes keys, signatures, and listings reproducible:

```
nox --home /tmp/demo --faketime 1700000000 gen -c 'fixture'
```

Key material still comes from `getrandom(2)`. The option exists for
tests and for stable documentation examples, not for dating
documents in production.

`make test` runs the unit tests and `tests/test.sh`, which builds
several keyrings under `tests/tmp`, exercises every profile, checks
that one profile refuses another profile's messages, verifies the
failure paths (wrong passphrase, tampered message, oversized
comments, conflicting options), and checks output permissions. It
takes a handful of seconds, mostly Argon2id.

## What NoxCrypt does not protect against

Worth reading before trusting it with anything that matters.

- **A compromised machine.** Secret keys live on disk, unlocked with
  a passphrase typed on that same machine. Malware running with your
  privileges gets everything.
- **No forward secrecy.** The file key is wrapped to long-term keys.
  Whoever holds the identity's secret key later, and kept the
  ciphertext, can read it then.
- **Metadata.** A message reveals how many recipients it has, which
  algorithms they use, and the plaintext length rounded up to 64 KiB
  chunks. Detached signatures reveal the signer fingerprint and a
  timestamp. File names never appear inside a document.
- **Weak passphrases.** Argon2id raises the price of a guess. It
  does not fix a bad passphrase.
- **Clock games.** Timestamps come from the local clock. They are
  signed once inside a document, but nothing checks that they are
  plausible.
- **A quantum computer, if you chose `ecc`.** That profile exists
  for people who decided the trade-off is acceptable. It is not the
  default for a reason.

And the honest summary: this is a small readable implementation that
has not been independently audited. It is a good place to read about
hybrid encryption, and it is not a replacement for a widely deployed
tool with a bug bounty.

## Troubleshooting

- `no public key matches 'xyz'`: the prefix is not in the keyring.
  `nox list` shows full fingerprints. Only `nox list` matches a
  comment substring; commands that select a key want hex.

- `fingerprint prefix 'abc' is ambiguous`: two keys share the
  prefix. Use more characters.

- `'alice' is not a fingerprint prefix (hex only)`: a comment cannot
  be used where a key is expected. Run `nox list alice` to find the
  fingerprint that belongs to that comment, then use it.

- `fingerprint prefix must be at least 8 hex characters`: the query
  was hex but too short.

- `no matching recipient or wrong passphrase`: the message was not
  encrypted to this key, or the passphrase is wrong, or the message
  is truncated. Also the error for a flavor mismatch: a hybrid key
  cannot read an `ecc` message even with the right passphrase.

- `-i and -p cannot be combined`: a passphrase message is not tied
  to an identity. Decide which kind of message you are holding.

- `wrong passphrase or corrupted secret key`: the wrapping AEAD did
  not authenticate. Almost always the passphrase.

- `corrupted ciphertext`: a chunk failed to authenticate. The file
  changed in transit, or it is not the file you think it is.

- `trailing bytes after ciphertext`: the file has extra data past
  the end of the message. This is treated as tampering.

- `multiple secret keys; specify -i FINGERPRINT`: the keyring holds
  more than one secret key and the command would be guessing.

- `refusing to write binary to the terminal (use --armor)`: redirect
  to a file or add `--armor`. Binary NoxCrypt documents do not
  survive a terminal.

- `identity self-signature is invalid`: the public key file was
  edited. It is not usable; import it again from a trustworthy copy.

- `comment longer than 1024 bytes` or `comment is not valid UTF-8`:
  the `-c` value breaks the format rules. Nothing was generated and
  no passphrase was asked for.

- `passphrase in FILE is longer than 1023 bytes`: the passphrase
  file line does not fit. Shorten it; the tool will not guess which
  prefix you meant.

## Files and environment

| Path / variable          | Meaning                                       |
|--------------------------|-----------------------------------------------|
| `~/.nox`                 | the keyring, mode 0700                        |
| `~/.nox/<fp>.pub`        | public key, mode 0600                         |
| `~/.nox/<fp>.sec`        | secret key, mode 0600, passphrase-wrapped     |
| `<dir>/.nox-tmp-<pid>-*` | short-lived output scratch, mode 0600         |
| `$NOX_HOME`              | replaces `~` when locating the keyring        |
| `$HOME`                  | used when `NOX_HOME` is unset                 |

Temporary output files are removed as soon as the command finishes;
one may be left behind only if the process is killed outright, and
it never contains anything the destination would not.

## Where the source keeps things

| File               | What it does                                   |
|--------------------|------------------------------------------------|
| `src/nox.c`        | command line parsing and output                |
| `src/identity.c`   | key generation, parsing, fingerprints          |
| `src/secret.c`     | passphrase wrapping of secret keys             |
| `src/cipher.c`     | recipient flavors and payload encryption       |
| `src/sign.c`       | detached signatures                            |
| `src/keyring.c`    | `~/.nox` and the `list` output                 |
| `src/armor.c`      | PEM-style armor, streaming                     |
| `src/passphrase.c` | no-echo prompt                                 |
| `src/packet.c`     | packet framing                                 |
| `src/util.c`       | bytes, randomness, files, Argon2id, names      |

The library surface is `include/noxcrypt.h`, which promises
`noxcrypt_version()` and `noxcrypt_error()`. Link the `src/*.c`
modules you need plus the two libncrypt files from the submodule.
What the review checked, and how to repeat it, is in
[REVIEW.md](REVIEW.md).
