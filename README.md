# NoxCrypt

A small Linux command-line tool for hybrid (classical plus
post-quantum) encryption and signatures. It is closer to
[age](https://age-encryption.org/) and
[minisign](https://jedisct1.github.io/minisign/) than to OpenSSL:
auditable C, no network protocol, stdin and stdout, one job per
subcommand.

This is SPEC-v1 (draft). The wire format is in
[doc/SPEC.md](doc/SPEC.md). Do not treat it as audited production
cryptography; [REVIEW.md](REVIEW.md) records what has been checked,
and by what means.

## Features

- Hybrid identities: Ed25519 + ML-DSA-44 + X25519 + ML-KEM-768
- Classical (`ecc`), post-quantum (`pqc`), and hand-picked `mixed`
  profiles as well
- Encrypt / decrypt to keys or to a passphrase
- Detached sign / verify, one signature per signing key
- Passphrase-protected secret keys (Argon2id + XChaCha20-Poly1305)
- ASCII armor (PEM style, 64-column wrap)
- Keyring under `~/.nox`, directory 0700, files 0600
- Atomic output files, pipes, streaming of large inputs

## Build

Linux, GCC or Clang, no extra libraries. The one dependency,
libncrypt, is a git submodule pinned to its 1.0.0 release:

```
git clone --recursive https://github.com/RYSF13/NoxCrypt
cd NoxCrypt
git submodule update --init   # no-op after a recursive clone
make
```

That produces `./nox`. If `make` says the submodule is missing, run
the `git submodule update --init` line above. `make test` runs the
unit tests and a CLI round-trip (Argon2id uses 64 MiB, so the first
`gen` takes a few seconds). `make install` puts the binary and the
man page under `/usr/local`; `PREFIX` and `DESTDIR` work as usual.

## Usage

```
nox gen -c 'alice@example.com'
nox list
nox encrypt -r 0123abcd -a -o secret.nox message.txt
nox decrypt -i 0123abcd -o message.txt secret.nox
nox sign -i 0123abcd -a -o message.sig message.txt
nox verify message.sig message.txt
nox export -a 0123abcd
nox import alice.pub
nox delete 0123abcd
nox info
```

Which algorithms a key carries is decided once, at generation time:

```
nox gen -A hybrid -c 'both worlds'      # the default
nox gen -A ecc    -c 'classical only'
nox gen -A pqc    -c 'post-quantum only'
nox gen --sig ed25519 --kem mlkem768    # one of each, by hand
```

Passphrase-only encryption, no keys involved:

```
nox encrypt -p -a -o secret.nox message.txt
nox decrypt -p -o message.txt secret.nox
```

Global options go before the command name:

```
nox --home /tmp/demo --faketime 1700000000 gen -c alice
```

`--faketime` replaces the system clock for `created` timestamps.
`--home` (or `NOX_HOME`) relocates the keyring. Every command
accepts `--help`, and the long form of all of it is the
[manual](doc/manual.md) and the man page `nox(1)`.

Keys are selected by a hex fingerprint prefix of at least eight
characters. Secret keys always prompt for a passphrase (echo is
disabled on `/dev/tty`); scripts can pass `--passphrase-file`.
Binary NoxCrypt documents are refused on a terminal unless
`--armor` is set. `nox verify` prints only `Good signature` when a
signature is genuine.

## Library

The CLI is a thin `src/nox.c` over small modules:

| Module       | Role                                        |
|--------------|---------------------------------------------|
| `util`       | endianness, RNG, hex, files, Argon2id       |
| `packet`     | magic and typed length-prefixed packets     |
| `armor`      | RFC 4648 / PEM, streaming reader and writer |
| `identity`   | generate and parse identities               |
| `secret`     | passphrase wrap for secret keys             |
| `passphrase` | no-echo prompt, restore terminal            |
| `cipher`     | recipient wraps and payload encryption      |
| `sign`       | detached signatures                         |
| `keyring`    | `~/.nox`                                    |

`include/noxcrypt.h` exports `noxcrypt_version()` and
`noxcrypt_error()`. Link the `src/*.c` modules you need plus the two
libncrypt files from the `vendor/libncrypt` submodule.

## Cryptography

- XChaCha20-Poly1305 (Monocypher via libncrypt)
- X25519, Ed25519
- BLAKE2b
- Argon2id (t=3, m=65536 KiB, p=1)
- ML-KEM-768, ML-DSA-44 (hedged signing)

Recipients follow the key: an identity holding both X25519 and
ML-KEM-768 gets the combined `0x0005` recipient, an X25519-only
identity gets `0x0001`, an ML-KEM-768-only identity gets `0x0003`,
and a decryptor only accepts the flavor its own key set implies. A
hybrid identity is never unwrapped through a single-algorithm
recipient. The same idea applies to signatures: a signer emits one
signature per signing key, and the verifier requires exactly those.

ML-KEM-768 is a KEM, so it never encrypts file data. Its shared
secret is hashed with BLAKE2b into the XChaCha20-Poly1305 key that
wraps the random file key; the hybrid recipient mixes an ephemeral
X25519 Diffie-Hellman into that hash first.

Random bytes come from `getrandom(2)`.

## Documentation

- [doc/manual.md](doc/manual.md): the long form manual, with the
  threat model and troubleshooting
- [doc/nox.1](doc/nox.1): the man page
- [doc/SPEC.md](doc/SPEC.md): the wire format
- [REVIEW.md](REVIEW.md): the review record

## License

This project is in the Public Domain. See [LICENSE](LICENSE) for more information.
