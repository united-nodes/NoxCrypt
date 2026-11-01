#ifndef NOXCRYPT_H
#define NOXCRYPT_H

/*
 * NoxCrypt public library surface.
 *
 * The implementation is split across src/*.c so that a program can
 * link only the pieces it needs.  This header is the version/error
 * contract; cryptographic types and operations live in the matching
 * src/*.h files (identity, secret, cipher, sign, keyring, armor).
 *
 * Wire formats are defined in doc/SPEC.md.  This is SPEC-v1 (draft).
 */

#ifdef __cplusplus
extern "C" {
#endif

const char *noxcrypt_version(void);
const char *noxcrypt_error(void);

#ifdef __cplusplus
}
#endif

#endif
