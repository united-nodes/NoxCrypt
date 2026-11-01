#ifndef NOX_SIGN_H
#define NOX_SIGN_H

#include "identity.h"

int nox_hash_file(FILE *fp, uint8_t hash[32]);

int nox_sign_detached(uint8_t **out, size_t *n, nox_ident *id,
                      const uint8_t hash[32]);

/* Returns 0 if every signing key of `id` verifies. */
int nox_verify_detached(const uint8_t *sig, size_t n, nox_ident *id,
                        const uint8_t hash[32]);

#endif
