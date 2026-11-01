#ifndef NOX_SECRET_H
#define NOX_SECRET_H

#include "identity.h"

int nox_secret_lock(uint8_t **out, size_t *n, const nox_ident *id,
                    const char *pass, size_t pass_len);
int nox_secret_unlock(nox_ident *id, const uint8_t *buf, size_t n,
                      const char *pass, size_t pass_len);

#endif
