#ifndef NOX_CIPHER_H
#define NOX_CIPHER_H

#include "identity.h"
#include "armor.h"

int nox_encrypt(FILE *in, FILE *out, int armor,
                nox_ident **recips, int nrecips,
                const char *pass, size_t pass_len);

int nox_decrypt(FILE *in, FILE *out,
                nox_ident **idents, int nidents,
                const char *pass, size_t pass_len);

#endif
