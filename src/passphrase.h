#ifndef NOX_PASSPHRASE_H
#define NOX_PASSPHRASE_H

#include "util.h"

int nox_read_passphrase(char *buf, size_t n, const char *prompt);
int nox_confirm_passphrase(char *buf, size_t n);
int nox_read_passfile(char *buf, size_t n, const char *path);

#endif
