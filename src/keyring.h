#ifndef NOX_KEYRING_H
#define NOX_KEYRING_H

#include "identity.h"

typedef struct {
    int pub;
    int sec;
} nox_keyring_info;

int nox_keyring_dir(char *buf, size_t n);
int nox_keyring_key_path(char *buf, size_t n, const uint8_t fp[NOX_FP_LEN],
                         const char *ext);
int nox_keyring_init(void);

int nox_keyring_store_pub(const nox_ident *id);
int nox_keyring_store_sec(const uint8_t fp[NOX_FP_LEN],
                          const uint8_t *blob, size_t n);

int nox_keyring_load_pub(const char *query, nox_ident *id);
int nox_keyring_load_sec_blob(const char *query, uint8_t **blob, size_t *n,
                              uint8_t fp[NOX_FP_LEN]);

int nox_keyring_delete(const char *query);
int nox_keyring_list(FILE *out, const char *query);
int nox_keyring_count_sec(void);
int nox_keyring_stats(nox_keyring_info *st);

#endif
