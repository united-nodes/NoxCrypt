#ifndef NOX_IDENTITY_H
#define NOX_IDENTITY_H

#include "util.h"

typedef struct {
    uint16_t alg;
    uint8_t usage;
    uint8_t encoding;          /* NOX_ENC_SEED or NOX_ENC_EXP when has_sk */
    uint8_t pk[1312];
    size_t pk_len;
    uint8_t sk[2560];
    size_t sk_len;
    int has_sk;
} nox_key;

typedef struct {
    uint64_t created;
    char comment[NOX_MAX_COMMENT + 1];
    uint8_t fp[NOX_FP_LEN];
    nox_key keys[NOX_MAX_KEYS];
    int nkeys;
    uint8_t *raw;              /* Identity.value */
    size_t raw_len;
    size_t body_len;           /* bytes before the first Signature packet */
} nox_ident;

/*
 * Which algorithms an identity should carry.  A usable identity needs
 * at least one signing and one encryption algorithm; everything else
 * is the caller's choice.
 */
typedef struct {
    uint8_t ed25519;
    uint8_t mldsa44;
    uint8_t x25519;
    uint8_t mlkem768;
} nox_algset;

void nox_algset_full(nox_algset *set);      /* Ed25519, ML-DSA-44, X25519, ML-KEM-768 */
void nox_algset_classic(nox_algset *set);   /* Ed25519 + X25519 */
void nox_algset_pq(nox_algset *set);        /* ML-DSA-44 + ML-KEM-768 */
int nox_algset_parse(nox_algset *set, const char *name);
int nox_algset_add(nox_algset *set, uint16_t alg);
int nox_algset_has(const nox_algset *set, uint16_t alg);
int nox_algset_valid(const nox_algset *set);
const char *nox_algset_name(const nox_algset *set);

void nox_ident_init(nox_ident *id);
void nox_ident_wipe(nox_ident *id);

int nox_ident_generate(nox_ident *id, const nox_algset *set,
                       const char *comment, uint64_t created);

/* Validate a key comment before any key material or prompt exists. */
int nox_comment_ok(const char *comment);
int nox_ident_parse(nox_ident *id, const uint8_t *buf, size_t n);
int nox_ident_parse_value(nox_ident *id, const uint8_t *val, size_t vlen);
int nox_ident_public_blob(const nox_ident *id, uint8_t **out, size_t *n);
int nox_ident_load_pub(nox_ident *id, const uint8_t *buf, size_t n);

/* Expand a secret into `sk` (caller wipes). Does not consume the stored seed. */
int nox_key_expand(const nox_key *k, uint8_t *sk, size_t *sk_len);

nox_key *nox_ident_find(const nox_ident *id, uint16_t alg);
int nox_ident_has_hybrid_enc(const nox_ident *id);

/*
 * Describe what an identity can do.  `nox_ident_recipient_alg` is the
 * recipient algorithm `nox encrypt` will use for it: 0x0005 when both
 * X25519 and ML-KEM-768 are present, 0x0001 or 0x0003 when only one of
 * them is, and -1 when there is no encryption key at all.
 */
void nox_ident_algset(const nox_ident *id, nox_algset *set);
const char *nox_ident_profile(const nox_ident *id);
int nox_ident_recipient_alg(const nox_ident *id);
void nox_ident_alg_list(const nox_ident *id, char *buf, size_t n);

#endif
