#ifndef NOX_UTIL_H
#define NOX_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#include "ncrypt.h"
#include "ncrypt-pqc.h"

#define NOX_OK 0

/*
 * Program identity.  These are macros rather than variables so that
 * any translation unit can use them without pulling in util.c, and so
 * that the strings end up in .rodata and not in a writable page.
 */
#define NOX_VERSION "1.0.0"

#define NOX_FP_LEN          32
#define NOX_MAX_COMMENT     1024
#define NOX_MAX_RECIPIENTS  16
#define NOX_CHUNK           65536
#define NOX_MAX_KEYS        8
#define NOX_MAX_IDENT       65536
#define NOX_MAX_BLOB        (256 * 1024)
#define NOX_PASS_MAX        1023

#define NOX_MAGIC0 0x4E
#define NOX_MAGIC1 0x4F
#define NOX_MAGIC2 0x58
#define NOX_MAGIC3 0x01

#define NOX_PKT_IDENTITY  0x0001
#define NOX_PKT_SECRET    0x0002
#define NOX_PKT_ENCHDR    0x0003
#define NOX_PKT_DETSIG    0x0004
#define NOX_PKT_PUBKEY    0x0010
#define NOX_PKT_SECKEY    0x0011
#define NOX_PKT_SIG       0x0012
#define NOX_PKT_RECIPIENT 0x0013
#define NOX_PKT_CHUNK     0x0014

#define NOX_ALG_X25519    0x0001
#define NOX_ALG_ED25519   0x0002
#define NOX_ALG_MLKEM768  0x0003
#define NOX_ALG_MLDSA44   0x0004
#define NOX_ALG_HYBRID    0x0005
#define NOX_ALG_ARGON2ID  0x0006

#define NOX_USAGE_ENCRYPT 0x01
#define NOX_USAGE_SIGN    0x02
#define NOX_USAGE_AUTH    0x04

#define NOX_ENC_SEED 0x01
#define NOX_ENC_EXP  0x02

#define NOX_ARGON2_T 3
#define NOX_ARGON2_M 65536
#define NOX_ARGON2_P 1
#define NOX_ARGON2_M_MIN 16384
#define NOX_ARGON2_M_MAX (1u << 21)

#define DS_IDENTITY     "noxcrypt/v1/identity"
#define DS_FINGERPRINT  "noxcrypt/v1/fingerprint"
#define DS_SIGNATURE    "noxcrypt/v1/signature"
#define DS_SECRET       "noxcrypt/v1/secret"
#define DS_HEADER       "noxcrypt/v1/header"
#define DS_PAYLOAD      "noxcrypt/v1/payload"
#define DS_X25519WRAP   "noxcrypt/v1/x25519-wrap"
#define DS_MLKEMWRAP    "noxcrypt/v1/mlkem768-wrap"
#define DS_HYBRIDWRAP   "noxcrypt/v1/hybrid-wrap"

extern char nox_err[256];

int nox_seterr(const char *fmt, ...);
void nox_wipe(void *p, size_t n);

void nox_be16(uint8_t *p, uint16_t x);
void nox_be32(uint8_t *p, uint32_t x);
void nox_be64(uint8_t *p, uint64_t x);
uint16_t nox_rd16(const uint8_t *p);
uint32_t nox_rd32(const uint8_t *p);
uint64_t nox_rd64(const uint8_t *p);

int nox_random(void *buf, size_t n);
void nox_set_faketime(int64_t ts);
uint64_t nox_now(void);

int nox_memeq(const uint8_t *a, const uint8_t *b, size_t n);
void nox_hex(char *out, const uint8_t *in, size_t n);
int nox_unhex(uint8_t *out, size_t *out_n, const char *s);
int nox_fp_prefix(const uint8_t fp[NOX_FP_LEN], const char *hex);

int nox_utf8_ok(const uint8_t *s, size_t n);
int nox_pk_len(uint16_t alg);
int nox_sk_seed_len(uint16_t alg);
int nox_sk_exp_len(uint16_t alg);
int nox_sig_len(uint16_t alg);
int nox_usage_ok(uint16_t alg, uint8_t usage);
int nox_is_sign_alg(uint16_t alg);
int nox_is_enc_alg(uint16_t alg);

/* "Ed25519", "ML-KEM-768", ... or "unknown" for an id we do not know. */
const char *nox_alg_name(uint16_t alg);

/*
 * Parse a CLI algorithm name: "ed25519", "mldsa44", "x25519", "mlkem768".
 * Dashes and case are ignored, so "ML-KEM-768" works too.  Returns 0 or
 * -1; the conventional 0x0000 means "no match".
 */
int nox_alg_parse(const char *name, uint16_t *alg);

/* UTC date, "YYYY-MM-DD".  Falls back to "-" out of range. */
void nox_fmt_date(char *out, size_t n, uint64_t ts);

int nox_argon2id(uint8_t key[32], const void *pass, size_t pass_len,
                 uint32_t t, uint32_t m, uint32_t p, const uint8_t salt[16]);

int nox_read_all(FILE *fp, uint8_t **out, size_t *n, size_t max);
int nox_write_all(FILE *fp, const void *buf, size_t n);
int nox_write_file(const char *path, const void *buf, size_t n, mode_t mode);
int nox_replace_file(const char *path, const void *buf, size_t n, mode_t mode);
int nox_read_file(const char *path, uint8_t **out, size_t *n, size_t max);
int nox_ensure_dir(const char *path, mode_t mode);
int nox_isatty(FILE *fp);
void nox_set_home(const char *path);
const char *nox_home_dir(const char *override);
const char *noxcrypt_version(void);
const char *noxcrypt_error(void);

typedef struct {
    uint8_t *p;
    size_t n;
    size_t cap;
    int err;
} nox_buf;

int nox_buf_init(nox_buf *b, size_t cap);
void nox_buf_free(nox_buf *b);
int nox_buf_put(nox_buf *b, const void *p, size_t n);
int nox_buf_u8(nox_buf *b, uint8_t x);
int nox_buf_u16(nox_buf *b, uint16_t x);
int nox_buf_u32(nox_buf *b, uint32_t x);
int nox_buf_u64(nox_buf *b, uint64_t x);
int nox_buf_pkt(nox_buf *b, uint16_t type, const uint8_t *val, uint32_t vlen);

#endif
