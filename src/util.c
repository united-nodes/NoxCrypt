#define _GNU_SOURCE

#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

char nox_err[256];

static int64_t fake_time = -1;
static const char *home_override;

int
nox_seterr(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(nox_err, sizeof nox_err, fmt, ap);
    va_end(ap);
    return -1;
}

void
nox_wipe(void *p, size_t n)
{
    if (p != NULL && n > 0)
        ncrypt_wipe(p, n);
}

void
nox_be16(uint8_t *p, uint16_t x)
{
    p[0] = (uint8_t)(x >> 8);
    p[1] = (uint8_t)x;
}

void
nox_be32(uint8_t *p, uint32_t x)
{
    p[0] = (uint8_t)(x >> 24);
    p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >> 8);
    p[3] = (uint8_t)x;
}

void
nox_be64(uint8_t *p, uint64_t x)
{
    nox_be32(p, (uint32_t)(x >> 32));
    nox_be32(p + 4, (uint32_t)x);
}

uint16_t
nox_rd16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

uint32_t
nox_rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

uint64_t
nox_rd64(const uint8_t *p)
{
    return ((uint64_t)nox_rd32(p) << 32) | nox_rd32(p + 4);
}

int
nox_random(void *buf, size_t n)
{
    uint8_t *p = buf;

    while (n > 0) {
        ssize_t r = getrandom(p, n, 0);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return nox_seterr("getrandom: %s", strerror(errno));
        }
        if (r == 0)
            return nox_seterr("getrandom returned no data");
        p += (size_t)r;
        n -= (size_t)r;
    }
    return 0;
}

void
nox_set_faketime(int64_t ts)
{
    fake_time = ts;
}

uint64_t
nox_now(void)
{
    time_t t;

    if (fake_time >= 0)
        return (uint64_t)fake_time;
    t = time(NULL);
    if (t < 0)
        return 0;
    return (uint64_t)t;
}

int
nox_memeq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    size_t i;

    for (i = 0; i < n; i++)
        d |= (uint8_t)(a[i] ^ b[i]);
    return d; /* 0 if equal */
}

void
nox_hex(char *out, const uint8_t *in, size_t n)
{
    static const char h[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < n; i++) {
        out[2 * i] = h[in[i] >> 4];
        out[2 * i + 1] = h[in[i] & 0xf];
    }
    out[2 * n] = 0;
}

static int
hexval(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

int
nox_unhex(uint8_t *out, size_t *out_n, const char *s)
{
    size_t i, n = strlen(s);

    if (n == 0 || (n & 1) != 0)
        return nox_seterr("hex string must have even length");
    if (n / 2 > *out_n)
        return nox_seterr("hex string too long");
    for (i = 0; i < n; i += 2) {
        int hi = hexval((unsigned char)s[i]);
        int lo = hexval((unsigned char)s[i + 1]);
        if (hi < 0 || lo < 0)
            return nox_seterr("invalid hex character");
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    *out_n = n / 2;
    return 0;
}

int
nox_fp_prefix(const uint8_t fp[NOX_FP_LEN], const char *hex)
{
    char full[65];
    size_t n;

    nox_hex(full, fp, NOX_FP_LEN);
    n = strlen(hex);
    if (n < 8 || n > 64)
        return 0;
    /* prefix match, case-insensitive */
    {
        size_t i;
        for (i = 0; i < n; i++) {
            int a = hex[i];
            int b = full[i];
            if (a >= 'A' && a <= 'F')
                a += 'a' - 'A';
            if (a != b)
                return 0;
        }
    }
    return 1;
}

int
nox_utf8_ok(const uint8_t *s, size_t n)
{
    size_t i = 0;

    while (i < n) {
        uint8_t c = s[i];
        uint32_t cp;
        int need;

        if (c == 0 || c == '\n' || c == '\r')
            return 0;
        if (c < 0x80) {
            i++;
            continue;
        }
        if ((c & 0xe0) == 0xc0) {
            need = 1;
            cp = c & 0x1f;
            if (c < 0xc2)
                return 0; /* overlong */
        } else if ((c & 0xf0) == 0xe0) {
            need = 2;
            cp = c & 0x0f;
        } else if ((c & 0xf8) == 0xf0) {
            need = 3;
            cp = c & 0x07;
            if (c > 0xf4)
                return 0;
        } else {
            return 0;
        }
        if (i + 1 + (size_t)need > n)
            return 0;
        {
            int k;
            for (k = 1; k <= need; k++) {
                uint8_t x = s[i + (size_t)k];
                if ((x & 0xc0) != 0x80)
                    return 0;
                cp = (cp << 6) | (x & 0x3f);
            }
        }
        if (need == 2 && cp < 0x800)
            return 0;
        if (need == 3 && cp < 0x10000)
            return 0;
        if (cp >= 0xd800 && cp <= 0xdfff)
            return 0;
        if (cp > 0x10ffff)
            return 0;
        i += 1 + (size_t)need;
    }
    return 1;
}

int
nox_pk_len(uint16_t alg)
{
    switch (alg) {
    case NOX_ALG_X25519:   return 32;
    case NOX_ALG_ED25519:  return 32;
    case NOX_ALG_MLKEM768: return 1184;
    case NOX_ALG_MLDSA44:  return 1312;
    default:               return -1;
    }
}

int
nox_sk_seed_len(uint16_t alg)
{
    switch (alg) {
    case NOX_ALG_X25519:   return 32;
    case NOX_ALG_ED25519:  return 32;
    case NOX_ALG_MLKEM768: return 64;
    case NOX_ALG_MLDSA44:  return 32;
    default:               return -1;
    }
}

int
nox_sk_exp_len(uint16_t alg)
{
    switch (alg) {
    case NOX_ALG_X25519:   return 32;
    case NOX_ALG_ED25519:  return 64;
    case NOX_ALG_MLKEM768: return 2400;
    case NOX_ALG_MLDSA44:  return 2560;
    default:               return -1;
    }
}

int
nox_sig_len(uint16_t alg)
{
    switch (alg) {
    case NOX_ALG_ED25519: return 64;
    case NOX_ALG_MLDSA44: return 2420;
    default:              return -1;
    }
}

int
nox_usage_ok(uint16_t alg, uint8_t usage)
{
    if (usage == 0 || (usage & ~0x07) != 0)
        return 0;
    switch (alg) {
    case NOX_ALG_X25519:
    case NOX_ALG_MLKEM768:
        return usage == NOX_USAGE_ENCRYPT;
    case NOX_ALG_ED25519:
    case NOX_ALG_MLDSA44:
        return (usage & NOX_USAGE_ENCRYPT) == 0 &&
               (usage & (NOX_USAGE_SIGN | NOX_USAGE_AUTH)) != 0;
    default:
        return 0;
    }
}

int
nox_is_sign_alg(uint16_t alg)
{
    return alg == NOX_ALG_ED25519 || alg == NOX_ALG_MLDSA44;
}

int
nox_is_enc_alg(uint16_t alg)
{
    return alg == NOX_ALG_X25519 || alg == NOX_ALG_MLKEM768;
}

static const struct {
    uint16_t alg;
    const char *name;
} alg_names[] = {
    { NOX_ALG_X25519,   "X25519" },
    { NOX_ALG_ED25519,  "Ed25519" },
    { NOX_ALG_MLKEM768, "ML-KEM-768" },
    { NOX_ALG_MLDSA44,  "ML-DSA-44" },
    { NOX_ALG_HYBRID,   "X25519+ML-KEM-768" },
    { NOX_ALG_ARGON2ID, "Argon2id" },
};

const char *
nox_alg_name(uint16_t alg)
{
    size_t i;

    for (i = 0; i < sizeof alg_names / sizeof alg_names[0]; i++) {
        if (alg_names[i].alg == alg)
            return alg_names[i].name;
    }
    return "unknown";
}

int
nox_alg_parse(const char *name, uint16_t *alg)
{
    static const struct {
        const char *text;
        uint16_t alg;
    } table[] = {
        { "ed25519",  NOX_ALG_ED25519 },
        { "mldsa44",  NOX_ALG_MLDSA44 },
        { "mldsa",    NOX_ALG_MLDSA44 },
        { "x25519",   NOX_ALG_X25519 },
        { "mlkem768", NOX_ALG_MLKEM768 },
        { "mlkem",    NOX_ALG_MLKEM768 },
    };
    char clean[24];
    size_t i, n = 0;

    if (name == NULL)
        return -1;
    for (i = 0; name[i] != 0; i++) {
        char c = name[i];
        if (c == '-' || c == '_' || c == ' ')
            continue;
        if (n + 1 >= sizeof clean)
            return -1;
        if (c >= 'A' && c <= 'Z')
            c = (char)(c + 'a' - 'A');
        clean[n++] = c;
    }
    clean[n] = 0;
    for (i = 0; i < sizeof table / sizeof table[0]; i++) {
        if (strcmp(clean, table[i].text) == 0) {
            *alg = table[i].alg;
            return 0;
        }
    }
    return -1;
}

void
nox_fmt_date(char *out, size_t n, uint64_t ts)
{
    time_t t = (time_t)ts;
    struct tm tm;

    if (gmtime_r(&t, &tm) == NULL) {
        if (n > 0)
            snprintf(out, n, "-");
        return;
    }
    snprintf(out, n, "%04d-%02d-%02d", tm.tm_year + 1900, tm.tm_mon + 1,
             tm.tm_mday);
}

int
nox_argon2id(uint8_t key[32], const void *pass, size_t pass_len,
             uint32_t t, uint32_t m, uint32_t p, const uint8_t salt[16])
{
    void *work;
    ncrypt_argon2_config cfg;
    ncrypt_argon2_inputs in;

    if (p == 0 || m < 8 * p)
        return nox_seterr("invalid Argon2id parameters");
    if (m > NOX_ARGON2_M_MAX)
        return nox_seterr("Argon2id memory parameter is too large");
    if (t < 1)
        return nox_seterr("invalid Argon2id time parameter");
    /*
     * The parameters may come from an untrusted file (a passphrase
     * recipient, a secret key header).  Cap the total work so a
     * hostile document cannot make the decryptor grind for hours.
     * With m capped at NOX_ARGON2_M_MAX, t <= 64 bounds the total
     * work at 2^27 KiB-passes, about 680x the v1 default of
     * t=3, m=65536.
     */
    if (t > 64)
        return nox_seterr("Argon2id work factor is unreasonably large");
    if (pass_len > 0xffffffffu)
        return nox_seterr("passphrase too long");
    work = malloc((size_t)m * 1024);
    if (work == NULL)
        return nox_seterr("out of memory for Argon2id");
    cfg.algorithm = NCRYPT_ARGON2_ID;
    cfg.nb_blocks = m;
    cfg.nb_passes = t;
    cfg.nb_lanes = p;
    in.pass = pass;
    in.salt = salt;
    in.pass_size = (uint32_t)pass_len;
    in.salt_size = 16;
    ncrypt_argon2(key, 32, work, cfg, in, ncrypt_argon2_no_extras);
    nox_wipe(work, (size_t)m * 1024);
    free(work);
    return 0;
}

const char *
noxcrypt_version(void)
{
    return NOX_VERSION;
}

const char *
noxcrypt_error(void)
{
    return nox_err;
}

int
nox_read_all(FILE *fp, uint8_t **out, size_t *n, size_t max)
{
    uint8_t *buf = NULL;
    size_t cap = 0, used = 0;

    for (;;) {
        uint8_t tmp[4096];
        size_t r = fread(tmp, 1, sizeof tmp, fp);
        if (r > 0) {
            if (used > max || r > max - used) {
                free(buf);
                return nox_seterr("input too large");
            }
            if (buf == NULL || used + r > cap) {
                size_t ncap = cap ? cap * 2 : 8192;
                uint8_t *p;
                while (ncap < used + r)
                    ncap *= 2;
                p = realloc(buf, ncap);
                if (p == NULL) {
                    free(buf);
                    return nox_seterr("out of memory");
                }
                buf = p;
                cap = ncap;
            }
            memcpy(buf + used, tmp, r);
            used += r;
        }
        if (r < sizeof tmp) {
            if (ferror(fp)) {
                free(buf);
                return nox_seterr("read: %s", strerror(errno));
            }
            break;
        }
    }
    *out = buf;
    *n = used;
    return 0;
}

int
nox_write_all(FILE *fp, const void *buf, size_t n)
{
    const uint8_t *p = buf;

    while (n > 0) {
        size_t w = fwrite(p, 1, n, fp);
        if (w == 0)
            return nox_seterr("write: %s", strerror(errno));
        p += w;
        n -= w;
    }
    return 0;
}

int
nox_write_file(const char *path, const void *buf, size_t n, mode_t mode)
{
    int fd;
    const uint8_t *p = buf;

    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode);
    if (fd < 0)
        return nox_seterr("create %s: %s", path, strerror(errno));
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            unlink(path);
            return nox_seterr("write %s: %s", path, strerror(errno));
        }
        p += (size_t)w;
        n -= (size_t)w;
    }
    if (fsync(fd) < 0) {
        close(fd);
        unlink(path);
        return nox_seterr("fsync %s: %s", path, strerror(errno));
    }
    if (close(fd) < 0) {
        unlink(path);
        return nox_seterr("close %s: %s", path, strerror(errno));
    }
    return 0;
}

int
nox_replace_file(const char *path, const void *buf, size_t n, mode_t mode)
{
    char tmp[4096];
    int k;

    k = snprintf(tmp, sizeof tmp, "%s.tmp", path);
    if (k < 0 || (size_t)k >= sizeof tmp)
        return nox_seterr("path too long");
    unlink(tmp);
    if (nox_write_file(tmp, buf, n, mode) < 0)
        return -1;
    if (rename(tmp, path) < 0) {
        unlink(tmp);
        return nox_seterr("rename %s: %s", path, strerror(errno));
    }
    return 0;
}

int
nox_read_file(const char *path, uint8_t **out, size_t *n, size_t max)
{
    FILE *fp = fopen(path, "rb");
    int rc;

    if (fp == NULL)
        return nox_seterr("open %s: %s", path, strerror(errno));
    rc = nox_read_all(fp, out, n, max);
    fclose(fp);
    return rc;
}

int
nox_ensure_dir(const char *path, mode_t mode)
{
    char tmp[4096];
    struct stat st;
    size_t i, n;

    if (stat(path, &st) == 0) {
        if (!S_ISDIR(st.st_mode))
            return nox_seterr("%s exists and is not a directory", path);
        /*
         * The keyring holds secret keys.  A directory that already
         * exists with looser permissions (an old run, another tool,
         * an attacker) is tightened to the requested mode or the
         * command refuses to touch it.
         */
        if ((st.st_mode & 07777) != mode) {
            if (chmod(path, mode) < 0 || stat(path, &st) < 0 ||
                !S_ISDIR(st.st_mode) || (st.st_mode & 07777) != mode)
                return nox_seterr("%s is not mode 0%o and could not be "
                                  "tightened", path, (unsigned)mode);
        }
        return 0;
    }
    n = strlen(path);
    if (n == 0 || n >= sizeof tmp)
        return nox_seterr("path too long");

    /* --home /tmp/fresh has to work, so fill in the missing parents */
    memcpy(tmp, path, n + 1);
    for (i = 1; i < n; i++) {
        if (tmp[i] != '/')
            continue;
        tmp[i] = 0;
        if (mkdir(tmp, mode) < 0 && errno != EEXIST) {
            nox_seterr("mkdir %s: %s", tmp, strerror(errno));
            return -1;
        }
        tmp[i] = '/';
    }
    if (mkdir(tmp, mode) < 0) {
        if (errno != EEXIST)
            return nox_seterr("mkdir %s: %s", path, strerror(errno));
        if (stat(tmp, &st) < 0 || !S_ISDIR(st.st_mode))
            return nox_seterr("%s exists and is not a directory", path);
    }
    return 0;
}

int
nox_isatty(FILE *fp)
{
    return isatty(fileno(fp));
}

void
nox_set_home(const char *path)
{
    home_override = path;
}

const char *
nox_home_dir(const char *override)
{
    const char *h;

    if (override != NULL && override[0] != 0)
        return override;
    if (home_override != NULL)
        return home_override;
    h = getenv("NOX_HOME");
    if (h != NULL && h[0] != 0)
        return h;
    h = getenv("HOME");
    if (h == NULL || h[0] == 0)
        return NULL;
    return h;
}

int
nox_buf_init(nox_buf *b, size_t cap)
{
    b->p = malloc(cap);
    if (b->p == NULL) {
        b->n = b->cap = 0;
        b->err = 1;
        return nox_seterr("out of memory");
    }
    b->n = 0;
    b->cap = cap;
    b->err = 0;
    return 0;
}

void
nox_buf_free(nox_buf *b)
{
    if (b->p != NULL) {
        nox_wipe(b->p, b->cap);
        free(b->p);
    }
    b->p = NULL;
    b->n = b->cap = 0;
}

int
nox_buf_put(nox_buf *b, const void *p, size_t n)
{
    if (b->err)
        return -1;
    if (n > b->cap - b->n) {
        b->err = 1;
        return nox_seterr("buffer overflow");
    }
    memcpy(b->p + b->n, p, n);
    b->n += n;
    return 0;
}

int
nox_buf_u8(nox_buf *b, uint8_t x)
{
    return nox_buf_put(b, &x, 1);
}

int
nox_buf_u16(nox_buf *b, uint16_t x)
{
    uint8_t t[2];
    nox_be16(t, x);
    return nox_buf_put(b, t, 2);
}

int
nox_buf_u32(nox_buf *b, uint32_t x)
{
    uint8_t t[4];
    nox_be32(t, x);
    return nox_buf_put(b, t, 4);
}

int
nox_buf_u64(nox_buf *b, uint64_t x)
{
    uint8_t t[8];
    nox_be64(t, x);
    return nox_buf_put(b, t, 8);
}

int
nox_buf_pkt(nox_buf *b, uint16_t type, const uint8_t *val, uint32_t vlen)
{
    if (nox_buf_u16(b, type) < 0)
        return -1;
    if (nox_buf_u32(b, vlen) < 0)
        return -1;
    return nox_buf_put(b, val, vlen);
}
