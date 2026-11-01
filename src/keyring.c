#define _GNU_SOURCE

#include "keyring.h"
#include "armor.h"
#include "packet.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int
nox_keyring_dir(char *buf, size_t n)
{
    const char *home = nox_home_dir(NULL);
    int k;

    if (home == NULL)
        return nox_seterr("HOME is not set");
    k = snprintf(buf, n, "%s/.nox", home);
    if (k < 0 || (size_t)k >= n)
        return nox_seterr("path too long");
    return 0;
}

int
nox_keyring_init(void)
{
    char dir[4096];

    if (nox_keyring_dir(dir, sizeof dir) < 0)
        return -1;
    return nox_ensure_dir(dir, 0700);
}

int
nox_keyring_key_path(char *buf, size_t n, const uint8_t fp[NOX_FP_LEN],
                     const char *ext)
{
    char dir[4096], hex[65];
    int k;

    if (nox_keyring_dir(dir, sizeof dir) < 0)
        return -1;
    nox_hex(hex, fp, NOX_FP_LEN);
    k = snprintf(buf, n, "%s/%s.%s", dir, hex, ext);
    if (k < 0 || (size_t)k >= n)
        return nox_seterr("path too long");
    return 0;
}

int
nox_keyring_store_pub(const nox_ident *id)
{
    char path[4096];
    uint8_t *blob = NULL;
    size_t n = 0;
    int rc;

    if (nox_keyring_init() < 0)
        return -1;
    if (nox_keyring_key_path(path, sizeof path, id->fp, "pub") < 0)
        return -1;
    if (nox_ident_public_blob(id, &blob, &n) < 0)
        return -1;
    rc = nox_replace_file(path, blob, n, 0600);
    free(blob);
    return rc;
}

int
nox_keyring_store_sec(const uint8_t fp[NOX_FP_LEN],
                      const uint8_t *blob, size_t n)
{
    char path[4096];

    if (nox_keyring_init() < 0)
        return -1;
    if (nox_keyring_key_path(path, sizeof path, fp, "sec") < 0)
        return -1;
    return nox_replace_file(path, blob, n, 0600);
}

static int
hex64(const char *s)
{
    int i;

    for (i = 0; i < 64; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return 0;
    }
    return 1;
}

/* A keyring file name is <64 hex chars>.<pub|sec>, nothing else. */
static int
key_file(const char *name, const char *ext)
{
    return strlen(name) == 68 && name[64] == '.' &&
           hex64(name) && strcmp(name + 65, ext) == 0;
}

typedef struct {
    uint8_t fp[NOX_FP_LEN];
    char path[8192];
    int nmatch;
} kr_match;

static int
scan_ext(const char *query, const char *ext, kr_match *m)
{
    char dir[4096], want[65];
    DIR *dp;
    struct dirent *de;
    size_t qlen;

    memset(m, 0, sizeof *m);
    if (nox_keyring_dir(dir, sizeof dir) < 0)
        return -1;
    qlen = query ? strlen(query) : 0;
    if (qlen > 0) {
        size_t i;
        if (qlen > 64)
            return nox_seterr("fingerprint query too long");
        for (i = 0; i < qlen; i++) {
            int c = (unsigned char)query[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                  (c >= 'A' && c <= 'F')))
                return nox_seterr("'%s' is not a fingerprint prefix "
                                  "(hex only)", query);
            want[i] = (char)((c >= 'A' && c <= 'F') ? c + 'a' - 'A' : c);
        }
        want[qlen] = 0;
        if (qlen < 8)
            return nox_seterr("fingerprint prefix must be at least 8 hex characters");
    }

    dp = opendir(dir);
    if (dp == NULL) {
        if (errno == ENOENT)
            return 0;
        return nox_seterr("open %s: %s", dir, strerror(errno));
    }
    while ((de = readdir(dp)) != NULL) {
        char hex[65];
        uint8_t fp[NOX_FP_LEN];
        size_t fpn = NOX_FP_LEN;

        if (!key_file(de->d_name, ext))
            continue;
        memcpy(hex, de->d_name, 64);
        hex[64] = 0;
        if (nox_unhex(fp, &fpn, hex) < 0 || fpn != NOX_FP_LEN)
            continue;
        if (qlen > 0 && strncmp(hex, want, qlen) != 0)
            continue;
        m->nmatch++;
        if (m->nmatch == 1) {
            memcpy(m->fp, fp, NOX_FP_LEN);
            snprintf(m->path, sizeof m->path, "%s/%s", dir, de->d_name);
        }
    }
    closedir(dp);
    return 0;
}

int
nox_keyring_load_pub(const char *query, nox_ident *id)
{
    kr_match m;
    uint8_t *buf = NULL;
    size_t n = 0;
    int rc;

    if (scan_ext(query, "pub", &m) < 0)
        return -1;
    if (m.nmatch == 0)
        return nox_seterr("no public key matches '%s'", query ? query : "");
    if (m.nmatch > 1)
        return nox_seterr("fingerprint prefix '%s' is ambiguous", query);
    if (nox_read_file(m.path, &buf, &n, NOX_MAX_BLOB) < 0)
        return -1;
    rc = nox_ident_load_pub(id, buf, n);
    free(buf);
    return rc;
}

int
nox_keyring_load_sec_blob(const char *query, uint8_t **blob, size_t *n,
                          uint8_t fp[NOX_FP_LEN])
{
    kr_match m;

    if (scan_ext(query, "sec", &m) < 0)
        return -1;
    if (m.nmatch == 0)
        return nox_seterr("no secret key matches '%s'", query ? query : "");
    if (m.nmatch > 1)
        return nox_seterr("fingerprint prefix '%s' is ambiguous", query);
    memcpy(fp, m.fp, NOX_FP_LEN);
    return nox_read_file(m.path, blob, n, NOX_MAX_BLOB);
}

int
nox_keyring_delete(const char *query)
{
    kr_match pub, sec;
    int did = 0;

    if (query == NULL || query[0] == 0)
        return nox_seterr("delete requires a fingerprint prefix");
    if (scan_ext(query, "pub", &pub) < 0)
        return -1;
    if (scan_ext(query, "sec", &sec) < 0)
        return -1;
    if (pub.nmatch > 1 || sec.nmatch > 1)
        return nox_seterr("fingerprint prefix '%s' is ambiguous", query);
    if (pub.nmatch == 0 && sec.nmatch == 0)
        return nox_seterr("no key matches '%s'", query);
    if (pub.nmatch && sec.nmatch && nox_memeq(pub.fp, sec.fp, NOX_FP_LEN) != 0)
        return nox_seterr("fingerprint prefix '%s' is ambiguous", query);
    if (pub.nmatch) {
        if (unlink(pub.path) < 0)
            return nox_seterr("unlink %s: %s", pub.path, strerror(errno));
        did = 1;
    }
    if (sec.nmatch) {
        if (unlink(sec.path) < 0)
            return nox_seterr("unlink %s: %s", sec.path, strerror(errno));
        did = 1;
    }
    return did ? 0 : nox_seterr("no key matches '%s'", query);
}

int
nox_keyring_count_sec(void)
{
    kr_match m;

    if (scan_ext(NULL, "sec", &m) < 0)
        return -1;
    return m.nmatch;
}

static int
count_ext(const char *dir, const char *ext)
{
    DIR *dp;
    struct dirent *de;
    int n = 0;

    dp = opendir(dir);
    if (dp == NULL)
        return errno == ENOENT ? 0 : -1;
    while ((de = readdir(dp)) != NULL) {
        if (key_file(de->d_name, ext))
            n++;
    }
    closedir(dp);
    return n;
}

int
nox_keyring_stats(nox_keyring_info *st)
{
    char dir[4096];

    if (nox_keyring_dir(dir, sizeof dir) < 0)
        return -1;
    st->pub = count_ext(dir, "pub");
    st->sec = count_ext(dir, "sec");
    if (st->pub < 0 || st->sec < 0)
        return nox_seterr("open %s: %s", dir, strerror(errno));
    return 0;
}

static int
have_sec(const uint8_t fp[NOX_FP_LEN])
{
    char path[4096];
    struct stat st;

    if (nox_keyring_key_path(path, sizeof path, fp, "sec") < 0)
        return 0;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

struct kr_row {
    char hex[65];
    char date[16];
    char algs[160];
    char comment[NOX_MAX_COMMENT + 1];
    const char *profile;
    int has_sec;
};

static int
row_cmp(const void *a, const void *b)
{
    return strcmp(((const struct kr_row *)a)->hex,
                  ((const struct kr_row *)b)->hex);
}

int
nox_keyring_list(FILE *out, const char *query)
{
    char dir[4096];
    DIR *dp;
    struct dirent *de;
    struct kr_row *rows = NULL;
    size_t nrows = 0, cap = 0;
    size_t qlen = query ? strlen(query) : 0;
    int i;

    if (nox_keyring_dir(dir, sizeof dir) < 0)
        return -1;
    dp = opendir(dir);
    if (dp == NULL) {
        if (errno == ENOENT) {
            if (qlen > 0)
                fprintf(stderr, "nox: no key matches '%s'\n", query);
            else
                fprintf(stderr, "nox: no keys in %s\n", dir);
            return 0;
        }
        return nox_seterr("open %s: %s", dir, strerror(errno));
    }
    while ((de = readdir(dp)) != NULL) {
        char path[8192], hex[65];
        uint8_t *buf = NULL;
        size_t bn = 0;
        nox_ident id;
        int match;

        if (!key_file(de->d_name, "pub"))
            continue;
        memcpy(hex, de->d_name, 64);
        hex[64] = 0;
        match = 0;
        if (qlen > 0) {
            size_t k;
            if (qlen <= 64) {
                match = 1;
                for (k = 0; k < qlen; k++) {
                    int a = query[k], b = hex[k];
                    if (a >= 'A' && a <= 'F')
                        a += 'a' - 'A';
                    if (a != b) {
                        match = 0;
                        break;
                    }
                }
            }
        }
        snprintf(path, sizeof path, "%s/%s", dir, de->d_name);
        if (nox_read_file(path, &buf, &bn, NOX_MAX_BLOB) < 0) {
            closedir(dp);
            free(rows);
            return -1;
        }
        nox_ident_init(&id);
        if (nox_ident_load_pub(&id, buf, bn) < 0) {
            free(buf);
            fprintf(stderr, "nox: skipping %s: %s\n", de->d_name, nox_err);
            continue;
        }
        free(buf);
        if (!match && qlen > 0) {
            if (strcasestr(id.comment, query) == NULL) {
                nox_ident_wipe(&id);
                continue;
            }
        }
        if (nrows == cap) {
            struct kr_row *p;
            size_t ncap = cap ? cap * 2 : 16;
            p = realloc(rows, ncap * sizeof *rows);
            if (p == NULL) {
                nox_ident_wipe(&id);
                closedir(dp);
                free(rows);
                return nox_seterr("out of memory");
            }
            rows = p;
            cap = ncap;
        }
        {
            struct kr_row *r = &rows[nrows++];

            memcpy(r->hex, hex, 65);
            nox_fmt_date(r->date, sizeof r->date, id.created);
            r->profile = nox_ident_profile(&id);
            nox_ident_alg_list(&id, r->algs, sizeof r->algs);
            memcpy(r->comment, id.comment, sizeof r->comment);
            r->has_sec = have_sec(id.fp);
        }
        nox_ident_wipe(&id);
    }
    closedir(dp);

    /* readdir order is arbitrary; sort by fingerprint */
    if (nrows > 1)
        qsort(rows, nrows, sizeof *rows, row_cmp);

    for (i = 0; i < (int)nrows; i++) {
        if (i > 0)
            fputc('\n', out);
        fprintf(out, "%s  %s\n", rows[i].hex, rows[i].date);
        fprintf(out, "  %s: %s%s\n", rows[i].profile, rows[i].algs,
                rows[i].has_sec ? "" : " (no secret key)");
        fprintf(out, "  \"%s\"\n", rows[i].comment);
    }
    free(rows);
    if (nrows == 0) {
        if (qlen > 0)
            fprintf(stderr, "nox: no key matches '%s'\n", query);
        else
            fprintf(stderr, "nox: no keys in %s\n", dir);
    }
    return 0;
}
