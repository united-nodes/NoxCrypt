#include "armor.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static const char b64tab[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int
b64val(int c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

int
nox_b64_encode(char **out, size_t *out_n, const uint8_t *in, size_t n)
{
    size_t groups = (n + 2) / 3;
    size_t cap = groups * 4 + 1;
    char *s;
    size_t i, o = 0;

    s = malloc(cap);
    if (s == NULL)
        return nox_seterr("out of memory");
    for (i = 0; i < n; i += 3) {
        unsigned a = in[i];
        unsigned b = (i + 1 < n) ? in[i + 1] : 0;
        unsigned c = (i + 2 < n) ? in[i + 2] : 0;
        unsigned v = (a << 16) | (b << 8) | c;
        s[o++] = b64tab[(v >> 18) & 63];
        s[o++] = b64tab[(v >> 12) & 63];
        s[o++] = (i + 1 < n) ? b64tab[(v >> 6) & 63] : '=';
        s[o++] = (i + 2 < n) ? b64tab[v & 63] : '=';
    }
    s[o] = 0;
    *out = s;
    *out_n = o;
    return 0;
}

int
nox_b64_decode(uint8_t **out, size_t *out_n, const uint8_t *in, size_t n)
{
    uint8_t *clean, *dst;
    size_t i, m = 0, o = 0;
    int pad = 0;

    clean = malloc(n + 4); /* +3 slack for padding fill, +1 NUL safety */
    if (clean == NULL)
        return nox_seterr("out of memory");
    for (i = 0; i < n; i++) {
        unsigned char c = in[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
            c == '\v' || c == '\f')
            continue;
        clean[m++] = c;
    }
    if (m == 0) {
        free(clean);
        *out = malloc(1);
        if (*out == NULL)
            return nox_seterr("out of memory");
        *out_n = 0;
        return 0;
    }
    if (m % 4 == 1) {
        free(clean);
        return nox_seterr("invalid base64 length");
    }
    /* tolerate missing padding */
    while (m % 4 != 0)
        clean[m++] = '=';

    dst = malloc(m / 4 * 3);
    if (dst == NULL) {
        free(clean);
        return nox_seterr("out of memory");
    }
    for (i = 0; i < m; i += 4) {
        int a, b, c, d;
        if (clean[i] == '=' || clean[i + 1] == '=') {
            free(clean);
            free(dst);
            return nox_seterr("invalid base64 padding");
        }
        a = b64val(clean[i]);
        b = b64val(clean[i + 1]);
        if (a < 0 || b < 0)
            goto bad;
        if (clean[i + 2] == '=') {
            if (clean[i + 3] != '=')
                goto bad;
            c = d = 0;
            pad = 2;
        } else {
            c = b64val(clean[i + 2]);
            if (c < 0)
                goto bad;
            if (clean[i + 3] == '=') {
                d = 0;
                pad = 1;
            } else {
                d = b64val(clean[i + 3]);
                if (d < 0)
                    goto bad;
                pad = 0;
            }
        }
        if (pad && i + 4 != m)
            goto bad;
        dst[o++] = (uint8_t)((a << 2) | (b >> 4));
        if (pad < 2)
            dst[o++] = (uint8_t)((b << 4) | (c >> 2));
        if (pad < 1)
            dst[o++] = (uint8_t)((c << 6) | d);
        if (pad)
            break;
    }
    free(clean);
    *out = dst;
    *out_n = o;
    return 0;
bad:
    free(clean);
    free(dst);
    return nox_seterr("invalid base64 character");
}

int
nox_armor(char **out, size_t *out_n, const uint8_t *in, size_t n,
          const char *kind)
{
    char *b64 = NULL, *s;
    size_t b64n = 0, i, o, lines, cap;

    if (nox_b64_encode(&b64, &b64n, in, n) < 0)
        return -1;
    lines = (b64n + 63) / 64;
    cap = strlen("-----BEGIN NOX -----\n\n-----END NOX -----\n") +
          2 * strlen(kind) + b64n + lines + 8;
    s = malloc(cap);
    if (s == NULL) {
        free(b64);
        return nox_seterr("out of memory");
    }
    o = (size_t)snprintf(s, cap, "-----BEGIN NOX %s-----\n\n", kind);
    for (i = 0; i < b64n; i += 64) {
        size_t chunk = b64n - i;
        if (chunk > 64)
            chunk = 64;
        memcpy(s + o, b64 + i, chunk);
        o += chunk;
        s[o++] = '\n';
    }
    o += (size_t)snprintf(s + o, cap - o, "-----END NOX %s-----\n", kind);
    free(b64);
    *out = s;
    *out_n = o;
    return 0;
}

int
nox_looks_armored(const uint8_t *buf, size_t n)
{
    const char *p = "-----BEGIN ";
    size_t i;

    if (n < 11)
        return 0;
    for (i = 0; i < 11; i++) {
        if (buf[i] != (uint8_t)p[i])
            return 0;
    }
    return 1;
}

int
nox_dearmor(uint8_t **out, size_t *out_n, const uint8_t *in, size_t n)
{
    const uint8_t *p = in, *end = in + n;
    const uint8_t *body, *body_end;
    int seen_blank = 0;

    /* skip leading whitespace */
    while (p < end && (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t'))
        p++;
    if ((size_t)(end - p) < 11 || memcmp(p, "-----BEGIN ", 11) != 0)
        return nox_seterr("missing armor header");
    /* consume the BEGIN line */
    while (p < end && *p != '\n')
        p++;
    if (p < end)
        p++;

    /*
     * Headers live between BEGIN and the first blank line.  If the
     * first non-empty line already looks like base64, accept it as
     * the body (lenient input).
     */
    body = p;
    while (p < end) {
        const uint8_t *line = p;
        while (p < end && *p != '\n')
            p++;
        {
            size_t ln = (size_t)(p - line);
            if (p < end && *p == '\n')
                p++;
            /* strip CR */
            if (ln > 0 && line[ln - 1] == '\r')
                ln--;
            if (ln == 0) {
                seen_blank = 1;
                body = p;
                break;
            }
            if (ln >= 9 && memcmp(line, "-----END ", 9) == 0)
                return nox_seterr("empty armor body");
            /* if this line is base64-ish, treat as body start */
            {
                size_t k;
                int b64line = 1;
                for (k = 0; k < ln; k++) {
                    int c = line[k];
                    if (b64val(c) < 0 && c != '=') {
                        b64line = 0;
                        break;
                    }
                }
                if (b64line && !seen_blank) {
                    body = line;
                    break;
                }
            }
        }
    }

    /* find END line */
    body_end = body;
    p = body;
    while (p < end) {
        const uint8_t *line = p;
        while (p < end && *p != '\n')
            p++;
        {
            size_t ln = (size_t)(p - line);
            if (p < end && *p == '\n')
                p++;
            if (ln > 0 && line[ln - 1] == '\r')
                ln--;
            if (ln >= 9 && memcmp(line, "-----END ", 9) == 0) {
                body_end = line;
                break;
            }
            body_end = p;
        }
    }
    if (body_end == body && (end - body) > 0) {
        /* no END marker: still try to decode remaining bytes */
        body_end = end;
    }
    return nox_b64_decode(out, out_n, body, (size_t)(body_end - body));
}

int
nox_unwrap_blob(uint8_t **out, size_t *out_n, const uint8_t *in, size_t n)
{
    if (n == 0)
        return nox_seterr("empty input");
    if (nox_looks_armored(in, n))
        return nox_dearmor(out, out_n, in, n);
    /* copy so caller can always free() */
    *out = malloc(n);
    if (*out == NULL)
        return nox_seterr("out of memory");
    memcpy(*out, in, n);
    *out_n = n;
    return 0;
}

static int
wr_raw(FILE *fp, const void *buf, size_t n)
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

static int
flush_line(nox_writer *w, const uint8_t *block, int nbytes)
{
    char line[4];
    unsigned a = block[0];
    unsigned b = nbytes > 1 ? block[1] : 0;
    unsigned c = nbytes > 2 ? block[2] : 0;
    unsigned v = (a << 16) | (b << 8) | c;

    line[0] = b64tab[(v >> 18) & 63];
    line[1] = b64tab[(v >> 12) & 63];
    line[2] = nbytes > 1 ? b64tab[(v >> 6) & 63] : '=';
    line[3] = nbytes > 2 ? b64tab[v & 63] : '=';
    if (wr_raw(w->fp, line, 4) < 0)
        return -1;
    return 0;
}

int
nox_writer_init(nox_writer *w, FILE *fp, int armor, const char *kind)
{
    memset(w, 0, sizeof *w);
    w->fp = fp;
    w->armor = armor;
    w->kind = kind;
    if (armor) {
        if (fprintf(fp, "-----BEGIN NOX %s-----\n\n", kind) < 0)
            return nox_seterr("write: %s", strerror(errno));
    }
    return 0;
}

int
nox_writer_write(nox_writer *w, const void *buf, size_t n)
{
    const uint8_t *p = buf;

    if (w->finished)
        return nox_seterr("write after finish");
    if (!w->armor)
        return wr_raw(w->fp, buf, n);

    while (n > 0) {
        int take = 3 - w->nrem;
        if ((size_t)take > n)
            take = (int)n;
        memcpy(w->rem + w->nrem, p, (size_t)take);
        w->nrem += take;
        p += take;
        n -= (size_t)take;
        if (w->nrem == 3) {
            if (flush_line(w, w->rem, 3) < 0)
                return -1;
            w->col += 4;
            w->nrem = 0;
            if (w->col >= 64) {
                if (wr_raw(w->fp, "\n", 1) < 0)
                    return -1;
                w->col = 0;
            }
        }
    }
    return 0;
}

int
nox_writer_finish(nox_writer *w)
{
    if (w->finished)
        return 0;
    w->finished = 1;
    if (!w->armor) {
        if (fflush(w->fp) != 0)
            return nox_seterr("write: %s", strerror(errno));
        return 0;
    }
    if (w->nrem > 0) {
        if (flush_line(w, w->rem, w->nrem) < 0)
            return -1;
        w->col += 4;
        w->nrem = 0;
    }
    if (w->col > 0) {
        if (wr_raw(w->fp, "\n", 1) < 0)
            return -1;
    }
    if (fprintf(w->fp, "-----END NOX %s-----\n", w->kind) < 0)
        return nox_seterr("write: %s", strerror(errno));
    if (fflush(w->fp) != 0)
        return nox_seterr("write: %s", strerror(errno));
    return 0;
}

static int
rd_getc(nox_reader *r)
{
    int c;

    if (r->poff < r->npush)
        return r->push[r->poff++];
    c = fgetc(r->fp);
    if (c == EOF) {
        if (ferror(r->fp)) {
            r->err = 1;
            nox_seterr("read: %s", strerror(errno));
        }
        r->eof = 1;
    }
    return c;
}

static int
skip_armor_header(nox_reader *r)
{
    char line[sizeof r->push];
    int pos, c, seen_begin = 0, overlong;

    for (;;) {
        pos = 0;
        overlong = 0;
        for (;;) {
            c = rd_getc(r);
            if (c == EOF)
                return nox_seterr("truncated armor header");
            if (c == '\n')
                break;
            if (c == '\r')
                continue;
            if (pos < (int)sizeof line - 1)
                line[pos++] = (char)c;
            else
                overlong = 1;
        }
        line[pos] = 0;
        if (!seen_begin) {
            if (strncmp(line, "-----BEGIN ", 11) != 0) {
                /* allow leading blank lines */
                if (pos == 0)
                    continue;
                return nox_seterr("missing armor header");
            }
            seen_begin = 1;
            continue;
        }
        if (pos == 0)
            return 0; /* blank line, body follows */
        /* a base64 line with no preceding blank: treat as body */
        {
            int i, b64line = pos > 0;
            for (i = 0; i < pos; i++) {
                if (b64val((unsigned char)line[i]) < 0 && line[i] != '=') {
                    b64line = 0;
                    break;
                }
            }
            if (b64line) {
                /*
                 * Hand the line to the decoder through the reader's
                 * own pushback (ungetc() loops are not portable and
                 * cannot be trusted past one character).
                 */
                if (overlong)
                    return nox_seterr("armor body line is too long");
                memcpy(r->push, line, (size_t)pos);
                r->push[pos] = '\n';
                r->npush = pos + 1;
                r->poff = 0;
                return 0;
            }
        }
        /* otherwise a header, ignore */
    }
}

static void
rd_push_char(nox_reader *r, int c)
{
    if (r->npush < (int)sizeof r->push)
        r->push[r->npush++] = (uint8_t)c;
    r->poff = 0; /* everything queued becomes pending again */
}

int
nox_reader_init(nox_reader *r, FILE *fp)
{
    int c;

    memset(r, 0, sizeof *r);
    r->fp = fp;
    /* skip a leading UTF-8 BOM if present, then detect */
    c = rd_getc(r);
    if (c == 0xEF) {
        int c2 = rd_getc(r);
        int c3 = rd_getc(r);

        if (c2 == 0xBB && c3 == 0xBF) {
            c = rd_getc(r);
        } else if (c2 == EOF || c3 == EOF) {
            /* "EF" or "EF BB" alone is too short to be anything */
            return nox_seterr("empty input");
        } else {
            /*
             * Not a BOM.  The three bytes belong to the stream, so
             * they go back into the pushback queue; the detection
             * byte is taken from the file behind them.
             */
            r->push[0] = (uint8_t)c;
            r->push[1] = (uint8_t)c2;
            r->push[2] = (uint8_t)c3;
            r->npush = 3;
            r->poff = 0;
            c = fgetc(fp);
            if (c == EOF) {
                if (ferror(fp)) {
                    r->err = 1;
                    nox_seterr("read: %s", strerror(errno));
                }
                r->eof = 1;
            }
        }
    }
    if (c == EOF)
        return nox_seterr("empty input");
    if (c == '-') {
        r->armor = 1;
        rd_push_char(r, c);
        return skip_armor_header(r);
    }
    if (c == 'N') {
        r->armor = 0;
        rd_push_char(r, c);
        return 0;
    }
    return nox_seterr("input is neither a NoxCrypt file nor armor");
}

static int
armor_fill(nox_reader *r)
{
    if (r->doff < r->ndec)
        return 0;
    r->ndec = r->doff = 0;
    if (r->eof)
        return 0;

    while (r->nacc < 4) {
        int c = rd_getc(r);
        if (c == EOF) {
            if (r->nacc == 0)
                return 0;
            return nox_seterr("truncated base64");
        }
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
            c == '\v' || c == '\f')
            continue;
        if (c == '-') {
            /* END line. consume it. */
            while (c != EOF && c != '\n')
                c = rd_getc(r);
            r->eof = 1;
            if (r->nacc == 0)
                return 0;
            /* missing padding: accept 2 or 3 leftover chars */
            while (r->nacc < 4)
                r->acc[r->nacc++] = '=';
            break;
        }
        if (c == '=') {
            r->acc[r->nacc++] = (uint8_t)c;
            r->pend = 1;
            continue;
        }
        if (r->pend)
            return nox_seterr("data after base64 padding");
        if (b64val(c) < 0)
            return nox_seterr("invalid base64 character");
        r->acc[r->nacc++] = (uint8_t)c;
    }
    if (r->nacc == 0)
        return 0;
    {
        int a, b, c, d, pad = 0;
        if (r->acc[0] == '=' || r->acc[1] == '=')
            return nox_seterr("invalid base64 padding");
        a = b64val(r->acc[0]);
        b = b64val(r->acc[1]);
        if (r->acc[2] == '=') {
            if (r->acc[3] != '=')
                return nox_seterr("invalid base64 padding");
            c = d = 0;
            pad = 2;
        } else if (r->acc[3] == '=') {
            c = b64val(r->acc[2]);
            d = 0;
            pad = 1;
            if (c < 0)
                return nox_seterr("invalid base64 character");
        } else {
            c = b64val(r->acc[2]);
            d = b64val(r->acc[3]);
            if (c < 0 || d < 0)
                return nox_seterr("invalid base64 character");
        }
        r->dec[0] = (uint8_t)((a << 2) | (b >> 4));
        r->ndec = 1;
        if (pad < 2) {
            r->dec[1] = (uint8_t)((b << 4) | (c >> 2));
            r->ndec = 2;
        }
        if (pad < 1) {
            r->dec[2] = (uint8_t)((c << 6) | d);
            r->ndec = 3;
        }
        r->nacc = 0;
        if (pad)
            r->eof = 1;
    }
    return 0;
}

int
nox_reader_read(nox_reader *r, void *buf, size_t n)
{
    uint8_t *p = buf;
    size_t got = 0;

    if (r->err)
        return -1;
    if (!r->armor) {
        while (got < n) {
            size_t k;
            if (r->poff < r->npush) {
                p[got++] = r->push[r->poff++];
                continue;
            }
            k = fread(p + got, 1, n - got, r->fp);
            got += k;
            if (k == 0) {
                if (ferror(r->fp)) {
                    r->err = 1;
                    return nox_seterr("read: %s", strerror(errno));
                }
                r->eof = 1;
                break;
            }
        }
        return (int)got;
    }
    while (got < n) {
        if (r->doff >= r->ndec) {
            if (armor_fill(r) < 0) {
                r->err = 1;
                return -1;
            }
            if (r->doff >= r->ndec) {
                r->eof = 1;
                break;
            }
        }
        p[got++] = r->dec[r->doff++];
    }
    return (int)got;
}

int
nox_reader_eof(nox_reader *r)
{
    if (r->armor)
        return r->eof && r->doff >= r->ndec;
    if (r->eof)
        return 1;
    {
        int c = fgetc(r->fp);
        if (c == EOF)
            return 1;
        ungetc(c, r->fp);
        return 0;
    }
}
