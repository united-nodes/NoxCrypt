#ifndef NOX_ARMOR_H
#define NOX_ARMOR_H

#include "util.h"

#define NOX_KIND_PUB  "PUBLIC KEY"
#define NOX_KIND_SEC  "SECRET KEY"
#define NOX_KIND_MSG  "MESSAGE"
#define NOX_KIND_SIG  "SIGNATURE"

int nox_b64_encode(char **out, size_t *out_n, const uint8_t *in, size_t n);
int nox_b64_decode(uint8_t **out, size_t *out_n, const uint8_t *in, size_t n);

int nox_armor(char **out, size_t *out_n, const uint8_t *in, size_t n,
              const char *kind);
int nox_dearmor(uint8_t **out, size_t *out_n, const uint8_t *in, size_t n);
int nox_looks_armored(const uint8_t *buf, size_t n);

/* Decode a blob that may be armored or raw binary. */
int nox_unwrap_blob(uint8_t **out, size_t *out_n, const uint8_t *in, size_t n);

typedef struct {
    FILE *fp;
    int armor;
    int finished;
    uint8_t rem[3];
    int nrem;
    int col;
    const char *kind;
} nox_writer;

int nox_writer_init(nox_writer *w, FILE *fp, int armor, const char *kind);
int nox_writer_write(nox_writer *w, const void *buf, size_t n);
int nox_writer_finish(nox_writer *w);

typedef struct {
    FILE *fp;
    int armor;
    int eof;
    int err;
    /*
     * Bytes that were read past a decision point and must be
     * replayed before touching fp again.  (Repeated ungetc() is
     * not portable, so the reader carries its own pushback.)
     */
    uint8_t push[1024];
    int npush;
    int poff;
    /* armor decoder */
    int body;
    uint8_t acc[4];
    int nacc;
    uint8_t dec[3];
    int ndec;
    int doff;
    int pend; /* seen padding */
} nox_reader;

int nox_reader_init(nox_reader *r, FILE *fp);
int nox_reader_read(nox_reader *r, void *buf, size_t n); /* bytes read, 0 eof, -1 err */
int nox_reader_eof(nox_reader *r);

#endif
