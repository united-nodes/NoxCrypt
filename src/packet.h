#ifndef NOX_PACKET_H
#define NOX_PACKET_H

#include "util.h"

typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t off;
} nox_parser;

void nox_parser_init(nox_parser *p, const uint8_t *buf, size_t len);
int nox_parser_left(const nox_parser *p);
int nox_pkt_next(nox_parser *p, uint16_t *type, int *critical,
                 const uint8_t **val, uint32_t *vlen);
int nox_check_magic(const uint8_t *buf, size_t n);
int nox_skip_magic(nox_parser *p);
int nox_first_packet(const uint8_t *buf, size_t n, uint16_t *type);

#endif
