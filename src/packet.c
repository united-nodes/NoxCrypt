#include "packet.h"

void
nox_parser_init(nox_parser *p, const uint8_t *buf, size_t len)
{
    p->buf = buf;
    p->len = len;
    p->off = 0;
}

int
nox_parser_left(const nox_parser *p)
{
    return p->off < p->len;
}

int
nox_check_magic(const uint8_t *buf, size_t n)
{
    if (n < 4)
        return nox_seterr("truncated file (no magic)");
    if (buf[0] != NOX_MAGIC0 || buf[1] != NOX_MAGIC1 || buf[2] != NOX_MAGIC2)
        return nox_seterr("not a NoxCrypt file");
    if (buf[3] != NOX_MAGIC3)
        return nox_seterr("unsupported format version %u", buf[3]);
    return 0;
}

int
nox_skip_magic(nox_parser *p)
{
    if (nox_check_magic(p->buf, p->len) < 0)
        return -1;
    p->off = 4;
    return 0;
}

int
nox_pkt_next(nox_parser *p, uint16_t *type, int *critical,
             const uint8_t **val, uint32_t *vlen)
{
    size_t left;
    uint16_t t;
    uint32_t n;

    if (p->off > p->len)
        return nox_seterr("internal parser error");
    left = p->len - p->off;
    if (left < 6)
        return nox_seterr("truncated packet header");
    t = nox_rd16(p->buf + p->off);
    n = nox_rd32(p->buf + p->off + 2);
    if (t == 0)
        return nox_seterr("packet type 0 is reserved");
    if (n > left - 6)
        return nox_seterr("packet length exceeds input");
    *critical = (t & 0x8000) != 0;
    *type = (uint16_t)(t & 0x7fff);
    *val = p->buf + p->off + 6;
    *vlen = n;
    p->off += 6 + (size_t)n;
    return 0;
}

int
nox_first_packet(const uint8_t *buf, size_t n, uint16_t *type)
{
    nox_parser p;
    int crit;
    const uint8_t *val;
    uint32_t vlen;

    nox_parser_init(&p, buf, n);
    if (nox_skip_magic(&p) < 0)
        return -1;
    return nox_pkt_next(&p, type, &crit, &val, &vlen);
}
