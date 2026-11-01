#include "secret.h"
#include "packet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
nox_secret_lock(uint8_t **out, size_t *n, const nox_ident *id,
                const char *pass, size_t pass_len)
{
    nox_buf pt, file;
    uint8_t salt[16], nonce[24], mac[16], pw_key[32];
    uint8_t ad[18 + 4 + 33];
    uint8_t hdr[73];
    uint8_t *ct = NULL;
    size_t ct_len = 0;
    int i, rc = -1;

    if (id->raw == NULL)
        return nox_seterr("identity has no encoding");
    if (nox_random(salt, 16) < 0 || nox_random(nonce, 24) < 0)
        return -1;

    if (nox_buf_init(&pt, id->raw_len + 4096) < 0)
        return -1;
    nox_buf_put(&pt, id->raw, id->raw_len);
    for (i = 0; i < id->nkeys; i++) {
        const nox_key *k = &id->keys[i];
        uint8_t val[4 + 64];
        uint32_t slen;
        if (!k->has_sk) {
            nox_buf_free(&pt);
            return nox_seterr("missing secret key material");
        }
        if (k->encoding != NOX_ENC_SEED) {
            nox_buf_free(&pt);
            return nox_seterr("internal error: expected seed encoding");
        }
        slen = (uint32_t)k->sk_len;
        nox_be16(val, k->alg);
        val[2] = k->usage;
        val[3] = NOX_ENC_SEED;
        memcpy(val + 4, k->sk, slen);
        nox_buf_pkt(&pt, NOX_PKT_SECKEY, val, 4 + slen);
    }
    if (pt.err) {
        nox_buf_free(&pt);
        return -1;
    }

    nox_be32(hdr, NOX_ARGON2_T);
    nox_be32(hdr + 4, NOX_ARGON2_M);
    nox_be32(hdr + 8, NOX_ARGON2_P);
    nox_be32(hdr + 12, 32);
    hdr[16] = 16;
    memcpy(hdr + 17, salt, 16);
    memcpy(hdr + 33, nonce, 24);

    memcpy(ad, DS_SECRET, sizeof(DS_SECRET) - 1);
    ad[sizeof(DS_SECRET) - 1] = NOX_MAGIC0;
    ad[sizeof(DS_SECRET)]     = NOX_MAGIC1;
    ad[sizeof(DS_SECRET) + 1] = NOX_MAGIC2;
    ad[sizeof(DS_SECRET) + 2] = NOX_MAGIC3;
    memcpy(ad + sizeof(DS_SECRET) + 3, hdr, 33);

    if (nox_argon2id(pw_key, pass, pass_len, NOX_ARGON2_T, NOX_ARGON2_M,
                     NOX_ARGON2_P, salt) < 0) {
        nox_buf_free(&pt);
        goto out;
    }
    ct_len = pt.n;
    ct = malloc(ct_len);
    if (ct == NULL) {
        nox_buf_free(&pt);
        nox_seterr("out of memory");
        goto out;
    }
    ncrypt_aead_lock(ct, mac, pw_key, nonce, ad, sizeof ad, pt.p, ct_len);
    memcpy(hdr + 57, mac, 16);

    if (nox_buf_init(&file, 4 + 6 + 73 + pt.n) < 0) {
        nox_buf_free(&pt);
        goto out;
    }
    nox_buf_u8(&file, NOX_MAGIC0);
    nox_buf_u8(&file, NOX_MAGIC1);
    nox_buf_u8(&file, NOX_MAGIC2);
    nox_buf_u8(&file, NOX_MAGIC3);
    {
        nox_buf sec;
        if (nox_buf_init(&sec, 73 + pt.n) < 0) {
            nox_buf_free(&file);
            nox_buf_free(&pt);
            goto out;
        }
        nox_buf_put(&sec, hdr, 73);
        nox_buf_put(&sec, ct, ct_len);
        nox_buf_pkt(&file, NOX_PKT_SECRET, sec.p, (uint32_t)sec.n);
        nox_buf_free(&sec);
    }
    nox_buf_free(&pt);
    if (file.err) {
        nox_buf_free(&file);
        goto out;
    }
    *out = file.p;
    *n = file.n;
    file.p = NULL;
    nox_buf_free(&file);
    rc = 0;
out:
    nox_wipe(pw_key, sizeof pw_key);
    nox_wipe(salt, sizeof salt);
    nox_wipe(nonce, sizeof nonce);
    if (ct != NULL) {
        nox_wipe(ct, ct_len);
        free(ct);
    }
    return rc;
}

int
nox_secret_unlock(nox_ident *id, const uint8_t *buf, size_t n,
                  const char *pass, size_t pass_len)
{
    nox_parser p, inner;
    uint16_t type;
    int crit, i;
    const uint8_t *val;
    uint32_t vlen;
    uint32_t t, m, p_lanes, outlen;
    uint8_t salt_len;
    const uint8_t *salt, *nonce, *mac, *ct;
    size_t ct_len;
    uint8_t pw_key[32], ad[18 + 4 + 33];
    uint8_t *pt = NULL;
    int rc = -1;

    nox_ident_init(id);
    nox_parser_init(&p, buf, n);
    if (nox_skip_magic(&p) < 0)
        return -1;
    if (nox_pkt_next(&p, &type, &crit, &val, &vlen) < 0)
        return -1;
    if (type != NOX_PKT_SECRET)
        return nox_seterr("expected a secret key packet");
    if (nox_parser_left(&p))
        return nox_seterr("trailing bytes after secret key");
    if (vlen < 73)
        return nox_seterr("secret key is truncated");

    t = nox_rd32(val);
    m = nox_rd32(val + 4);
    p_lanes = nox_rd32(val + 8);
    outlen = nox_rd32(val + 12);
    salt_len = val[16];
    if (outlen != 32 || salt_len != 16)
        return nox_seterr("unsupported secret key KDF parameters");
    if (m < NOX_ARGON2_M_MIN || t < 3)
        fprintf(stderr, "nox: warning: weak Argon2id parameters (t=%u m=%u)\n",
                t, m);
    salt = val + 17;
    nonce = val + 33;
    mac = val + 57;
    ct = val + 73;
    ct_len = vlen - 73;

    memcpy(ad, DS_SECRET, sizeof(DS_SECRET) - 1);
    ad[sizeof(DS_SECRET) - 1] = NOX_MAGIC0;
    ad[sizeof(DS_SECRET)]     = NOX_MAGIC1;
    ad[sizeof(DS_SECRET) + 1] = NOX_MAGIC2;
    ad[sizeof(DS_SECRET) + 2] = NOX_MAGIC3;
    memcpy(ad + sizeof(DS_SECRET) + 3, val, 33);

    if (nox_argon2id(pw_key, pass, pass_len, t, m, p_lanes, salt) < 0)
        return -1;
    pt = malloc(ct_len);
    if (pt == NULL) {
        nox_wipe(pw_key, sizeof pw_key);
        return nox_seterr("out of memory");
    }
    if (ncrypt_aead_unlock(pt, mac, pw_key, nonce, ad, sizeof ad,
                           ct, ct_len) != 0) {
        nox_wipe(pw_key, sizeof pw_key);
        nox_wipe(pt, ct_len);
        free(pt);
        return nox_seterr("wrong passphrase or corrupted secret key");
    }
    nox_wipe(pw_key, sizeof pw_key);

    if (nox_ident_parse_value(id, pt, ct_len) < 0) {
        nox_wipe(pt, ct_len);
        free(pt);
        return -1;
    }
    nox_parser_init(&inner, pt + id->raw_len, ct_len - id->raw_len);
    if (id->nkeys == 0) {
        nox_ident_wipe(id);
        nox_wipe(pt, ct_len);
        free(pt);
        return nox_seterr("secret key contains no keys");
    }
    for (i = 0; i < id->nkeys; i++) {
        uint16_t t2, alg;
        int c;
        const uint8_t *v;
        uint32_t vn;
        uint8_t usage, enc;
        int slen;
        nox_key *k = &id->keys[i];
        uint8_t expanded[2560];
        size_t explen;

        if (nox_pkt_next(&inner, &t2, &c, &v, &vn) < 0)
            goto fail;
        if (t2 != NOX_PKT_SECKEY || vn < 4)
            goto fail;
        alg = nox_rd16(v);
        usage = v[2];
        enc = v[3];
        if (alg != k->alg || usage != k->usage)
            goto fail;
        if (enc == NOX_ENC_SEED)
            slen = nox_sk_seed_len(alg);
        else if (enc == NOX_ENC_EXP)
            slen = nox_sk_exp_len(alg);
        else
            goto fail;
        if (slen < 0 || vn != (uint32_t)(4 + slen))
            goto fail;
        k->encoding = enc;
        memcpy(k->sk, v + 4, (size_t)slen);
        k->sk_len = (size_t)slen;
        k->has_sk = 1;
        if (nox_key_expand(k, expanded, &explen) < 0)
            goto fail;
        nox_wipe(expanded, sizeof expanded);
    }
    if (nox_parser_left(&inner))
        goto fail;
    rc = 0;
fail:
    nox_wipe(pt, ct_len);
    free(pt);
    if (rc < 0) {
        nox_ident_wipe(id);
        if (nox_err[0] == 0)
            nox_seterr("secret key is corrupted");
    }
    return rc;
}
