#include "sign.h"
#include "packet.h"
#include "armor.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* "noxcrypt/v1/signature" || created || fingerprint || message hash */
#define SIG_MSG_LEN ((sizeof(DS_SIGNATURE) - 1) + 8 + 32 + 32)

int
nox_hash_file(FILE *fp, uint8_t hash[32])
{
    ncrypt_blake2b_ctx ctx;
    uint8_t buf[8192];

    ncrypt_blake2b_init(&ctx, 32);
    for (;;) {
        size_t r = fread(buf, 1, sizeof buf, fp);
        if (r > 0)
            ncrypt_blake2b_update(&ctx, buf, r);
        if (r < sizeof buf) {
            if (ferror(fp))
                return nox_seterr("read: %s", strerror(errno));
            break;
        }
    }
    ncrypt_blake2b_final(&ctx, hash);
    return 0;
}

static void
signed_msg(uint8_t msg[SIG_MSG_LEN], uint64_t created,
           const uint8_t fp[32], const uint8_t hash[32])
{
    memcpy(msg, DS_SIGNATURE, sizeof(DS_SIGNATURE) - 1);
    nox_be64(msg + sizeof(DS_SIGNATURE) - 1, created);
    memcpy(msg + sizeof(DS_SIGNATURE) - 1 + 8, fp, 32);
    memcpy(msg + sizeof(DS_SIGNATURE) - 1 + 8 + 32, hash, 32);
}

int
nox_sign_detached(uint8_t **out, size_t *n, nox_ident *id,
                  const uint8_t hash[32])
{
    uint8_t msg[SIG_MSG_LEN];
    nox_buf inner, file;
    uint64_t created;
    int i, nsign = 0, rc = -1;

    if (id->raw == NULL)
        return nox_seterr("identity has no encoding");
    for (i = 0; i < id->nkeys; i++) {
        if (id->keys[i].usage & NOX_USAGE_SIGN)
            nsign++;
    }
    if (nsign < 1)
        return nox_seterr("identity has no signing key");

    created = nox_now();
    signed_msg(msg, created, id->fp, hash);

    if (nox_buf_init(&inner, 16 + 8 + 32 + 64 + 2420 + 64) < 0)
        return -1;
    nox_buf_u64(&inner, created);
    nox_buf_put(&inner, id->fp, 32);

    for (i = 0; i < id->nkeys; i++) {
        nox_key *k = &id->keys[i];
        uint8_t sk[2560], sval[2 + 2420], rnd[32];
        size_t slen;
        int sigl;

        if ((k->usage & NOX_USAGE_SIGN) == 0)
            continue;
        if (!k->has_sk) {
            nox_buf_free(&inner);
            return nox_seterr("missing secret key material");
        }
        sigl = nox_sig_len(k->alg);
        if (sigl < 0) {
            nox_buf_free(&inner);
            return nox_seterr("not a signing algorithm");
        }
        if (nox_key_expand(k, sk, &slen) < 0) {
            nox_buf_free(&inner);
            return -1;
        }
        nox_be16(sval, k->alg);
        if (k->alg == NOX_ALG_ED25519) {
            ncrypt_ed25519_sign(sval + 2, sk, msg, sizeof msg);
        } else if (k->alg == NOX_ALG_MLDSA44) {
            if (nox_random(rnd, sizeof rnd) < 0) {
                nox_wipe(sk, sizeof sk);
                nox_buf_free(&inner);
                return -1;
            }
            if (ncrypt_mldsa44_sign(sval + 2, sk, rnd, NULL, 0,
                                    msg, sizeof msg) != 0) {
                nox_wipe(rnd, sizeof rnd);
                nox_wipe(sk, sizeof sk);
                nox_buf_free(&inner);
                return nox_seterr("ML-DSA-44 signing failed");
            }
            nox_wipe(rnd, sizeof rnd);
        }
        else {
            nox_wipe(sk, sizeof sk);
            nox_buf_free(&inner);
            return nox_seterr("not a signing algorithm");
        }
        nox_wipe(sk, sizeof sk);
        nox_buf_pkt(&inner, NOX_PKT_SIG, sval, (uint32_t)(2 + sigl));
        nox_wipe(sval, sizeof sval);
    }
    if (inner.err) {
        nox_buf_free(&inner);
        return -1;
    }
    if (nox_buf_init(&file, 4 + 6 + inner.n) < 0) {
        nox_buf_free(&inner);
        return -1;
    }
    nox_buf_u8(&file, NOX_MAGIC0);
    nox_buf_u8(&file, NOX_MAGIC1);
    nox_buf_u8(&file, NOX_MAGIC2);
    nox_buf_u8(&file, NOX_MAGIC3);
    nox_buf_pkt(&file, NOX_PKT_DETSIG, inner.p, (uint32_t)inner.n);
    nox_buf_free(&inner);
    if (file.err) {
        nox_buf_free(&file);
        return -1;
    }
    *out = file.p;
    *n = file.n;
    file.p = NULL;
    nox_buf_free(&file);
    rc = 0;
    nox_wipe(msg, sizeof msg);
    return rc;
}

int
nox_verify_detached(const uint8_t *sig, size_t n, nox_ident *id,
                    const uint8_t hash[32])
{
    uint8_t *raw = NULL;
    size_t rn = 0;
    nox_parser p, inner;
    uint16_t type;
    int crit, i, left, rc = -1;
    const uint8_t *val;
    uint32_t vlen;
    uint64_t created;
    const uint8_t *fp;
    uint8_t msg[SIG_MSG_LEN];

    if (nox_unwrap_blob(&raw, &rn, sig, n) < 0)
        return -1;
    nox_parser_init(&p, raw, rn);
    if (nox_skip_magic(&p) < 0)
        goto out;
    if (nox_pkt_next(&p, &type, &crit, &val, &vlen) < 0)
        goto out;
    if (type != NOX_PKT_DETSIG) {
        nox_seterr("expected a detached signature");
        goto out;
    }
    if (nox_parser_left(&p)) {
        nox_seterr("trailing bytes after signature");
        goto out;
    }
    if (vlen < 8 + 32) {
        nox_seterr("signature is truncated");
        goto out;
    }
    created = nox_rd64(val);
    fp = val + 8;
    if (nox_memeq(fp, id->fp, 32) != 0) {
        nox_seterr("signature does not match this public key");
        goto out;
    }
    signed_msg(msg, created, fp, hash);

    left = 0;
    for (i = 0; i < id->nkeys; i++) {
        if (id->keys[i].usage & NOX_USAGE_SIGN)
            left++;
    }
    if (left < 1) {
        nox_seterr("public key has no signing key");
        goto out;
    }

    nox_parser_init(&inner, val + 40, vlen - 40);
    for (i = 0; i < id->nkeys; i++) {
        nox_key *k = &id->keys[i];
        uint16_t t, alg;
        int c;
        const uint8_t *v;
        uint32_t vn;
        int sl;

        if ((k->usage & NOX_USAGE_SIGN) == 0)
            continue;
        if (nox_pkt_next(&inner, &t, &c, &v, &vn) < 0) {
            nox_seterr("signature is missing a required algorithm");
            goto out;
        }
        if (t != NOX_PKT_SIG || vn < 2) {
            nox_seterr("malformed signature packet");
            goto out;
        }
        alg = nox_rd16(v);
        sl = nox_sig_len(alg);
        if (alg != k->alg || sl < 0 || vn != (uint32_t)(2 + sl)) {
            nox_seterr("signature algorithm mismatch (downgrade rejected)");
            goto out;
        }
        if (alg == NOX_ALG_ED25519) {
            if (ncrypt_ed25519_check(v + 2, k->pk, msg, sizeof msg) != 0) {
                nox_seterr("bad signature");
                goto out;
            }
        } else if (alg == NOX_ALG_MLDSA44) {
            if (ncrypt_mldsa44_check(v + 2, k->pk, NULL, 0,
                                     msg, sizeof msg) != 0) {
                nox_seterr("bad signature");
                goto out;
            }
        } else {
            nox_seterr("unsupported signature algorithm");
            goto out;
        }
        left--;
    }
    if (left != 0 || nox_parser_left(&inner)) {
        nox_seterr("signature algorithm mismatch (downgrade rejected)");
        goto out;
    }
    rc = 0;
out:
    free(raw);
    nox_wipe(msg, sizeof msg);
    return rc;
}
