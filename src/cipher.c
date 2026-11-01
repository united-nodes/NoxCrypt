#include "cipher.h"
#include "packet.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define HYBRID_RVAL 1226
#define X25519_RVAL 138
#define MLKEM_RVAL  1194
#define PASS_RVAL   107

static const uint8_t zeros32[32];

static int
read_exact(nox_reader *r, void *buf, size_t n)
{
    uint8_t *p = buf;
    size_t got = 0;

    while (got < n) {
        int k = nox_reader_read(r, p + got, n - got);
        if (k < 0)
            return -1;
        if (k == 0)
            return nox_seterr("truncated ciphertext");
        got += (size_t)k;
    }
    return 0;
}

static int
x25519_wrap_key(uint8_t out[32], const uint8_t sk[32], const uint8_t peer_pk[32],
                const uint8_t eph_pk[32], const uint8_t static_pk[32])
{
    uint8_t raw[32];
    ncrypt_blake2b_ctx ctx;

    ncrypt_x25519(raw, sk, peer_pk);
    if (ncrypt_verify32(raw, zeros32) == 0) {
        nox_wipe(raw, 32);
        return nox_seterr("X25519 shared secret is all zeros");
    }
    ncrypt_blake2b_init(&ctx, 32);
    ncrypt_blake2b_update(&ctx, (const uint8_t *)DS_X25519WRAP,
                          sizeof(DS_X25519WRAP) - 1);
    ncrypt_blake2b_update(&ctx, eph_pk, 32);
    ncrypt_blake2b_update(&ctx, static_pk, 32);
    ncrypt_blake2b_update(&ctx, raw, 32);
    ncrypt_blake2b_final(&ctx, out);
    nox_wipe(raw, 32);
    return 0;
}

static void
mlkem_wrap_key(uint8_t out[32], const uint8_t kem_ct[1088],
               const uint8_t pk[1184], const uint8_t ss[32])
{
    ncrypt_blake2b_ctx ctx;

    ncrypt_blake2b_init(&ctx, 32);
    ncrypt_blake2b_update(&ctx, (const uint8_t *)DS_MLKEMWRAP,
                          sizeof(DS_MLKEMWRAP) - 1);
    ncrypt_blake2b_update(&ctx, kem_ct, 1088);
    ncrypt_blake2b_update(&ctx, pk, 1184);
    ncrypt_blake2b_update(&ctx, ss, 32);
    ncrypt_blake2b_final(&ctx, out);
}

static void
hybrid_wrap_key(uint8_t out[32], const uint8_t xk[32], const uint8_t kk[32],
                const uint8_t fp[32])
{
    ncrypt_blake2b_ctx ctx;

    ncrypt_blake2b_init(&ctx, 32);
    ncrypt_blake2b_update(&ctx, (const uint8_t *)DS_HYBRIDWRAP,
                          sizeof(DS_HYBRIDWRAP) - 1);
    ncrypt_blake2b_update(&ctx, xk, 32);
    ncrypt_blake2b_update(&ctx, kk, 32);
    ncrypt_blake2b_update(&ctx, fp, 32);
    ncrypt_blake2b_final(&ctx, out);
}

static void
wrap_ad(uint8_t ad[46], const uint8_t nonce[24])
{
    memcpy(ad, DS_HEADER, sizeof(DS_HEADER) - 1);
    ad[sizeof(DS_HEADER) - 1] = NOX_MAGIC0;
    ad[sizeof(DS_HEADER)]     = NOX_MAGIC1;
    ad[sizeof(DS_HEADER) + 1] = NOX_MAGIC2;
    ad[sizeof(DS_HEADER) + 2] = NOX_MAGIC3;
    memcpy(ad + sizeof(DS_HEADER) + 3, nonce, 24);
}

static const nox_key *
enc_key(const nox_ident *id, uint16_t alg)
{
    const nox_key *k = nox_ident_find(id, alg);

    if (k == NULL || (k->usage & NOX_USAGE_ENCRYPT) == 0)
        return NULL;
    return k;
}

static int
wrap_x25519(nox_buf *recs, const nox_ident *recip, const uint8_t file_key[32],
            const uint8_t ad[46])
{
    const nox_key *kx = enc_key(recip, NOX_ALG_X25519);
    uint8_t eph_sk[32], eph_pk[32], xk[32];
    uint8_t nonce[24], mac[16], wrapped[32];
    uint8_t val[X25519_RVAL];
    int rc = -1;

    if (kx == NULL)
        return nox_seterr("recipient has no X25519 encryption key");
    if (nox_random(eph_sk, 32) < 0 || nox_random(nonce, 24) < 0)
        return -1;
    ncrypt_x25519_public_key(eph_pk, eph_sk);
    if (x25519_wrap_key(xk, eph_sk, kx->pk, eph_pk, kx->pk) < 0)
        goto out;
    ncrypt_aead_lock(wrapped, mac, xk, nonce, ad, 46, file_key, 32);

    nox_be16(val, NOX_ALG_X25519);
    memcpy(val + 2, recip->fp, 32);
    memcpy(val + 34, eph_pk, 32);
    memcpy(val + 66, nonce, 24);
    memcpy(val + 90, mac, 16);
    memcpy(val + 106, wrapped, 32);
    rc = nox_buf_pkt(recs, NOX_PKT_RECIPIENT, val, X25519_RVAL);
out:
    nox_wipe(eph_sk, sizeof eph_sk);
    nox_wipe(xk, sizeof xk);
    nox_wipe(nonce, sizeof nonce);
    nox_wipe(wrapped, sizeof wrapped);
    return rc;
}

static int
wrap_mlkem(nox_buf *recs, const nox_ident *recip, const uint8_t file_key[32],
           const uint8_t ad[46])
{
    const nox_key *kk = enc_key(recip, NOX_ALG_MLKEM768);
    uint8_t kem_seed[32], kem_ct[1088], ss[32], mk[32];
    uint8_t nonce[24], mac[16], wrapped[32];
    uint8_t val[MLKEM_RVAL];
    int rc = -1;

    if (kk == NULL)
        return nox_seterr("recipient has no ML-KEM-768 encryption key");
    if (nox_random(kem_seed, 32) < 0 || nox_random(nonce, 24) < 0)
        return -1;
    if (ncrypt_mlkem768_encapsulate(kem_ct, ss, kk->pk, kem_seed) != 0) {
        nox_seterr("ML-KEM-768 encapsulation failed (malformed public key)");
        goto out;
    }
    mlkem_wrap_key(mk, kem_ct, kk->pk, ss);
    ncrypt_aead_lock(wrapped, mac, mk, nonce, ad, 46, file_key, 32);

    nox_be16(val, NOX_ALG_MLKEM768);
    memcpy(val + 2, recip->fp, 32);
    memcpy(val + 34, kem_ct, 1088);
    memcpy(val + 1122, nonce, 24);
    memcpy(val + 1146, mac, 16);
    memcpy(val + 1162, wrapped, 32);
    rc = nox_buf_pkt(recs, NOX_PKT_RECIPIENT, val, MLKEM_RVAL);
out:
    nox_wipe(kem_seed, sizeof kem_seed);
    nox_wipe(ss, sizeof ss);
    nox_wipe(mk, sizeof mk);
    nox_wipe(nonce, sizeof nonce);
    nox_wipe(wrapped, sizeof wrapped);
    return rc;
}

static int
wrap_hybrid(nox_buf *recs, const nox_ident *recip, const uint8_t file_key[32],
            const uint8_t ad[46])
{
    const nox_key *kx = enc_key(recip, NOX_ALG_X25519);
    const nox_key *kk = enc_key(recip, NOX_ALG_MLKEM768);
    uint8_t eph_sk[32], eph_pk[32], xk[32];
    uint8_t kem_seed[32], kem_ct[1088], ss[32], mk[32], wk[32];
    uint8_t nonce[24], mac[16], wrapped[32];
    uint8_t val[HYBRID_RVAL];
    int rc = -1;

    if (kx == NULL || kk == NULL)
        return nox_seterr("recipient is missing hybrid encryption keys");

    if (nox_random(eph_sk, 32) < 0 ||
        nox_random(kem_seed, 32) < 0 ||
        nox_random(nonce, 24) < 0)
        return -1;
    ncrypt_x25519_public_key(eph_pk, eph_sk);
    if (x25519_wrap_key(xk, eph_sk, kx->pk, eph_pk, kx->pk) < 0)
        goto out;
    if (ncrypt_mlkem768_encapsulate(kem_ct, ss, kk->pk, kem_seed) != 0) {
        nox_seterr("ML-KEM-768 encapsulation failed (malformed public key)");
        goto out;
    }
    mlkem_wrap_key(mk, kem_ct, kk->pk, ss);
    hybrid_wrap_key(wk, xk, mk, recip->fp);
    ncrypt_aead_lock(wrapped, mac, wk, nonce, ad, 46, file_key, 32);

    nox_be16(val, NOX_ALG_HYBRID);
    memcpy(val + 2, recip->fp, 32);
    memcpy(val + 34, eph_pk, 32);
    memcpy(val + 66, kem_ct, 1088);
    memcpy(val + 1154, nonce, 24);
    memcpy(val + 1178, mac, 16);
    memcpy(val + 1194, wrapped, 32);
    rc = nox_buf_pkt(recs, NOX_PKT_RECIPIENT, val, HYBRID_RVAL);
out:
    nox_wipe(eph_sk, sizeof eph_sk);
    nox_wipe(kem_seed, sizeof kem_seed);
    nox_wipe(ss, sizeof ss);
    nox_wipe(xk, sizeof xk);
    nox_wipe(mk, sizeof mk);
    nox_wipe(wk, sizeof wk);
    nox_wipe(nonce, sizeof nonce);
    nox_wipe(wrapped, sizeof wrapped);
    return rc;
}

/* Pick the recipient flavour that matches what the identity can do. */
static int
wrap_recipient(nox_buf *recs, const nox_ident *recip, const uint8_t file_key[32],
               const uint8_t ad[46])
{
    switch (nox_ident_recipient_alg(recip)) {
    case NOX_ALG_HYBRID:
        return wrap_hybrid(recs, recip, file_key, ad);
    case NOX_ALG_X25519:
        return wrap_x25519(recs, recip, file_key, ad);
    case NOX_ALG_MLKEM768:
        return wrap_mlkem(recs, recip, file_key, ad);
    default:
        return nox_seterr("recipient has no encryption key");
    }
}

static int
wrap_password(nox_buf *recs, const char *pass, size_t pass_len,
              const uint8_t file_key[32], const uint8_t ad[46])
{
    uint8_t salt[16], nonce[24], mac[16], pw_key[32], wrapped[32];
    uint8_t val[PASS_RVAL];
    int rc = -1;

    if (nox_random(salt, 16) < 0 || nox_random(nonce, 24) < 0)
        return -1;
    if (nox_argon2id(pw_key, pass, pass_len, NOX_ARGON2_T, NOX_ARGON2_M,
                     NOX_ARGON2_P, salt) < 0)
        goto out;
    ncrypt_aead_lock(wrapped, mac, pw_key, nonce, ad, 46, file_key, 32);
    nox_be16(val, NOX_ALG_ARGON2ID);
    nox_be32(val + 2, NOX_ARGON2_T);
    nox_be32(val + 6, NOX_ARGON2_M);
    nox_be32(val + 10, NOX_ARGON2_P);
    nox_be32(val + 14, 32);
    val[18] = 16;
    memcpy(val + 19, salt, 16);
    memcpy(val + 35, nonce, 24);
    memcpy(val + 59, mac, 16);
    memcpy(val + 75, wrapped, 32);
    rc = nox_buf_pkt(recs, NOX_PKT_RECIPIENT, val, PASS_RVAL);
out:
    nox_wipe(pw_key, sizeof pw_key);
    nox_wipe(salt, sizeof salt);
    nox_wipe(nonce, sizeof nonce);
    nox_wipe(wrapped, sizeof wrapped);
    return rc;
}

static void
chunk_ad(uint8_t ad[sizeof(DS_PAYLOAD) - 1 + 8 + 1], uint64_t idx, int last)
{
    memcpy(ad, DS_PAYLOAD, sizeof(DS_PAYLOAD) - 1);
    nox_be64(ad + sizeof(DS_PAYLOAD) - 1, idx);
    ad[sizeof(DS_PAYLOAD) - 1 + 8] = last ? 1 : 0;
}

static int
emit_chunk(nox_writer *w, ncrypt_aead_ctx *ctx, uint64_t idx, int last,
           const uint8_t *pt, size_t n)
{
    uint8_t ad[sizeof(DS_PAYLOAD) - 1 + 8 + 1];
    uint8_t mac[16];
    uint8_t *ct;
    uint8_t hdr[6];
    int rc;

    if (n > NOX_CHUNK)
        return nox_seterr("internal error: chunk too large");
    ct = malloc(n == 0 ? 1 : n);
    if (ct == NULL)
        return nox_seterr("out of memory");
    chunk_ad(ad, idx, last);
    ncrypt_aead_write(ctx, ct, mac, ad, sizeof ad, pt, n);
    nox_be16(hdr, NOX_PKT_CHUNK);
    nox_be32(hdr + 2, (uint32_t)(16 + n));
    rc = nox_writer_write(w, hdr, 6);
    if (rc == 0)
        rc = nox_writer_write(w, mac, 16);
    if (rc == 0 && n > 0)
        rc = nox_writer_write(w, ct, n);
    nox_wipe(ct, n == 0 ? 1 : n);
    free(ct);
    return rc;
}

int
nox_encrypt(FILE *in, FILE *out, int armor,
            nox_ident **recips, int nrecips,
            const char *pass, size_t pass_len)
{
    uint8_t file_key[32], payload_nonce[24], ad[46];
    nox_buf recs, hdr;
    nox_writer w;
    ncrypt_aead_ctx ctx;
    uint8_t *plain = NULL;
    uint64_t idx = 0;
    int i, rc = -1;

    if (pass != NULL && nrecips > 0)
        return nox_seterr("passphrase recipient must be the sole recipient");
    if (pass == NULL && nrecips < 1)
        return nox_seterr("no recipients");
    if (nrecips > NOX_MAX_RECIPIENTS)
        return nox_seterr("too many recipients (max %d)", NOX_MAX_RECIPIENTS);
    for (i = 0; i < nrecips; i++) {
        if (nox_ident_recipient_alg(recips[i]) < 0)
            return nox_seterr("recipient has no encryption key");
    }

    if (nox_random(file_key, 32) < 0 || nox_random(payload_nonce, 24) < 0)
        return -1;
    wrap_ad(ad, payload_nonce);

    if (nox_buf_init(&recs, 64 * 1024) < 0)
        goto wipe_key;
    if (pass != NULL) {
        if (wrap_password(&recs, pass, pass_len, file_key, ad) < 0) {
            nox_buf_free(&recs);
            goto wipe_key;
        }
    } else {
        for (i = 0; i < nrecips; i++) {
            if (wrap_recipient(&recs, recips[i], file_key, ad) < 0) {
                nox_buf_free(&recs);
                goto wipe_key;
            }
        }
    }
    if (recs.err) {
        nox_buf_free(&recs);
        goto wipe_key;
    }

    if (nox_buf_init(&hdr, 24 + recs.n + 16) < 0) {
        nox_buf_free(&recs);
        goto wipe_key;
    }
    nox_buf_put(&hdr, payload_nonce, 24);
    nox_buf_put(&hdr, recs.p, recs.n);
    nox_buf_free(&recs);
    if (hdr.err) {
        nox_buf_free(&hdr);
        goto wipe_key;
    }

    if (nox_writer_init(&w, out, armor, NOX_KIND_MSG) < 0) {
        nox_buf_free(&hdr);
        goto wipe_key;
    }
    {
        uint8_t mag[4] = { NOX_MAGIC0, NOX_MAGIC1, NOX_MAGIC2, NOX_MAGIC3 };
        uint8_t ph[6];
        if (nox_writer_write(&w, mag, 4) < 0) {
            nox_buf_free(&hdr);
            goto wipe_key;
        }
        nox_be16(ph, NOX_PKT_ENCHDR);
        nox_be32(ph + 2, (uint32_t)hdr.n);
        if (nox_writer_write(&w, ph, 6) < 0 ||
            nox_writer_write(&w, hdr.p, hdr.n) < 0) {
            nox_buf_free(&hdr);
            goto wipe_key;
        }
    }
    nox_buf_free(&hdr);

    ncrypt_aead_init_x(&ctx, file_key, payload_nonce);
    plain = malloc(NOX_CHUNK);
    if (plain == NULL) {
        nox_seterr("out of memory");
        goto wipe_ctx;
    }

    for (;;) {
        size_t n = 0;
        int last;

        while (n < NOX_CHUNK) {
            size_t r = fread(plain + n, 1, NOX_CHUNK - n, in);
            n += r;
            if (r == 0)
                break;
        }
        if (ferror(in)) {
            nox_seterr("read: %s", strerror(errno));
            goto wipe_ctx;
        }
        last = feof(in);
        if (n == 0) {
            if (emit_chunk(&w, &ctx, idx, 1, plain, 0) < 0)
                goto wipe_ctx;
            break;
        }
        if (n < NOX_CHUNK)
            last = 1;
        if (emit_chunk(&w, &ctx, idx, last, plain, n) < 0)
            goto wipe_ctx;
        idx++;
        if (last)
            break;
    }
    if (nox_writer_finish(&w) < 0)
        goto wipe_ctx;
    rc = 0;
wipe_ctx:
    nox_wipe(&ctx, sizeof ctx);
    if (plain != NULL) {
        nox_wipe(plain, NOX_CHUNK);
        free(plain);
    }
wipe_key:
    nox_wipe(file_key, sizeof file_key);
    nox_wipe(payload_nonce, sizeof payload_nonce);
    return rc;
}

static int
unwrap_hybrid(uint8_t file_key[32], const uint8_t *val, uint32_t vlen,
              nox_ident *id, const uint8_t ad[46])
{
    const nox_key *kx, *kk;
    uint8_t x_sk[32], k_sk[2400];
    size_t xlen, klen;
    uint8_t xk[32], ss[32], mk[32], wk[32];
    const uint8_t *fp, *eph_pk, *kem_ct, *nonce, *mac, *wrapped;
    int rc = -1;

    if (vlen != HYBRID_RVAL)
        return -1;
    fp = val + 2;
    eph_pk = val + 34;
    kem_ct = val + 66;
    nonce = val + 1154;
    mac = val + 1178;
    wrapped = val + 1194;
    if (nox_memeq(fp, id->fp, 32) != 0)
        return -1;
    kx = nox_ident_find(id, NOX_ALG_X25519);
    kk = nox_ident_find(id, NOX_ALG_MLKEM768);
    if (kx == NULL || kk == NULL || !kx->has_sk || !kk->has_sk)
        return nox_seterr("identity is missing encryption secrets");
    if (!(kx->usage & NOX_USAGE_ENCRYPT) || !(kk->usage & NOX_USAGE_ENCRYPT))
        return nox_seterr("encryption keys have the wrong usage");
    if (nox_key_expand(kx, x_sk, &xlen) < 0)
        return -1;
    if (nox_key_expand(kk, k_sk, &klen) < 0) {
        nox_wipe(x_sk, sizeof x_sk);
        return -1;
    }
    if (x25519_wrap_key(xk, x_sk, eph_pk, eph_pk, kx->pk) < 0)
        goto out;
    if (ncrypt_mlkem768_decapsulate(ss, kem_ct, k_sk) != 0) {
        nox_seterr("ML-KEM-768 decapsulation failed");
        goto out;
    }
    mlkem_wrap_key(mk, kem_ct, kk->pk, ss);
    hybrid_wrap_key(wk, xk, mk, id->fp);
    if (ncrypt_aead_unlock(file_key, mac, wk, nonce, ad, 46, wrapped, 32) != 0) {
        nox_seterr("hybrid unwrap failed to authenticate");
        goto out;
    }
    rc = 0;
out:
    nox_wipe(x_sk, sizeof x_sk);
    nox_wipe(k_sk, sizeof k_sk);
    nox_wipe(xk, sizeof xk);
    nox_wipe(ss, sizeof ss);
    nox_wipe(mk, sizeof mk);
    nox_wipe(wk, sizeof wk);
    return rc;
}

static int
unwrap_x25519(uint8_t file_key[32], const uint8_t *val, uint32_t vlen,
              nox_ident *id, const uint8_t ad[46])
{
    const nox_key *kx;
    uint8_t x_sk[32], xk[32];
    size_t xlen;
    const uint8_t *fp, *eph_pk, *nonce, *mac, *wrapped;
    int rc = -1;

    if (vlen != X25519_RVAL)
        return -1;
    fp = val + 2;
    eph_pk = val + 34;
    nonce = val + 66;
    mac = val + 90;
    wrapped = val + 106;
    if (nox_memeq(fp, id->fp, 32) != 0)
        return -1;
    kx = nox_ident_find(id, NOX_ALG_X25519);
    if (kx == NULL || !kx->has_sk)
        return nox_seterr("identity is missing its X25519 secret");
    if ((kx->usage & NOX_USAGE_ENCRYPT) == 0)
        return nox_seterr("encryption key has the wrong usage");
    if (nox_key_expand(kx, x_sk, &xlen) < 0)
        return -1;
    if (x25519_wrap_key(xk, x_sk, eph_pk, eph_pk, kx->pk) < 0)
        goto out;
    if (ncrypt_aead_unlock(file_key, mac, xk, nonce, ad, 46, wrapped, 32) != 0) {
        nox_seterr("X25519 unwrap failed to authenticate");
        goto out;
    }
    rc = 0;
out:
    nox_wipe(x_sk, sizeof x_sk);
    nox_wipe(xk, sizeof xk);
    return rc;
}

static int
unwrap_mlkem(uint8_t file_key[32], const uint8_t *val, uint32_t vlen,
             nox_ident *id, const uint8_t ad[46])
{
    const nox_key *kk;
    uint8_t k_sk[2400], ss[32], mk[32];
    size_t klen;
    const uint8_t *fp, *kem_ct, *nonce, *mac, *wrapped;
    int rc = -1;

    if (vlen != MLKEM_RVAL)
        return -1;
    fp = val + 2;
    kem_ct = val + 34;
    nonce = val + 1122;
    mac = val + 1146;
    wrapped = val + 1162;
    if (nox_memeq(fp, id->fp, 32) != 0)
        return -1;
    kk = nox_ident_find(id, NOX_ALG_MLKEM768);
    if (kk == NULL || !kk->has_sk)
        return nox_seterr("identity is missing its ML-KEM-768 secret");
    if ((kk->usage & NOX_USAGE_ENCRYPT) == 0)
        return nox_seterr("encryption key has the wrong usage");
    if (nox_key_expand(kk, k_sk, &klen) < 0)
        return -1;
    if (ncrypt_mlkem768_decapsulate(ss, kem_ct, k_sk) != 0) {
        nox_seterr("ML-KEM-768 decapsulation failed");
        goto out;
    }
    mlkem_wrap_key(mk, kem_ct, kk->pk, ss);
    if (ncrypt_aead_unlock(file_key, mac, mk, nonce, ad, 46, wrapped, 32) != 0) {
        nox_seterr("ML-KEM-768 unwrap failed to authenticate");
        goto out;
    }
    rc = 0;
out:
    nox_wipe(k_sk, sizeof k_sk);
    nox_wipe(ss, sizeof ss);
    nox_wipe(mk, sizeof mk);
    return rc;
}

/*
 * An identity only ever unwraps the recipient flavour that matches its
 * own keys.  A hybrid identity therefore cannot be tricked into
 * accepting a bare X25519 or ML-KEM-768 recipient.
 */
static int
unwrap_recipient(uint8_t file_key[32], uint16_t alg, const uint8_t *val,
                 uint32_t vlen, nox_ident *id, const uint8_t ad[46])
{
    if (nox_ident_recipient_alg(id) != (int)alg)
        return -1;
    switch (alg) {
    case NOX_ALG_HYBRID:
        return unwrap_hybrid(file_key, val, vlen, id, ad);
    case NOX_ALG_X25519:
        return unwrap_x25519(file_key, val, vlen, id, ad);
    case NOX_ALG_MLKEM768:
        return unwrap_mlkem(file_key, val, vlen, id, ad);
    default:
        return -1;
    }
}

static int
unwrap_password(uint8_t file_key[32], const uint8_t *val, uint32_t vlen,
                const char *pass, size_t pass_len, const uint8_t ad[46])
{
    uint32_t t, m, p, outlen;
    uint8_t salt_len;
    const uint8_t *salt, *nonce, *mac, *wrapped;
    uint8_t pw_key[32];
    int rc;

    if (vlen != PASS_RVAL)
        return -1;
    t = nox_rd32(val + 2);
    m = nox_rd32(val + 6);
    p = nox_rd32(val + 10);
    outlen = nox_rd32(val + 14);
    salt_len = val[18];
    if (outlen != 32 || salt_len != 16)
        return -1;
    salt = val + 19;
    nonce = val + 35;
    mac = val + 59;
    wrapped = val + 75;
    if (nox_argon2id(pw_key, pass, pass_len, t, m, p, salt) < 0)
        return -1;
    rc = ncrypt_aead_unlock(file_key, mac, pw_key, nonce, ad, 46, wrapped, 32);
    nox_wipe(pw_key, sizeof pw_key);
    return rc == 0 ? 0 : -1;
}

int
nox_decrypt(FILE *in, FILE *out,
            nox_ident **idents, int nidents,
            const char *pass, size_t pass_len)
{
    nox_reader r;
    uint8_t mag[4], ph[6];
    uint16_t ptype;
    uint32_t plen;
    uint8_t *hval = NULL;
    uint8_t payload_nonce[24], ad[46], file_key[32];
    nox_parser hp;
    int got_key = 0, saw_pass = 0;
    int nrec = 0, last = 0;
    ncrypt_aead_ctx ctx;
    uint8_t *ct = NULL, *pt = NULL;
    uint64_t idx = 0;
    int rc = -1;

    if (nox_reader_init(&r, in) < 0)
        return -1;
    if (read_exact(&r, mag, 4) < 0)
        return -1;
    if (nox_check_magic(mag, 4) < 0)
        return -1;
    if (read_exact(&r, ph, 6) < 0)
        return -1;
    ptype = nox_rd16(ph);
    plen = nox_rd32(ph + 2);
    if ((ptype & 0x7fff) != NOX_PKT_ENCHDR)
        return nox_seterr("expected an encrypted header");
    if (ptype & 0x8000)
        return nox_seterr("encrypted header must not set the critical bit");
    if (plen < 24 || plen > NOX_MAX_BLOB)
        return nox_seterr("encrypted header has an invalid length");
    hval = malloc(plen);
    if (hval == NULL)
        return nox_seterr("out of memory");
    if (read_exact(&r, hval, plen) < 0) {
        free(hval);
        return -1;
    }
    memcpy(payload_nonce, hval, 24);
    wrap_ad(ad, payload_nonce);

    nox_parser_init(&hp, hval + 24, plen - 24);
    while (nox_parser_left(&hp)) {
        uint16_t t, alg;
        int crit;
        const uint8_t *v;
        uint32_t vn;

        if (nox_pkt_next(&hp, &t, &crit, &v, &vn) < 0) {
            free(hval);
            return -1;
        }
        if (t != NOX_PKT_RECIPIENT) {
            if (crit) {
                free(hval);
                return nox_seterr("unknown critical packet in header");
            }
            continue;
        }
        if (vn < 2) {
            free(hval);
            return nox_seterr("truncated recipient");
        }
        nrec++;
        if (nrec > NOX_MAX_RECIPIENTS) {
            free(hval);
            return nox_seterr("too many recipients");
        }
        alg = nox_rd16(v);
        if (alg == NOX_ALG_ARGON2ID)
            saw_pass = 1;
        else if (crit) {
            free(hval);
            return nox_seterr("unknown critical recipient");
        }
    }
    if (nrec < 1) {
        free(hval);
        return nox_seterr("ciphertext has no recipients");
    }
    if (saw_pass && nrec != 1) {
        free(hval);
        return nox_seterr("passphrase recipient must be the sole recipient");
    }

    nox_parser_init(&hp, hval + 24, plen - 24);
    while (!got_key && nox_parser_left(&hp)) {
        uint16_t t, alg;
        int crit;
        const uint8_t *v;
        uint32_t vn;

        if (nox_pkt_next(&hp, &t, &crit, &v, &vn) < 0)
            break;
        if (t != NOX_PKT_RECIPIENT || vn < 2)
            continue;
        alg = nox_rd16(v);
        if (alg == NOX_ALG_HYBRID || alg == NOX_ALG_X25519 ||
            alg == NOX_ALG_MLKEM768) {
            int i;
            for (i = 0; i < nidents; i++) {
                if (unwrap_recipient(file_key, alg, v, vn, idents[i], ad) == 0) {
                    got_key = 1;
                    break;
                }
            }
        } else if (alg == NOX_ALG_ARGON2ID) {
            if (pass != NULL &&
                unwrap_password(file_key, v, vn, pass, pass_len, ad) == 0)
                got_key = 1;
        }
    }
    free(hval);
    hval = NULL;
    if (!got_key) {
        if (nox_err[0] == 0)
            return nox_seterr("no matching recipient or wrong passphrase");
        return -1;
    }

    ncrypt_aead_init_x(&ctx, file_key, payload_nonce);
    nox_wipe(file_key, sizeof file_key);
    ct = malloc(NOX_CHUNK);
    pt = malloc(NOX_CHUNK);
    if (ct == NULL || pt == NULL) {
        nox_seterr("out of memory");
        goto out;
    }

    while (!last) {
        uint8_t ch[6];
        uint16_t t;
        uint32_t vn;
        uint8_t mac[16];
        uint8_t cad[sizeof(DS_PAYLOAD) - 1 + 8 + 1];
        size_t clen;
        int crit_bit;

        if (read_exact(&r, ch, 6) < 0)
            goto out;
        t = nox_rd16(ch);
        vn = nox_rd32(ch + 2);
        crit_bit = (t & 0x8000) != 0;
        t = (uint16_t)(t & 0x7fff);
        if (t == 0) {
            nox_seterr("packet type 0 is reserved");
            goto out;
        }
        if (t != NOX_PKT_CHUNK) {
            if (crit_bit) {
                nox_seterr("unknown critical packet in ciphertext");
                goto out;
            }
            if (vn > NOX_MAX_BLOB) {
                nox_seterr("packet too large");
                goto out;
            }
            {
                uint8_t *skip = malloc(vn ? vn : 1);
                if (skip == NULL) {
                    nox_seterr("out of memory");
                    goto out;
                }
                if (vn > 0 && read_exact(&r, skip, vn) < 0) {
                    free(skip);
                    goto out;
                }
                free(skip);
            }
            continue;
        }
        if (vn < 16 || vn > 16 + NOX_CHUNK) {
            nox_seterr("invalid chunk length");
            goto out;
        }
        if (read_exact(&r, mac, 16) < 0)
            goto out;
        clen = vn - 16;
        if (clen > 0 && read_exact(&r, ct, clen) < 0)
            goto out;

        last = 0;
        chunk_ad(cad, idx, 0);
        if (ncrypt_aead_read(&ctx, pt, mac, cad, sizeof cad, ct, clen) != 0) {
            chunk_ad(cad, idx, 1);
            if (ncrypt_aead_read(&ctx, pt, mac, cad, sizeof cad, ct, clen) != 0) {
                nox_seterr("corrupted ciphertext");
                goto out;
            }
            last = 1;
        }
        if (clen > 0 && nox_write_all(out, pt, clen) < 0)
            goto out;
        if (!last && clen != NOX_CHUNK) {
            nox_seterr("non-final chunk has the wrong size");
            goto out;
        }
        idx++;
    }
    if (!nox_reader_eof(&r)) {
        /* leftover bytes after the last chunk */
        uint8_t extra;
        int k = nox_reader_read(&r, &extra, 1);
        if (k < 0)
            goto out;
        if (k > 0) {
            nox_seterr("trailing bytes after ciphertext");
            goto out;
        }
    }
    rc = 0;
out:
    nox_wipe(&ctx, sizeof ctx);
    if (ct != NULL) {
        nox_wipe(ct, NOX_CHUNK);
        free(ct);
    }
    if (pt != NULL) {
        nox_wipe(pt, NOX_CHUNK);
        free(pt);
    }
    return rc;
}
