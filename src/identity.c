#include "identity.h"
#include "packet.h"
#include "armor.h"

#include <stdlib.h>
#include <string.h>

void
nox_ident_init(nox_ident *id)
{
    memset(id, 0, sizeof *id);
}

void
nox_ident_wipe(nox_ident *id)
{
    int i;

    if (id->raw != NULL) {
        nox_wipe(id->raw, id->raw_len);
        free(id->raw);
    }
    for (i = 0; i < NOX_MAX_KEYS; i++) {
        nox_wipe(id->keys[i].sk, sizeof id->keys[i].sk);
        nox_wipe(id->keys[i].pk, sizeof id->keys[i].pk);
    }
    nox_wipe(id, sizeof *id);
}

nox_key *
nox_ident_find(const nox_ident *id, uint16_t alg)
{
    int i;

    for (i = 0; i < id->nkeys; i++) {
        if (id->keys[i].alg == alg)
            return (nox_key *)&id->keys[i];
    }
    return NULL;
}

void
nox_algset_full(nox_algset *set)
{
    set->ed25519 = 1;
    set->mldsa44 = 1;
    set->x25519 = 1;
    set->mlkem768 = 1;
}

void
nox_algset_classic(nox_algset *set)
{
    memset(set, 0, sizeof *set);
    set->ed25519 = 1;
    set->x25519 = 1;
}

void
nox_algset_pq(nox_algset *set)
{
    memset(set, 0, sizeof *set);
    set->mldsa44 = 1;
    set->mlkem768 = 1;
}

int
nox_algset_parse(nox_algset *set, const char *name)
{
    if (name == NULL)
        return -1;
    if (strcmp(name, "hybrid") == 0 || strcmp(name, "all") == 0) {
        nox_algset_full(set);
        return 0;
    }
    if (strcmp(name, "ecc") == 0 || strcmp(name, "classic") == 0) {
        nox_algset_classic(set);
        return 0;
    }
    if (strcmp(name, "pqc") == 0 || strcmp(name, "pq") == 0) {
        nox_algset_pq(set);
        return 0;
    }
    return nox_seterr("unknown algorithm profile '%s' "
                      "(want hybrid, ecc, or pqc)", name);
}

int
nox_algset_add(nox_algset *set, uint16_t alg)
{
    switch (alg) {
    case NOX_ALG_ED25519:  set->ed25519 = 1;  return 0;
    case NOX_ALG_MLDSA44:  set->mldsa44 = 1;  return 0;
    case NOX_ALG_X25519:   set->x25519 = 1;   return 0;
    case NOX_ALG_MLKEM768: set->mlkem768 = 1; return 0;
    default:
        return nox_seterr("%s cannot go into an identity", nox_alg_name(alg));
    }
}

int
nox_algset_has(const nox_algset *set, uint16_t alg)
{
    switch (alg) {
    case NOX_ALG_ED25519:  return set->ed25519;
    case NOX_ALG_MLDSA44:  return set->mldsa44;
    case NOX_ALG_X25519:   return set->x25519;
    case NOX_ALG_MLKEM768: return set->mlkem768;
    default:               return 0;
    }
}

int
nox_algset_valid(const nox_algset *set)
{
    int nsig = set->ed25519 + set->mldsa44;
    int nenc = set->x25519 + set->mlkem768;

    return nsig > 0 && nenc > 0;
}

const char *
nox_algset_name(const nox_algset *set)
{
    if (set->ed25519 && set->mldsa44 && set->x25519 && set->mlkem768)
        return "hybrid";
    if (set->ed25519 && set->x25519 && !set->mldsa44 && !set->mlkem768)
        return "ecc";
    if (set->mldsa44 && set->mlkem768 && !set->ed25519 && !set->x25519)
        return "pqc";
    if (!nox_algset_valid(set))
        return "partial";  /* signing or encryption missing */
    return "mixed";
}

void
nox_ident_algset(const nox_ident *id, nox_algset *set)
{
    int i;

    memset(set, 0, sizeof *set);
    for (i = 0; i < id->nkeys; i++)
        nox_algset_add(set, id->keys[i].alg);
}

const char *
nox_ident_profile(const nox_ident *id)
{
    nox_algset set;

    nox_ident_algset(id, &set);
    return nox_algset_name(&set);
}

int
nox_ident_recipient_alg(const nox_ident *id)
{
    int i, have_x = 0, have_k = 0;

    for (i = 0; i < id->nkeys; i++) {
        if ((id->keys[i].usage & NOX_USAGE_ENCRYPT) == 0)
            continue;
        if (id->keys[i].alg == NOX_ALG_X25519)
            have_x = 1;
        else if (id->keys[i].alg == NOX_ALG_MLKEM768)
            have_k = 1;
    }
    if (have_x && have_k)
        return NOX_ALG_HYBRID;
    if (have_x)
        return NOX_ALG_X25519;
    if (have_k)
        return NOX_ALG_MLKEM768;
    return -1;
}

int
nox_ident_has_hybrid_enc(const nox_ident *id)
{
    return nox_ident_recipient_alg(id) == NOX_ALG_HYBRID;
}

void
nox_ident_alg_list(const nox_ident *id, char *buf, size_t n)
{
    size_t used = 0;
    int i;

    if (n == 0)
        return;
    buf[0] = 0;
    for (i = 0; i < id->nkeys; i++) {
        int k = snprintf(buf + used, n - used, "%s%s", i > 0 ? " + " : "",
                         nox_alg_name(id->keys[i].alg));
        if (k < 0 || (size_t)k >= n - used)
            break;
        used += (size_t)k;
    }
}

static int
put_pubkey(nox_buf *b, uint16_t alg, uint8_t usage,
           const uint8_t *pk, int pkl)
{
    uint8_t val[3 + 1312];

    nox_be16(val, alg);
    val[2] = usage;
    memcpy(val + 3, pk, (size_t)pkl);
    return nox_buf_pkt(b, NOX_PKT_PUBKEY, val, (uint32_t)(3 + pkl));
}

static int
put_sig(nox_buf *b, uint16_t alg, const uint8_t *sig, int sl)
{
    uint8_t val[2 + 2420];

    nox_be16(val, alg);
    memcpy(val + 2, sig, (size_t)sl);
    return nox_buf_pkt(b, NOX_PKT_SIG, val, (uint32_t)(2 + sl));
}

static void
fingerprint(uint8_t fp[NOX_FP_LEN], const uint8_t *keys, size_t n)
{
    ncrypt_blake2b_ctx ctx;

    ncrypt_blake2b_init(&ctx, NOX_FP_LEN);
    ncrypt_blake2b_update(&ctx, (const uint8_t *)DS_FINGERPRINT,
                          sizeof(DS_FINGERPRINT) - 1);
    ncrypt_blake2b_update(&ctx, keys, n);
    ncrypt_blake2b_final(&ctx, fp);
}

/*
 * The four algorithms an identity can hold, in the order they appear
 * in a public key file.  Signing keys first: the order is part of the
 * fingerprint, so it has to stay fixed.
 */
struct keygen {
    uint16_t alg;
    uint8_t usage;
    uint8_t seed_len;
    uint16_t pk_len;
};

static const struct keygen keygen_order[] = {
    { NOX_ALG_ED25519,  NOX_USAGE_SIGN | NOX_USAGE_AUTH, 32, 32 },
    { NOX_ALG_MLDSA44,  NOX_USAGE_SIGN,                  32, 1312 },
    { NOX_ALG_X25519,   NOX_USAGE_ENCRYPT,               32, 32 },
    { NOX_ALG_MLKEM768, NOX_USAGE_ENCRYPT,               64, 1184 },
};

#define NOX_KEYGEN_N ((int)(sizeof keygen_order / sizeof keygen_order[0]))

/* Derive a public key from a seed; libncrypt wipes the seed we hand it. */
static int
public_from_seed(uint16_t alg, const uint8_t *seed, size_t seed_len,
                 uint8_t *pk)
{
    uint8_t tmp[64], sk[2560];

    memcpy(tmp, seed, seed_len);
    switch (alg) {
    case NOX_ALG_ED25519:
        ncrypt_ed25519_key_pair(sk, pk, tmp);
        break;
    case NOX_ALG_MLDSA44:
        ncrypt_mldsa44_key_pair(sk, pk, tmp);
        break;
    case NOX_ALG_X25519:
        ncrypt_x25519_public_key(pk, tmp);
        break;
    case NOX_ALG_MLKEM768:
        ncrypt_mlkem768_key_pair(sk, pk, tmp);
        break;
    default:
        nox_wipe(tmp, sizeof tmp);
        return nox_seterr("cannot generate %s", nox_alg_name(alg));
    }
    nox_wipe(tmp, sizeof tmp);
    nox_wipe(sk, sizeof sk);
    return 0;
}

int
nox_key_expand(const nox_key *k, uint8_t *sk, size_t *sk_len)
{
    uint8_t seed[64];
    size_t slen;
    int want;

    if (!k->has_sk)
        return nox_seterr("no secret key");
    want = nox_sk_exp_len(k->alg);
    if (want < 0)
        return nox_seterr("unknown algorithm");

    if (k->encoding == NOX_ENC_EXP) {
        if (k->sk_len != (size_t)want)
            return nox_seterr("expanded secret has the wrong length");
        switch (k->alg) {
        case NOX_ALG_X25519: {
            uint8_t pk[32];
            ncrypt_x25519_public_key(pk, k->sk);
            if (nox_memeq(pk, k->pk, 32) != 0)
                return nox_seterr("X25519 secret does not match public key");
            break;
        }
        case NOX_ALG_ED25519: {
            uint8_t seed[32], pk[32], tmp[64];
            memcpy(seed, k->sk, 32);
            ncrypt_ed25519_key_pair(tmp, pk, seed);
            if (nox_memeq(pk, k->pk, 32) != 0 ||
                nox_memeq(tmp, k->sk, 64) != 0) {
                nox_wipe(tmp, sizeof tmp);
                return nox_seterr("Ed25519 secret does not match public key");
            }
            nox_wipe(tmp, sizeof tmp);
            break;
        }
        case NOX_ALG_MLKEM768: {
            uint8_t seed[32], ct[1088], ss1[32], ss2[32];
            int st;
            if (nox_random(seed, 32) < 0)
                return -1;
            st = ncrypt_mlkem768_encapsulate(ct, ss1, k->pk, seed);
            if (st != 0)
                return nox_seterr("ML-KEM-768 public key is malformed");
            if (ncrypt_mlkem768_decapsulate(ss2, ct, k->sk) != 0) {
                nox_wipe(ss1, 32);
                nox_wipe(ss2, 32);
                return nox_seterr("ML-KEM-768 secret key is corrupted");
            }
            st = ncrypt_verify32(ss1, ss2);
            nox_wipe(ss1, 32);
            nox_wipe(ss2, 32);
            nox_wipe(ct, sizeof ct);
            if (st != 0)
                return nox_seterr("ML-KEM-768 secret does not match public key");
            break;
        }
        case NOX_ALG_MLDSA44: {
            uint8_t sig[2420], rnd[32];
            static const uint8_t chk[] = "noxcrypt/v1/sk-check";
            if (nox_random(rnd, sizeof rnd) < 0)
                return -1;
            if (ncrypt_mldsa44_sign(sig, k->sk, rnd, NULL, 0,
                                    chk, sizeof chk - 1) != 0 ||
                ncrypt_mldsa44_check(sig, k->pk, NULL, 0,
                                     chk, sizeof chk - 1) != 0) {
                nox_wipe(rnd, sizeof rnd);
                nox_wipe(sig, sizeof sig);
                return nox_seterr("ML-DSA-44 secret does not match public key");
            }
            nox_wipe(rnd, sizeof rnd);
            nox_wipe(sig, sizeof sig);
            break;
        }
        default:
            return nox_seterr("unknown algorithm");
        }
        memcpy(sk, k->sk, (size_t)want);
        *sk_len = (size_t)want;
        return 0;
    }

    slen = (size_t)nox_sk_seed_len(k->alg);
    if (k->sk_len != slen)
        return nox_seterr("secret seed has the wrong length");
    memcpy(seed, k->sk, slen);

    switch (k->alg) {
    case NOX_ALG_X25519: {
        uint8_t pk[32];
        ncrypt_x25519_public_key(pk, seed);
        if (nox_memeq(pk, k->pk, 32) != 0) {
            nox_wipe(seed, sizeof seed);
            return nox_seterr("X25519 secret does not match public key");
        }
        memcpy(sk, seed, 32);
        *sk_len = 32;
        nox_wipe(seed, sizeof seed);
        return 0;
    }
    case NOX_ALG_ED25519: {
        uint8_t pk[32];
        ncrypt_ed25519_key_pair(sk, pk, seed); /* wipes seed[0..32] */
        if (nox_memeq(pk, k->pk, 32) != 0) {
            nox_wipe(sk, 64);
            return nox_seterr("Ed25519 secret does not match public key");
        }
        *sk_len = 64;
        return 0;
    }
    case NOX_ALG_MLKEM768: {
        uint8_t pk[1184];
        ncrypt_mlkem768_key_pair(sk, pk, seed);
        if (nox_memeq(pk, k->pk, 1184) != 0) {
            nox_wipe(sk, 2400);
            return nox_seterr("ML-KEM-768 secret does not match public key");
        }
        *sk_len = 2400;
        return 0;
    }
    case NOX_ALG_MLDSA44: {
        uint8_t pk[1312];
        ncrypt_mldsa44_key_pair(sk, pk, seed);
        if (nox_memeq(pk, k->pk, 1312) != 0) {
            nox_wipe(sk, 2560);
            return nox_seterr("ML-DSA-44 secret does not match public key");
        }
        *sk_len = 2560;
        return 0;
    }
    default:
        nox_wipe(seed, sizeof seed);
        return nox_seterr("unknown algorithm");
    }
}

static int
check_sigs(const nox_ident *id, const uint8_t *body, size_t body_len,
           const uint8_t *sigpkts, size_t sigpkts_len)
{
    uint8_t *msg;
    size_t msg_len = (sizeof(DS_IDENTITY) - 1) + body_len;
    nox_parser p;
    int i, left, rc = -1;

    left = 0;
    for (i = 0; i < id->nkeys; i++) {
        if (id->keys[i].usage & NOX_USAGE_SIGN)
            left++;
    }
    if (left == 0)
        return nox_seterr("identity has no signing key");

    msg = malloc(msg_len);
    if (msg == NULL)
        return nox_seterr("out of memory");
    memcpy(msg, DS_IDENTITY, sizeof(DS_IDENTITY) - 1);
    memcpy(msg + sizeof(DS_IDENTITY) - 1, body, body_len);

    nox_parser_init(&p, sigpkts, sigpkts_len);
    for (i = 0; i < id->nkeys; i++) {
        const nox_key *k = &id->keys[i];
        uint16_t type, alg;
        int crit;
        const uint8_t *val;
        uint32_t vlen;
        int sl;

        if ((k->usage & NOX_USAGE_SIGN) == 0)
            continue;
        if (nox_pkt_next(&p, &type, &crit, &val, &vlen) < 0)
            goto out;
        if (type != NOX_PKT_SIG || vlen < 2)
            goto bad;
        alg = nox_rd16(val);
        sl = nox_sig_len(alg);
        if (alg != k->alg || sl < 0 || vlen != (uint32_t)(2 + sl))
            goto bad;
        if (alg == NOX_ALG_ED25519) {
            if (ncrypt_ed25519_check(val + 2, k->pk, msg, msg_len) != 0)
                goto bad;
        } else if (alg == NOX_ALG_MLDSA44) {
            if (ncrypt_mldsa44_check(val + 2, k->pk, NULL, 0,
                                     msg, msg_len) != 0)
                goto bad;
        } else {
            goto bad;
        }
        left--;
    }
    if (left != 0 || nox_parser_left(&p))
        goto bad;
    rc = 0;
    goto out;
bad:
    nox_seterr("identity self-signature is invalid");
out:
    nox_wipe(msg, msg_len);
    free(msg);
    return rc;
}

/*
 * Comments travel in the public key and are shown by `nox list`:
 * bounded and well-formed, or refused.
 */
int
nox_comment_ok(const char *comment)
{
    size_t clen;

    if (comment == NULL)
        comment = "";
    clen = strlen(comment);
    if (clen > NOX_MAX_COMMENT)
        return nox_seterr("comment longer than %d bytes", NOX_MAX_COMMENT);
    if (!nox_utf8_ok((const uint8_t *)comment, clen))
        return nox_seterr("comment is not valid UTF-8 (or contains NUL/CR/LF)");
    return 0;
}

int
nox_ident_generate(nox_ident *id, const nox_algset *set, const char *comment,
                   uint64_t created)
{
    uint8_t seed[NOX_KEYGEN_N][64];
    uint8_t pk[NOX_KEYGEN_N][1312];
    const struct keygen *desc[NOX_KEYGEN_N];
    uint16_t algs[NOX_KEYGEN_N];
    uint8_t sk[2560], sig[2420];
    nox_buf body = { 0 }, full = { 0 };
    size_t clen, keys_off, keys_len, msg_len, sk_len;
    uint8_t *msg = NULL;
    int i, nkeys = 0, rc = -1;

    nox_ident_init(id);
    if (!nox_algset_valid(set))
        return nox_seterr("an identity needs one signing and one "
                          "encryption algorithm");
    if (comment == NULL)
        comment = "";
    clen = strlen(comment);
    if (nox_comment_ok(comment) < 0)
        return -1;

    if (nox_buf_init(&body, NOX_MAX_IDENT) < 0)
        goto out;
    nox_buf_u64(&body, created);
    nox_buf_u16(&body, (uint16_t)clen);
    nox_buf_put(&body, comment, clen);
    keys_off = body.n;

    for (i = 0; i < NOX_KEYGEN_N; i++) {
        const struct keygen *g = &keygen_order[i];

        if (!nox_algset_has(set, g->alg))
            continue;
        if (nox_random(seed[nkeys], g->seed_len) < 0)
            goto out;
        if (public_from_seed(g->alg, seed[nkeys], g->seed_len, pk[nkeys]) < 0)
            goto out;
        put_pubkey(&body, g->alg, g->usage, pk[nkeys], g->pk_len);
        desc[nkeys] = g;
        algs[nkeys] = g->alg;
        nkeys++;
    }
    if (body.err || nkeys == 0) {
        if (!body.err)
            nox_seterr("no algorithms selected");
        goto out;
    }
    keys_len = body.n - keys_off;

    msg_len = (sizeof(DS_IDENTITY) - 1) + body.n;
    msg = malloc(msg_len);
    if (msg == NULL) {
        nox_seterr("out of memory");
        goto out;
    }
    memcpy(msg, DS_IDENTITY, sizeof(DS_IDENTITY) - 1);
    memcpy(msg + sizeof(DS_IDENTITY) - 1, body.p, body.n);

    if (nox_buf_init(&full, NOX_MAX_IDENT) < 0)
        goto out;
    nox_buf_put(&full, body.p, body.n);

    id->nkeys = nkeys;
    for (i = 0; i < nkeys; i++) {
        const struct keygen *g = desc[i];
        nox_key *k = &id->keys[i];

        k->alg = algs[i];
        k->usage = g->usage;
        k->encoding = NOX_ENC_SEED;
        memcpy(k->pk, pk[i], g->pk_len);
        k->pk_len = g->pk_len;
        memcpy(k->sk, seed[i], g->seed_len);
        k->sk_len = g->seed_len;
        k->has_sk = 1;
    }

    for (i = 0; i < nkeys; i++) {
        if ((id->keys[i].usage & NOX_USAGE_SIGN) == 0)
            continue;
        if (nox_key_expand(&id->keys[i], sk, &sk_len) < 0)
            goto out;
        if (algs[i] == NOX_ALG_ED25519) {
            ncrypt_ed25519_sign(sig, sk, msg, msg_len);
        } else {
            uint8_t rnd[32];

            if (nox_random(rnd, sizeof rnd) < 0)
                goto out;
            if (ncrypt_mldsa44_sign(sig, sk, rnd, NULL, 0,
                                    msg, msg_len) != 0) {
                nox_wipe(rnd, sizeof rnd);
                nox_seterr("ML-DSA-44 signing failed");
                goto out;
            }
            nox_wipe(rnd, sizeof rnd);
        }
        nox_wipe(sk, sizeof sk);
        put_sig(&full, algs[i], sig, nox_sig_len(algs[i]));
        nox_wipe(sig, sizeof sig);
    }

    if (full.err || full.n > NOX_MAX_IDENT) {
        if (!full.err)
            nox_seterr("identity exceeds 65536 bytes");
        goto out;
    }

    id->created = created;
    memcpy(id->comment, comment, clen);
    id->comment[clen] = 0;
    fingerprint(id->fp, full.p + keys_off, keys_len);
    id->raw = full.p;
    id->raw_len = full.n;
    id->body_len = keys_off + keys_len;
    full.p = NULL;
    rc = 0;
out:
    for (i = 0; i < NOX_KEYGEN_N; i++) {
        nox_wipe(seed[i], sizeof seed[i]);
        nox_wipe(pk[i], sizeof pk[i]);
    }
    nox_wipe(sk, sizeof sk);
    nox_wipe(sig, sizeof sig);
    if (msg != NULL) {
        nox_wipe(msg, msg_len);
        free(msg);
    }
    nox_buf_free(&body);
    nox_buf_free(&full);
    if (rc != 0)
        nox_ident_wipe(id);
    return rc;
}

int
nox_ident_parse_value(nox_ident *id, const uint8_t *val, size_t vlen)
{
    nox_parser inner;
    uint16_t clen;
    size_t off;
    int state = 0; /* 0 = need PK, 1 = PKs, 2 = unknown, 3 = SIGs */
    int nsign = 0;
    const uint8_t *keys_start = NULL;
    size_t keys_len = 0;
    size_t body_len = 0;
    const uint8_t *sig_start = NULL;

    nox_ident_init(id);
    if (vlen > NOX_MAX_IDENT)
        return nox_seterr("identity larger than 65536 bytes");
    if (vlen < 10)
        return nox_seterr("identity is truncated");

    id->created = nox_rd64(val);
    clen = nox_rd16(val + 8);
    if (clen > NOX_MAX_COMMENT)
        return nox_seterr("comment longer than %d bytes", NOX_MAX_COMMENT);
    if ((size_t)10 + clen > vlen)
        return nox_seterr("comment overruns identity");
    if (!nox_utf8_ok(val + 10, clen))
        return nox_seterr("comment is not valid UTF-8 (or contains NUL/CR/LF)");
    memcpy(id->comment, val + 10, clen);
    id->comment[clen] = 0;

    off = 10 + (size_t)clen;
    nox_parser_init(&inner, val + off, vlen - off);

    while (nox_parser_left(&inner)) {
        const uint8_t *pkt = inner.buf + inner.off;
        size_t pkt_off = inner.off;
        uint16_t t;
        int c;
        const uint8_t *v;
        uint32_t vn;

        if (nox_pkt_next(&inner, &t, &c, &v, &vn) < 0) {
            nox_ident_wipe(id);
            return -1;
        }
        if (t == NOX_PKT_PUBKEY) {
            uint16_t alg;
            uint8_t usage;
            int pkl;
            nox_key *k;

            if (state > 1)
                goto bad;
            state = 1;
            if (vn < 3)
                goto bad;
            alg = nox_rd16(v);
            usage = v[2];
            pkl = nox_pk_len(alg);
            if (pkl < 0) {
                nox_ident_wipe(id);
                return nox_seterr("unknown public key algorithm");
            }
            if (!nox_usage_ok(alg, usage) || vn != (uint32_t)(3 + pkl))
                goto bad;
            if (id->nkeys >= NOX_MAX_KEYS) {
                nox_ident_wipe(id);
                return nox_seterr("too many keys in identity");
            }
            k = &id->keys[id->nkeys++];
            k->alg = alg;
            k->usage = usage;
            memcpy(k->pk, v + 3, (size_t)pkl);
            k->pk_len = (size_t)pkl;
            if (usage & NOX_USAGE_SIGN)
                nsign++;
            if (keys_start == NULL)
                keys_start = pkt;
            keys_len = (size_t)((inner.buf + inner.off) - keys_start);
        } else if (t == NOX_PKT_SIG) {
            if (state < 1)
                goto bad;
            if (state < 3) {
                body_len = off + pkt_off;
                sig_start = pkt;
                state = 3;
            }
            nsign--; /* one signature consumed; nsign was the expected count */
            if (nsign == 0)
                break;
        } else {
            if (c) {
                nox_ident_wipe(id);
                return nox_seterr("unknown critical packet in identity");
            }
            if (state == 0 || state == 3)
                goto bad;
            state = 2;
        }
    }
    if (state != 3 || nsign != 0)
        goto bad;

    {
        size_t consumed = off + inner.off;
        id->raw = malloc(consumed);
        if (id->raw == NULL) {
            nox_ident_wipe(id);
            return nox_seterr("out of memory");
        }
        memcpy(id->raw, val, consumed);
        id->raw_len = consumed;
        id->body_len = body_len;
        fingerprint(id->fp, keys_start, keys_len);

        if (check_sigs(id, val, body_len, sig_start,
                       consumed - body_len) < 0) {
            nox_ident_wipe(id);
            return -1;
        }
    }
    return 0;
bad:
    nox_ident_wipe(id);
    return nox_seterr("malformed identity");
}

int
nox_ident_parse(nox_ident *id, const uint8_t *buf, size_t n)
{
    nox_parser p;
    uint16_t type;
    int crit;
    const uint8_t *val;
    uint32_t vlen;

    nox_parser_init(&p, buf, n);
    if (nox_skip_magic(&p) < 0)
        return -1;
    if (nox_pkt_next(&p, &type, &crit, &val, &vlen) < 0)
        return -1;
    if (type != NOX_PKT_IDENTITY)
        return nox_seterr("expected an identity packet");
    if (nox_parser_left(&p))
        return nox_seterr("trailing bytes after identity");
    if (nox_ident_parse_value(id, val, vlen) < 0)
        return -1;
    if (id->raw_len != vlen) {
        nox_ident_wipe(id);
        return nox_seterr("trailing bytes inside identity");
    }
    return 0;
}

int
nox_ident_load_pub(nox_ident *id, const uint8_t *buf, size_t n)
{
    uint8_t *raw = NULL;
    size_t rn = 0;
    int rc;

    if (nox_unwrap_blob(&raw, &rn, buf, n) < 0)
        return -1;
    rc = nox_ident_parse(id, raw, rn);
    free(raw);
    return rc;
}

int
nox_ident_public_blob(const nox_ident *id, uint8_t **out, size_t *n)
{
    nox_buf b;

    if (nox_buf_init(&b, 16 + id->raw_len) < 0)
        return -1;
    nox_buf_u8(&b, NOX_MAGIC0);
    nox_buf_u8(&b, NOX_MAGIC1);
    nox_buf_u8(&b, NOX_MAGIC2);
    nox_buf_u8(&b, NOX_MAGIC3);
    nox_buf_pkt(&b, NOX_PKT_IDENTITY, id->raw, (uint32_t)id->raw_len);
    if (b.err) {
        nox_buf_free(&b);
        return -1;
    }
    *out = b.p;
    *n = b.n;
    b.p = NULL;
    nox_buf_free(&b);
    return 0;
}
