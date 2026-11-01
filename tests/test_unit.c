#include "armor.h"
#include "cipher.h"
#include "identity.h"
#include "packet.h"
#include "sign.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;

static void
ok(int cond, const char *what)
{
    if (!cond) {
        fprintf(stderr, "FAIL %s: %s\n", what, nox_err[0] ? nox_err : "");
        fails++;
    }
}

static void
check_crypto(const char *label, nox_ident *id, nox_ident *pub, nox_algset *set,
             int recip_alg)
{
    FILE *in, *ct, *pt;
    nox_ident *rp[1];
    uint8_t hash[32], *sig = NULL;
    size_t sig_n = 0;
    char buf[64];
    uint16_t alg;

    /* sign and verify */
    in = tmpfile();
    fputs("test message\n", in);
    rewind(in);
    ok(nox_hash_file(in, hash) == 0, "hash");
    fclose(in);
    ok(nox_sign_detached(&sig, &sig_n, id, hash) == 0, "sign");
    ok(nox_verify_detached(sig, sig_n, pub, hash) == 0, "verify");
    hash[0] ^= 1;
    ok(nox_verify_detached(sig, sig_n, pub, hash) < 0, "verify rejects a "
       "changed message");
    free(sig);

    /* encrypt and decrypt */
    in = tmpfile();
    ct = tmpfile();
    pt = tmpfile();
    fputs("secret payload", in);
    rewind(in);
    rp[0] = id;
    ok(nox_encrypt(in, ct, 0, rp, 1, NULL, 0) == 0, "encrypt");
    rewind(ct);
    ok(nox_decrypt(ct, pt, rp, 1, NULL, 0) == 0, "decrypt");
    rewind(pt);
    ok(fgets(buf, sizeof buf, pt) != NULL && strcmp(buf, "secret payload") == 0,
       "plaintext");
    fclose(in);
    fclose(ct);
    fclose(pt);

    /* the recipient flavor on the wire has to match the profile */
    in = tmpfile();
    ct = tmpfile();
    fputs("x", in);
    rewind(in);
    ok(nox_encrypt(in, ct, 0, rp, 1, NULL, 0) == 0, "encrypt again");
    rewind(ct);
    {
        uint8_t head[46];
        ok(fread(head, 1, sizeof head, ct) == sizeof head, "read header");
        ok(nox_rd16(head + 34) == NOX_PKT_RECIPIENT, "recipient packet");
        alg = nox_rd16(head + 40);
        ok(alg == (uint16_t)recip_alg, label);
    }
    fclose(in);
    fclose(ct);
    (void)set;
}

static void
check_profile(const char *label, const nox_algset *set, int nkeys,
              int recip_alg, const char *profile, uint64_t created)
{
    nox_ident id, pub;
    uint8_t *blob = NULL;
    size_t n = 0;

    nox_ident_init(&id);
    ok(nox_ident_generate(&id, set, label, created) == 0, "generate");
    ok(id.nkeys == nkeys, "key count");
    ok(nox_ident_recipient_alg(&id) == recip_alg, "recipient algorithm");
    ok(strcmp(nox_ident_profile(&id), profile) == 0, "profile name");
    ok(id.created == created, "created timestamp");
    ok(nox_ident_public_blob(&id, &blob, &n) == 0, "public blob");
    nox_ident_init(&pub);
    ok(nox_ident_parse(&pub, blob, n) == 0, "parse public");
    ok(nox_memeq(id.fp, pub.fp, NOX_FP_LEN) == 0, "fingerprint stable");
    ok(strcmp(pub.comment, label) == 0, "comment");
    free(blob);

    /* trailing bytes inside identity.value are still rejected */
    blob = NULL;
    ok(nox_ident_public_blob(&id, &blob, &n) == 0, "public blob again");
    {
        uint8_t *dirty = malloc(n + 1);
        nox_ident bad;
        memcpy(dirty, blob, n);
        dirty[n] = 0xff;
        nox_ident_init(&bad);
        ok(nox_ident_parse(&bad, dirty, n + 1) < 0, "trailing rejected");
        free(dirty);
    }
    free(blob);

    check_crypto(label, &id, &pub, (nox_algset *)set, recip_alg);
    nox_ident_wipe(&id);
    nox_ident_wipe(&pub);
}

/*
 * A hybrid identity must ignore a recipient addressed to its X25519 key
 * alone.  We fake that case by building a one-key identity that carries
 * the same fingerprint and X25519 public key.
 */
static void
check_no_downgrade(nox_ident *hybrid)
{
    nox_ident cut;
    nox_ident *rp[1];
    nox_key *kx = nox_ident_find(hybrid, NOX_ALG_X25519);
    FILE *in, *ct, *pt;
    uint8_t *blob = NULL;
    size_t n = 0;

    ok(kx != NULL, "hybrid has X25519");
    if (kx == NULL)
        return;
    memset(&cut, 0, sizeof cut);
    memcpy(cut.fp, hybrid->fp, NOX_FP_LEN);
    cut.nkeys = 1;
    cut.keys[0] = *kx;
    cut.keys[0].has_sk = 0;
    cut.keys[0].sk_len = 0;
    ok(nox_ident_recipient_alg(&cut) == NOX_ALG_X25519, "cut identity is "
       "classical");

    in = tmpfile();
    ct = tmpfile();
    pt = tmpfile();
    fputs("downgrade?", in);
    rewind(in);
    rp[0] = &cut;
    ok(nox_encrypt(in, ct, 0, rp, 1, NULL, 0) == 0, "encrypt to the cut key");
    rewind(ct);
    rp[0] = hybrid;
    ok(nox_decrypt(ct, pt, rp, 1, NULL, 0) < 0, "hybrid refuses a classical "
       "recipient");
    fclose(in);
    fclose(ct);
    fclose(pt);

    /* ... and the cut key cannot read a hybrid message either */
    in = tmpfile();
    ct = tmpfile();
    pt = tmpfile();
    fputs("hybrid", in);
    rewind(in);
    rp[0] = hybrid;
    ok(nox_encrypt(in, ct, 0, rp, 1, NULL, 0) == 0, "encrypt to the hybrid "
       "key");
    rewind(ct);
    rp[0] = &cut;
    ok(nox_decrypt(ct, pt, rp, 1, NULL, 0) < 0, "classical key refuses a "
       "hybrid recipient");
    fclose(in);
    fclose(ct);
    fclose(pt);
    nox_ident_wipe(&cut);
    (void)blob;
    (void)n;
}

int
main(void)
{
    uint8_t raw[] = { 0, 1, 2, 3, 4, 250, 255 };
    char *b64 = NULL;
    uint8_t *dec = NULL;
    size_t n = 0, m = 0;
    char *arm = NULL;
    uint8_t *body = NULL;
    nox_algset full, classic, pq, mixed;
    nox_ident hybrid;
    uint16_t alg;
    char list[160];
    uint8_t pkt[64];
    nox_parser p;
    uint16_t type;
    int crit;
    const uint8_t *val;
    uint32_t vlen;

    nox_set_faketime(1700000000);

    ok(nox_b64_encode(&b64, &n, raw, sizeof raw) == 0, "b64 encode");
    ok(nox_b64_decode(&dec, &m, (const uint8_t *)b64, n) == 0, "b64 decode");
    ok(m == sizeof raw && memcmp(dec, raw, m) == 0, "b64 round-trip");
    free(b64);
    free(dec);

    ok(nox_armor(&arm, &n, raw, sizeof raw, NOX_KIND_MSG) == 0, "armor");
    {
        const char *nl = strchr(arm, '\n');
        ok(nl != NULL && strncmp(arm, "-----BEGIN NOX MESSAGE-----", 27) == 0,
           "armor header");
        /* body lines wrap at 64; this payload is tiny so one short line */
        ok(strstr(arm, "-----END NOX MESSAGE-----") != NULL, "armor footer");
    }
    ok(nox_dearmor(&body, &m, (const uint8_t *)arm, n) == 0, "dearmor");
    ok(m == sizeof raw && memcmp(body, raw, m) == 0, "dearmor round-trip");
    free(arm);
    free(body);

    /* whitespace-lenient decode */
    {
        const char *messy = "  AA==\n\t\r ";
        ok(nox_b64_decode(&dec, &m, (const uint8_t *)messy, strlen(messy)) == 0,
           "b64 ignores whitespace");
        free(dec);
    }

    /*
     * Streaming armor reader: header handling, a missing blank line
     * (body directly after BEGIN and after plain headers), a UTF-8
     * BOM, and a body line longer than the reader's pushback buffer.
     */
    {
        static const unsigned char payload[7] =
            { 0, 1, 2, 3, 4, 250, 255 };
        char *arm2 = NULL;
        uint8_t back[64];
        size_t got;
        int i;

        ok(nox_armor(&arm2, &n, payload, sizeof payload, NOX_KIND_MSG) == 0,
           "armor for reader");
        {
            /* insert headers and drop the blank line after BEGIN */
            const char *b64start = arm2 + strlen("-----BEGIN NOX MESSAGE-----\n\n");
            char *endmark = strstr(arm2, "-----END NOX MESSAGE-----");
            size_t b64len = (size_t)(endmark - b64start);
            char tight[2048];

            snprintf(tight, sizeof tight,
                     "-----BEGIN NOX MESSAGE-----\n"
                     "Comment: no blank line follows\n"
                     "%.*s"
                     "-----END NOX MESSAGE-----\n",
                     (int)b64len, b64start);

            for (i = 0; i < 2; i++) {
                FILE *fp = tmpfile();
                nox_reader rd;

                if (i == 1) {
                    /* prefix a UTF-8 BOM, which has to be skipped */
                    static const unsigned char bom[3] = { 0xEF, 0xBB, 0xBF };
                    fwrite(bom, 1, 3, fp);
                }
                fputs(tight, fp);
                rewind(fp);
                ok(nox_reader_init(&rd, fp) == 0, "reader init tight armor");
                got = nox_reader_read(&rd, back, sizeof back);
                ok(got == sizeof payload &&
                   memcmp(back, payload, sizeof payload) == 0,
                   i == 0 ? "tight armor decodes" : "BOM armor decodes");
                ok(nox_reader_eof(&rd), "tight armor at end");
                fclose(fp);
            }

            /* a body line that exceeds the pushback buffer is an error */
            {
                FILE *fp = tmpfile();
                nox_reader rd;

                fputs("-----BEGIN NOX MESSAGE-----\n", fp);
                for (i = 0; i < 40; i++)
                    fputs("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", fp);
                fputs("\n-----END NOX MESSAGE-----\n", fp);
                rewind(fp);
                ok(nox_reader_init(&rd, fp) < 0,
                   "over-long tight armor line refused");
                fclose(fp);
            }

            /*
             * A leading "EF BB" sequence that is not a BOM belongs to
             * the stream: the reader must not swallow those bytes and
             * accept input that is not a NoxCrypt document.
             */
            {
                static const unsigned char pre[3] = { 0xEF, 0xBB, 0x42 };
                FILE *fp;
                nox_reader rd;

                fp = tmpfile();
                fwrite(pre, 1, 3, fp);
                fwrite(payload, 1, sizeof payload, fp); /* starts with 'N'? */
                rewind(fp);
                ok(nox_reader_init(&rd, fp) < 0,
                   "non-BOM prefix on binary input refused");
                fclose(fp);

                fp = tmpfile();
                fwrite(pre, 1, 3, fp);
                fputs(arm2, fp);
                rewind(fp);
                ok(nox_reader_init(&rd, fp) < 0,
                   "non-BOM prefix on armor refused");
                fclose(fp);

                /* a real BOM before binary input is skipped */
                {
                    static const unsigned char raw[8] =
                        { 'N', 'O', 'X', 1, 0, 250, 3, 255 };

                    fp = tmpfile();
                    fputc(0xEF, fp);
                    fputc(0xBB, fp);
                    fputc(0xBF, fp);
                    fwrite(raw, 1, sizeof raw, fp);
                    rewind(fp);
                    if (nox_reader_init(&rd, fp) == 0) {
                        got = nox_reader_read(&rd, back, sizeof raw);
                        ok(got == sizeof raw &&
                           memcmp(back, raw, sizeof raw) == 0,
                           "BOM binary decodes");
                    } else {
                        ok(0, "BOM binary init");
                    }
                    fclose(fp);
                }
            }
        }
        free(arm2);
    }

    pkt[0] = NOX_MAGIC0;
    pkt[1] = NOX_MAGIC1;
    pkt[2] = NOX_MAGIC2;
    pkt[3] = NOX_MAGIC3;
    nox_be16(pkt + 4, NOX_PKT_IDENTITY);
    nox_be32(pkt + 6, 3);
    pkt[10] = 'a';
    pkt[11] = 'b';
    pkt[12] = 'c';
    nox_parser_init(&p, pkt, 13);
    ok(nox_skip_magic(&p) == 0, "magic");
    ok(nox_pkt_next(&p, &type, &crit, &val, &vlen) == 0, "packet");
    ok(type == NOX_PKT_IDENTITY && vlen == 3 && val[0] == 'a', "packet fields");
    ok(!nox_parser_left(&p), "no trailing");

    nox_be16(pkt + 4, 0);
    nox_parser_init(&p, pkt, 13);
    nox_skip_magic(&p);
    ok(nox_pkt_next(&p, &type, &crit, &val, &vlen) < 0, "type 0 rejected");

    ok(!nox_utf8_ok((const uint8_t *)"a\nb", 3), "utf8 rejects LF");
    ok(!nox_utf8_ok((const uint8_t *)"a\0b", 3), "utf8 rejects NUL");
    ok(nox_utf8_ok((const uint8_t *)"ok \xE2\x9C\x93", 6), "utf8 accepts");

    /*
     * Regression: base64 decoding of every small length must be safe,
     * in particular lengths that are 2 mod 4 without whitespace used
     * to overflow the scratch buffer by one byte while appending
     * padding.  Run under ASan in the sanitizer build.
     */
    {
        int L;
        for (L = 1; L <= 24; L++) {
            char s[25];
            memset(s, 'A', (size_t)L);
            if (nox_b64_decode(&dec, &m, (const uint8_t *)s, (size_t)L) == 0)
                free(dec);
            else
                ok(L % 4 == 1, "b64 length classes");
        }
        /* padding may also push past the end when whitespace was eaten */
        {
            const char *messy = "AA AA";
            ok(nox_b64_decode(&dec, &m, (const uint8_t *)messy, 5) == 0 &&
               m == 3, "b64 whitespace then padless tail");
            free(dec);
        }
    }

    /*
     * Regression: an identity whose comment length field exceeds
     * NOX_MAX_COMMENT must be rejected before anything is copied
     * (it used to overflow the 1024-byte comment field).
     */
    {
        size_t c1 = NOX_MAX_COMMENT + 1;
        uint8_t *v = malloc(10 + c1);
        nox_ident bad;

        memset(v, 0, 10);
        v[8] = (uint8_t)(c1 >> 8);
        v[9] = (uint8_t)c1;
        memset(v + 10, 'A', c1);
        nox_ident_init(&bad);
        ok(nox_ident_parse_value(&bad, v, 10 + c1) < 0,
           "identity comment of 1025 bytes rejected");
        nox_ident_wipe(&bad);
        free(v);

        c1 = 0xffff;
        v = malloc(10 + c1);
        memset(v, 0, 10);
        v[8] = 0xff;
        v[9] = 0xff;
        memset(v + 10, 'A', c1);
        nox_ident_init(&bad);
        ok(nox_ident_parse_value(&bad, v, 10 + c1) < 0,
           "identity comment of 65535 bytes rejected");
        nox_ident_wipe(&bad);
        free(v);

        /* a comment of exactly NOX_MAX_COMMENT is still fine */
        {
            nox_ident id2;
            nox_algset ecc_set;
            char big[NOX_MAX_COMMENT + 1];
            uint8_t *blob = NULL;
            size_t bn = 0;

            nox_algset_classic(&ecc_set);
            memset(big, 'x', NOX_MAX_COMMENT);
            big[NOX_MAX_COMMENT] = 0;
            nox_ident_init(&id2);
            ok(nox_ident_generate(&id2, &ecc_set, big, nox_now()) == 0,
               "generate with 1024-byte comment");
            ok(nox_ident_public_blob(&id2, &blob, &bn) == 0, "blob");
            nox_ident_wipe(&id2);
            nox_ident_init(&id2);
            ok(nox_ident_parse(&id2, blob, bn) == 0,
               "parse with 1024-byte comment");
            ok(strlen(id2.comment) == NOX_MAX_COMMENT, "comment survives");
            nox_ident_wipe(&id2);
            free(blob);
        }
    }

    /* algorithm names and profiles */
    ok(strcmp(nox_alg_name(NOX_ALG_MLKEM768), "ML-KEM-768") == 0, "alg name");
    ok(strcmp(nox_alg_name(0x4242), "unknown") == 0, "unknown alg name");
    ok(nox_alg_parse("mlkem768", &alg) == 0 && alg == NOX_ALG_MLKEM768,
       "alg parse");
    ok(nox_alg_parse("ML-DSA-44", &alg) == 0 && alg == NOX_ALG_MLDSA44,
       "alg parse spelled out");
    ok(nox_alg_parse("rsa", &alg) < 0, "alg parse rejects rsa");

    nox_algset_full(&full);
    nox_algset_classic(&classic);
    nox_algset_pq(&pq);
    memset(&mixed, 0, sizeof mixed);
    nox_algset_add(&mixed, NOX_ALG_ED25519);
    nox_algset_add(&mixed, NOX_ALG_MLKEM768);
    ok(strcmp(nox_algset_name(&full), "hybrid") == 0, "full name");
    ok(strcmp(nox_algset_name(&classic), "ecc") == 0, "classic name");
    ok(strcmp(nox_algset_name(&pq), "pqc") == 0, "pq name");
    ok(strcmp(nox_algset_name(&mixed), "mixed") == 0, "mixed name");
    ok(nox_algset_valid(&mixed), "mixed is valid");
    ok(nox_algset_parse(&full, "ecc") == 0 && !full.mldsa44, "parse profile");
    ok(nox_algset_parse(&full, "nonsense") < 0, "parse rejects nonsense");
    {
        nox_algset signonly;
        memset(&signonly, 0, sizeof signonly);
        nox_algset_add(&signonly, NOX_ALG_ED25519);
        ok(!nox_algset_valid(&signonly), "sign-only set is invalid");
    }
    nox_algset_full(&full);

    check_profile("alice@example.com", &full, 4, NOX_ALG_HYBRID, "hybrid",
                  1700000000);
    check_profile("bob", &classic, 2, NOX_ALG_X25519, "ecc", 1700000001);
    check_profile("carol", &pq, 2, NOX_ALG_MLKEM768, "pqc", 1700000002);
    check_profile("dave", &mixed, 2, NOX_ALG_MLKEM768, "mixed", 1700000003);

    nox_ident_init(&hybrid);
    ok(nox_ident_generate(&hybrid, &full, "hybrid", nox_now()) == 0,
       "generate hybrid");
    nox_ident_alg_list(&hybrid, list, sizeof list);
    ok(strcmp(list, "Ed25519 + ML-DSA-44 + X25519 + ML-KEM-768") == 0,
       "algorithm list");
    ok(nox_ident_find(&hybrid, NOX_ALG_ED25519) != NULL, "ed25519");
    ok(nox_ident_find(&hybrid, NOX_ALG_MLDSA44) != NULL, "mldsa");
    ok(nox_ident_has_hybrid_enc(&hybrid), "hybrid encryption");
    check_no_downgrade(&hybrid);
    nox_ident_wipe(&hybrid);

    /* a key pair with an algorithm nobody has cannot be generated */
    {
        nox_algset none;
        nox_ident id;
        memset(&none, 0, sizeof none);
        nox_ident_init(&id);
        ok(nox_ident_generate(&id, &none, "x", nox_now()) < 0, "empty set");
    }

    /* untrusted Argon2id work factors are capped */
    {
        uint8_t key[32], salt[16];
        char pass[8] = "secret";
        memset(salt, 1, sizeof salt);
        ok(nox_argon2id(key, pass, 6, 3, 65536, 1, salt) == 0, "argon2 v1");
        ok(nox_argon2id(key, pass, 6, 65, 65536, 1, salt) < 0,
           "argon2 rejects t=65");
        ok(nox_argon2id(key, pass, 6, 0, 65536, 1, salt) < 0,
           "argon2 rejects t=0");
        ok(nox_argon2id(key, pass, 6, 4, 65536, 1, salt) == 0,
           "argon2 accepts a higher t under the cap");
    }

    {
        nox_ident id;
        uint8_t fp[NOX_FP_LEN];
        char hex[65], pre[9];
        int k;

        for (k = 0; k < NOX_FP_LEN; k++)
            fp[k] = (uint8_t)k;
        nox_hex(hex, fp, NOX_FP_LEN);
        memcpy(pre, hex, 8);
        pre[8] = 0;
        ok(nox_fp_prefix(fp, hex) == 1, "fp full");
        ok(nox_fp_prefix(fp, pre) == 1, "fp prefix 8");
        pre[7] = 0;
        ok(nox_fp_prefix(fp, pre) == 0, "fp prefix 7 rejected");
        nox_ident_init(&id);
    }

    if (fails) {
        fprintf(stderr, "%d test(s) failed\n", fails);
        return 1;
    }
    printf("test_unit: ok\n");
    return 0;
}
