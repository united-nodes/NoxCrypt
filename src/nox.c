#define _GNU_SOURCE

#include "armor.h"
#include "cipher.h"
#include "identity.h"
#include "keyring.h"
#include "packet.h"
#include "passphrase.h"
#include "secret.h"
#include "sign.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Output file modes.  Secret material (a passphrase-protected secret
 * key) is created 0600 regardless of the umask; everything else gets
 * the usual 0666 & ~umask.
 */
#define NOX_OUT_DATA   0666
#define NOX_OUT_SECRET 0600

/*
 * Output files are written to a temporary file next to the destination
 * and renamed into place when the command succeeds.  A failed command
 * (wrong passphrase, corrupted ciphertext, full disk) then leaves the
 * previous content of the output file untouched instead of a truncated
 * one.  die() discards the temporary file.
 */
static char pending_tmp[4096];
static char pending_dst[4096];
static mode_t pending_mode;

static void
pending_out_discard(void)
{
    if (pending_tmp[0] != 0) {
        unlink(pending_tmp);
        pending_tmp[0] = 0;
    }
    pending_dst[0] = 0;
}

static void
die(void)
{
    pending_out_discard();
    fprintf(stderr, "nox: %s\n", nox_err);
    exit(1);
}

static void
usage(FILE *fp)
{
    fprintf(fp,
        "Usage: nox [--faketime UNIX] [--home DIR] COMMAND [OPTIONS]\n"
        "\n"
        "Commands:\n"
        "  gen       generate a key pair and store it in the keyring\n"
        "  encrypt   encrypt a message to one or more recipients\n"
        "  decrypt   decrypt a message\n"
        "  sign      create a detached signature\n"
        "  verify    verify a detached signature\n"
        "  list      list the keys in the keyring\n"
        "  export    export a public or secret key\n"
        "  import    import a public or secret key\n"
        "  delete    delete a key from the keyring\n"
        "  info      show version, algorithms and keyring summary\n"
        "  help      print this text\n"
        "\n"
        "Global options:\n"
        "  --home DIR       use DIR instead of $HOME (or $NOX_HOME)\n"
        "  --faketime UNIX  pretend the clock reads UNIX seconds\n"
        "  --version        print the version and exit\n"
        "  --help           print this text and exit\n"
        "\n"
        "Run \"nox COMMAND --help\" for the options of a command.\n");
}

/* Commands without options of their own still take --help. */
static const struct option help_only[] = {
    { "help", no_argument, 0, 'h' },
    { 0, 0, 0, 0 }
};

static int
get_pass(char *buf, size_t n, int confirm, const char *passfile)
{
    if (passfile != NULL)
        return nox_read_passfile(buf, n, passfile);
    if (confirm)
        return nox_confirm_passphrase(buf, n);
    return nox_read_passphrase(buf, n, "Passphrase: ");
}

static int
refuse_binary(int armor, FILE *out)
{
    if (!armor && nox_isatty(out))
        return nox_seterr("refusing to write binary to the terminal (use --armor)");
    return 0;
}

static int
emit_blob(FILE *out, const uint8_t *buf, size_t n, int armor, const char *kind)
{
    if (refuse_binary(armor, out) < 0)
        return -1;
    if (armor) {
        char *s = NULL;
        size_t sn = 0;
        int rc;
        if (nox_armor(&s, &sn, buf, n, kind) < 0)
            return -1;
        rc = nox_write_all(out, s, sn);
        free(s);
        return rc;
    }
    return nox_write_all(out, buf, n);
}

static FILE *
open_in(const char *path, int *opened)
{
    *opened = 0;
    if (path == NULL || strcmp(path, "-") == 0)
        return stdin;
    {
        FILE *fp = fopen(path, "rb");
        if (fp == NULL) {
            nox_seterr("open %s: %s", path, strerror(errno));
            return NULL;
        }
        *opened = 1;
        return fp;
    }
}

static int
temp_path_for(const char *path, char *tmp, size_t n)
{
    char dir[4096];
    const char *slash = strrchr(path, '/');
    const char *base = path;
    int k;

    if (slash == NULL) {
        dir[0] = '.';
        dir[1] = 0;
    } else {
        size_t dl = (size_t)(slash - path);
        if (dl == 0)
            dl = 1; /* "/file" writes into "/" */
        if (dl >= sizeof dir)
            return nox_seterr("path too long");
        memcpy(dir, path, dl);
        dir[dl] = 0;
        base = slash + 1;
    }
    if (base[0] == 0)
        return nox_seterr("invalid output path");
    k = snprintf(tmp, n, "%s/.nox-tmp-%ld-%s", dir, (long)getpid(), base);
    if (k < 0 || (size_t)k >= n)
        return nox_seterr("path too long");
    return 0;
}

static FILE *
open_out(const char *path, int *opened, mode_t mode)
{
    char tmp[4096];
    int fd;
    FILE *fp;

    *opened = 0;
    if (path == NULL || strcmp(path, "-") == 0)
        return stdout;
    if (temp_path_for(path, tmp, sizeof tmp) < 0)
        return NULL;
    unlink(tmp);
    /*
     * Always created 0600: until finish_out() widens the mode, the
     * file may hold plaintext or a secret key.
     */
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
              0600);
    if (fd < 0) {
        nox_seterr("create %s: %s", path, strerror(errno));
        return NULL;
    }
    fp = fdopen(fd, "w");
    if (fp == NULL) {
        nox_seterr("fdopen: %s", strerror(errno));
        close(fd);
        unlink(tmp);
        return NULL;
    }
    snprintf(pending_tmp, sizeof pending_tmp, "%s", tmp);
    snprintf(pending_dst, sizeof pending_dst, "%s", path);
    pending_mode = mode;
    *opened = 1;
    return fp;
}

static int
finish_out(FILE *fp, int opened)
{
    if (fflush(fp) != 0) {
        nox_seterr("write: %s", strerror(errno));
        if (opened) {
            fclose(fp);
            pending_out_discard();
        }
        return -1;
    }
    if (!opened)
        return 0;
    /*
     * The temporary file was created 0600 and holds the finished
     * document.  Only now, with the content complete, does it get
     * its final mode, so nothing readable-by-others exists at any
     * intermediate point.
     */
    if (fchmod(fileno(fp), pending_mode) < 0) {
        nox_seterr("chmod %s: %s", pending_dst, strerror(errno));
        fclose(fp);
        pending_out_discard();
        return -1;
    }
    if (fclose(fp) != 0) {
        nox_seterr("close: %s", strerror(errno));
        pending_out_discard();
        return -1;
    }
    if (rename(pending_tmp, pending_dst) < 0) {
        nox_seterr("rename %s: %s", pending_dst, strerror(errno));
        pending_out_discard();
        return -1;
    }
    pending_tmp[0] = 0;
    pending_dst[0] = 0;
    return 0;
}

static int
unlock_query(nox_ident *id, const char *query, const char *passfile)
{
    uint8_t *blob = NULL, *raw = NULL;
    size_t n = 0, rn = 0;
    uint8_t fp[NOX_FP_LEN];
    char pass[NOX_PASS_MAX + 1];
    int rc;

    if (nox_keyring_load_sec_blob(query, &blob, &n, fp) < 0)
        return -1;
    if (nox_unwrap_blob(&raw, &rn, blob, n) < 0) {
        free(blob);
        return -1;
    }
    free(blob);
    if (get_pass(pass, sizeof pass, 0, passfile) < 0) {
        free(raw);
        return -1;
    }
    rc = nox_secret_unlock(id, raw, rn, pass, strlen(pass));
    nox_wipe(pass, sizeof pass);
    nox_wipe(raw, rn);
    free(raw);
    return rc;
}

static int
cmd_gen(int argc, char **argv)
{
    const char *comment = "";
    const char *pub_out = NULL, *sec_out = NULL, *passfile = NULL;
    const char *preset = NULL, *sig_name = NULL, *kem_name = NULL;
    nox_algset set;
    nox_ident id;
    char pass[NOX_PASS_MAX + 1];
    char pubpath[4096], secpath[4096], hex[65], algs[160];
    uint8_t *sec = NULL, *pub = NULL;
    size_t sec_n = 0, pub_n = 0;
    int armor = 0, c;

    static const struct option opts[] = {
        { "comment",         required_argument, 0, 'c' },
        { "algo",            required_argument, 0, 'A' },
        { "sig",             required_argument, 0, 's' },
        { "kem",             required_argument, 0, 'k' },
        { "pub",             required_argument, 0, 'P' },
        { "sec",             required_argument, 0, 'S' },
        { "armor",           no_argument,       0, 'a' },
        { "passphrase-file", required_argument, 0, 'F' },
        { "help",            no_argument,       0, 'h' },
        { 0, 0, 0, 0 }
    };
    optind = 1;
    while ((c = getopt_long(argc, argv, "c:A:P:S:aF:h", opts, NULL)) != -1) {
        switch (c) {
        case 'c': comment = optarg; break;
        case 'A': preset = optarg; break;
        case 's': sig_name = optarg; break;
        case 'k': kem_name = optarg; break;
        case 'P': pub_out = optarg; break;
        case 'S': sec_out = optarg; break;
        case 'a': armor = 1; break;
        case 'F': passfile = optarg; break;
        case 'h':
            fprintf(stdout,
                "Usage: nox gen [-A PROFILE | --sig ALG --kem ALG] [-c COMMENT]\n"
                "               [--pub FILE] [--sec FILE] [-a]\n"
                "               [--passphrase-file FILE]\n"
                "\n"
                "  -c, --comment TEXT          comment stored with the key\n"
                "  -A, --algo PROFILE          hybrid (default), ecc, or pqc\n"
                "      --sig ALG               ed25519 or mldsa44\n"
                "      --kem ALG               x25519 or mlkem768\n"
                "  -P, --pub FILE              also write the public key to FILE\n"
                "  -S, --sec FILE              also write the secret key to FILE\n"
                "  -a, --armor                 armor the files written above\n"
                "  -F, --passphrase-file FILE  read the passphrase from FILE\n"
                "\n"
                "  hybrid  Ed25519 + ML-DSA-44 + X25519 + ML-KEM-768\n"
                "  ecc     Ed25519 + X25519\n"
                "  pqc     ML-DSA-44 + ML-KEM-768\n"
                "\n"
                "--sig and --kem together select a mixed pair.  The key pair\n"
                "is stored in the keyring; the fingerprint goes to stdout and\n"
                "the file names to stderr.  The passphrase is read twice from\n"
                "the terminal (or once from --passphrase-file) and can only be\n"
                "changed by generating a new key.\n");
            return 0;
        default:
            return 2;
        }
    }
    if (sig_name != NULL || kem_name != NULL) {
        uint16_t alg;

        if (preset != NULL) {
            nox_seterr("--algo cannot be combined with --sig/--kem");
            die();
        }
        if (sig_name == NULL || kem_name == NULL) {
            nox_seterr("--sig and --kem must be given together");
            die();
        }
        memset(&set, 0, sizeof set);
        if (nox_alg_parse(sig_name, &alg) < 0 || !nox_is_sign_alg(alg)) {
            nox_seterr("'%s' is not a signing algorithm "
                       "(ed25519 or mldsa44)", sig_name);
            die();
        }
        nox_algset_add(&set, alg);
        if (nox_alg_parse(kem_name, &alg) < 0 || !nox_is_enc_alg(alg)) {
            nox_seterr("'%s' is not an encryption algorithm "
                       "(x25519 or mlkem768)", kem_name);
            die();
        }
        nox_algset_add(&set, alg);
    } else if (preset != NULL) {
        if (nox_algset_parse(&set, preset) < 0)
            die();
    } else {
        nox_algset_full(&set);
    }

    /* cheap checks first: do not ask twice for a passphrase we keep */
    if (nox_comment_ok(comment) < 0)
        die();
    if (get_pass(pass, sizeof pass, 1, passfile) < 0)
        die();
    nox_ident_init(&id);
    if (nox_ident_generate(&id, &set, comment, nox_now()) < 0) {
        nox_wipe(pass, sizeof pass);
        die();
    }
    if (nox_secret_lock(&sec, &sec_n, &id, pass, strlen(pass)) < 0) {
        nox_wipe(pass, sizeof pass);
        nox_ident_wipe(&id);
        die();
    }
    nox_wipe(pass, sizeof pass);
    if (nox_ident_public_blob(&id, &pub, &pub_n) < 0) {
        nox_ident_wipe(&id);
        nox_wipe(sec, sec_n);
        free(sec);
        die();
    }
    nox_hex(hex, id.fp, NOX_FP_LEN);
    if (nox_keyring_key_path(pubpath, sizeof pubpath, id.fp, "pub") < 0 ||
        nox_keyring_key_path(secpath, sizeof secpath, id.fp, "sec") < 0) {
        nox_ident_wipe(&id);
        nox_wipe(sec, sec_n);
        free(sec);
        free(pub);
        die();
    }

    if (nox_keyring_store_pub(&id) < 0 ||
        nox_keyring_store_sec(id.fp, sec, sec_n) < 0) {
        nox_ident_wipe(&id);
        nox_wipe(sec, sec_n);
        free(sec);
        free(pub);
        die();
    }
    nox_ident_alg_list(&id, algs, sizeof algs);
    fprintf(stderr, "nox: fingerprint  %s\n", hex);
    fprintf(stderr, "nox: algorithms   %s: %s\n", nox_ident_profile(&id), algs);
    fprintf(stderr, "nox: public key   %s\n", pubpath);
    fprintf(stderr, "nox: secret key   %s\n", secpath);
    if (pub_out != NULL) {
        FILE *fp;
        int op;
        fp = open_out(pub_out, &op, NOX_OUT_DATA);
        if (fp == NULL)
            goto fail;
        if (emit_blob(fp, pub, pub_n, armor || nox_isatty(fp), NOX_KIND_PUB) < 0 ||
            finish_out(fp, op) < 0)
            goto fail;
    }
    if (sec_out != NULL) {
        FILE *fp;
        int op;
        fp = open_out(sec_out, &op, NOX_OUT_SECRET);
        if (fp == NULL)
            goto fail;
        if (emit_blob(fp, sec, sec_n, armor || nox_isatty(fp), NOX_KIND_SEC) < 0 ||
            finish_out(fp, op) < 0)
            goto fail;
    }
    printf("%s\n", hex);
    nox_ident_wipe(&id);
    nox_wipe(sec, sec_n);
    free(sec);
    free(pub);
    return 0;
fail:
    nox_ident_wipe(&id);
    nox_wipe(sec, sec_n);
    free(sec);
    free(pub);
    die();
    return 1;
}

static int
cmd_encrypt(int argc, char **argv)
{
    const char *out_path = NULL, *passfile = NULL, *in_path = NULL;
    char *recip_q[NOX_MAX_RECIPIENTS];
    char *recip_f[NOX_MAX_RECIPIENTS];
    int nq = 0, nf = 0, armor = 0, want_pass = 0;
    nox_ident recips[NOX_MAX_RECIPIENTS];
    nox_ident *rp[NOX_MAX_RECIPIENTS];
    int nrec = 0, c, i;
    char pass[NOX_PASS_MAX + 1];
    FILE *in, *out;
    int in_open = 0, out_open = 0;

    static const struct option opts[] = {
        { "recipient",       required_argument, 0, 'r' },
        { "recipient-file",  required_argument, 0, 'R' },
        { "passphrase",      no_argument,       0, 'p' },
        { "armor",           no_argument,       0, 'a' },
        { "output",          required_argument, 0, 'o' },
        { "passphrase-file", required_argument, 0, 'F' },
        { "help",            no_argument,       0, 'h' },
        { 0, 0, 0, 0 }
    };
    optind = 1;
    while ((c = getopt_long(argc, argv, "r:R:pao:F:h", opts, NULL)) != -1) {
        switch (c) {
        case 'r':
            if (nq + nf >= NOX_MAX_RECIPIENTS) {
                nox_seterr("too many recipients");
                die();
            }
            recip_q[nq++] = optarg;
            break;
        case 'R':
            if (nq + nf >= NOX_MAX_RECIPIENTS) {
                nox_seterr("too many recipients");
                die();
            }
            recip_f[nf++] = optarg;
            break;
        case 'p': want_pass = 1; break;
        case 'a': armor = 1; break;
        case 'o': out_path = optarg; break;
        case 'F': passfile = optarg; want_pass = 1; break;
        case 'h':
            fprintf(stdout,
                "Usage: nox encrypt [-r FP]... [-R FILE]... | -p\n"
                "                   [-a] [-o FILE] [-F FILE] [IN]\n"
                "\n"
                "  -r, --recipient FP          recipient fingerprint prefix\n"
                "  -R, --recipient-file FILE   read a public key from FILE\n"
                "  -p, --passphrase            use a passphrase instead of keys\n"
                "  -a, --armor                 armor the output\n"
                "  -o, --output FILE           write to FILE instead of stdout\n"
                "  -F, --passphrase-file FILE  read the passphrase from FILE\n"
                "\n"
                "At least one recipient is required.  A passphrase recipient is\n"
                "always alone; mixing it with public keys is an error.  IN (or\n"
                "\"-\") is stdin, the output is a NoxCrypt message either way.\n"
                "Messages are readable by the recipient only, and by nobody\n"
                "who has neither the secret key nor the passphrase.\n");
            return 0;
        default:
            return 2;
        }
    }
    if (optind < argc)
        in_path = argv[optind];
    if (want_pass && (nq > 0 || nf > 0)) {
        nox_seterr("passphrase recipient must be the sole recipient");
        die();
    }
    if (!want_pass && nq == 0 && nf == 0) {
        nox_seterr("no recipients (use -r, -R, or -p)");
        die();
    }
    for (i = 0; i < nq; i++) {
        nox_ident_init(&recips[nrec]);
        if (nox_keyring_load_pub(recip_q[i], &recips[nrec]) < 0)
            die();
        rp[nrec] = &recips[nrec];
        nrec++;
    }
    for (i = 0; i < nf; i++) {
        uint8_t *buf = NULL;
        size_t n = 0;
        if (nox_read_file(recip_f[i], &buf, &n, NOX_MAX_BLOB) < 0)
            die();
        nox_ident_init(&recips[nrec]);
        if (nox_ident_load_pub(&recips[nrec], buf, n) < 0) {
            free(buf);
            die();
        }
        free(buf);
        rp[nrec] = &recips[nrec];
        nrec++;
    }
    in = open_in(in_path, &in_open);
    if (in == NULL)
        die();
    out = open_out(out_path, &out_open, NOX_OUT_DATA);
    if (out == NULL)
        die();
    if (refuse_binary(armor, out) < 0)
        die();
    /* the passphrase is taken last, after every other failure is ruled out */
    if (want_pass) {
        if (get_pass(pass, sizeof pass, 1, passfile) < 0)
            die();
    }
    if (nox_encrypt(in, out, armor, want_pass ? NULL : rp, want_pass ? 0 : nrec,
                    want_pass ? pass : NULL,
                    want_pass ? strlen(pass) : 0) < 0) {
        if (want_pass)
            nox_wipe(pass, sizeof pass);
        die();
    }
    if (want_pass)
        nox_wipe(pass, sizeof pass);
    if (in_open)
        fclose(in);
    if (finish_out(out, out_open) < 0)
        die();
    for (i = 0; i < nrec; i++)
        nox_ident_wipe(&recips[i]);
    return 0;
}

static int
cmd_decrypt(int argc, char **argv)
{
    const char *out_path = NULL, *passfile = NULL, *in_path = NULL;
    const char *ident = NULL;
    int want_pass = 0, c;
    char pass[NOX_PASS_MAX + 1];
    nox_ident id, *ids[1];
    FILE *in, *out;
    int in_open = 0, out_open = 0;

    static const struct option opts[] = {
        { "identity",        required_argument, 0, 'i' },
        { "passphrase",      no_argument,       0, 'p' },
        { "output",          required_argument, 0, 'o' },
        { "passphrase-file", required_argument, 0, 'F' },
        { "help",            no_argument,       0, 'h' },
        { 0, 0, 0, 0 }
    };
    optind = 1;
    while ((c = getopt_long(argc, argv, "i:po:F:h", opts, NULL)) != -1) {
        switch (c) {
        case 'i': ident = optarg; break;
        case 'p': want_pass = 1; break;
        case 'o': out_path = optarg; break;
        case 'F': passfile = optarg; break;
        case 'h':
            fprintf(stdout,
                "Usage: nox decrypt [-i FP | -p] [-o FILE] [-F FILE] [IN]\n"
                "\n"
                "  -i, --identity FP           key to decrypt with\n"
                "  -p, --passphrase            the message has a passphrase recipient\n"
                "  -o, --output FILE           write to FILE instead of stdout\n"
                "  -F, --passphrase-file FILE  read the passphrase from FILE\n"
                "\n"
                "Without -i the single secret key in the keyring is used.  The\n"
                "recipient flavor (hybrid, X25519, or ML-KEM-768) has to match\n"
                "the identity: a hybrid key never accepts a classical or a\n"
                "post-quantum-only recipient, and the other way round.\n");
            return 0;
        default:
            return 2;
        }
    }
    if (want_pass && ident != NULL) {
        nox_seterr("-i and -p cannot be combined: a passphrase message "
                   "is not tied to an identity");
        die();
    }
    if (optind < argc)
        in_path = argv[optind];
    in = open_in(in_path, &in_open);
    if (in == NULL)
        die();
    out = open_out(out_path, &out_open, NOX_OUT_DATA);
    if (out == NULL)
        die();

    if (want_pass) {
        if (get_pass(pass, sizeof pass, 0, passfile) < 0)
            die();
        if (nox_decrypt(in, out, NULL, 0, pass, strlen(pass)) < 0) {
            nox_wipe(pass, sizeof pass);
            die();
        }
        nox_wipe(pass, sizeof pass);
    } else {
        const char *q = ident;
        if (q == NULL) {
            int nsec = nox_keyring_count_sec();
            if (nsec < 0)
                die();
            if (nsec == 0) {
                nox_seterr("no secret keys in the keyring (use -i or -p)");
                die();
            }
            if (nsec > 1) {
                nox_seterr("multiple secret keys; specify -i FINGERPRINT");
                die();
            }
        }
        nox_ident_init(&id);
        if (unlock_query(&id, q, passfile) < 0)
            die();
        ids[0] = &id;
        if (nox_decrypt(in, out, ids, 1, NULL, 0) < 0) {
            nox_ident_wipe(&id);
            die();
        }
        nox_ident_wipe(&id);
    }
    if (in_open)
        fclose(in);
    if (finish_out(out, out_open) < 0)
        die();
    return 0;
}

static int
cmd_sign(int argc, char **argv)
{
    const char *out_path = NULL, *passfile = NULL, *in_path = NULL, *ident = NULL;
    int armor = 0, c;
    nox_ident id;
    uint8_t hash[32], *sig = NULL;
    size_t sig_n = 0;
    FILE *in, *out;
    int in_open = 0, out_open = 0;

    static const struct option opts[] = {
        { "identity",        required_argument, 0, 'i' },
        { "armor",           no_argument,       0, 'a' },
        { "output",          required_argument, 0, 'o' },
        { "passphrase-file", required_argument, 0, 'F' },
        { "help",            no_argument,       0, 'h' },
        { 0, 0, 0, 0 }
    };
    optind = 1;
    while ((c = getopt_long(argc, argv, "i:ao:F:h", opts, NULL)) != -1) {
        switch (c) {
        case 'i': ident = optarg; break;
        case 'a': armor = 1; break;
        case 'o': out_path = optarg; break;
        case 'F': passfile = optarg; break;
        case 'h':
            fprintf(stdout,
                "Usage: nox sign [-i FP] [-a] [-o FILE] [-F FILE] [IN]\n"
                "\n"
                "  -i, --identity FP           key to sign with\n"
                "  -a, --armor                 armor the signature\n"
                "  -o, --output FILE           write to FILE instead of stdout\n"
                "  -F, --passphrase-file FILE  read the passphrase from FILE\n"
                "\n"
                "The message is hashed, not copied, so IN can be large.  One\n"
                "signature is produced for every signing key of the identity.\n");
            return 0;
        default:
            return 2;
        }
    }
    if (optind < argc)
        in_path = argv[optind];
    if (ident == NULL) {
        int nsec = nox_keyring_count_sec();
        if (nsec < 0)
            die();
        if (nsec == 0) {
            nox_seterr("no secret keys in the keyring (use -i)");
            die();
        }
        if (nsec > 1) {
            nox_seterr("multiple secret keys; specify -i FINGERPRINT");
            die();
        }
    }
    /* hash first: never ask for a passphrase if the message is unreadable */
    in = open_in(in_path, &in_open);
    if (in == NULL)
        die();
    if (nox_hash_file(in, hash) < 0) {
        if (in_open)
            fclose(in);
        die();
    }
    if (in_open)
        fclose(in);
    nox_ident_init(&id);
    if (unlock_query(&id, ident, passfile) < 0)
        die();
    if (nox_sign_detached(&sig, &sig_n, &id, hash) < 0) {
        nox_ident_wipe(&id);
        die();
    }
    nox_ident_wipe(&id);
    out = open_out(out_path, &out_open, NOX_OUT_DATA);
    if (out == NULL) {
        free(sig);
        die();
    }
    if (refuse_binary(armor, out) < 0 ||
        emit_blob(out, sig, sig_n, armor, NOX_KIND_SIG) < 0) {
        if (out_open)
            fclose(out);
        free(sig);
        die();
    }
    free(sig);
    if (finish_out(out, out_open) < 0)
        die();
    return 0;
}

static int
cmd_verify(int argc, char **argv)
{
    const char *pubfile = NULL, *ident = NULL, *sigpath = NULL, *msgpath = NULL;
    int c;
    uint8_t *sig = NULL, hash[32];
    size_t sig_n = 0;
    nox_ident id;
    FILE *msg;
    int msg_open = 0;

    static const struct option opts[] = {
        { "key",      required_argument, 0, 'k' },
        { "identity", required_argument, 0, 'i' },
        { "help",     no_argument,       0, 'h' },
        { 0, 0, 0, 0 }
    };
    optind = 1;
    while ((c = getopt_long(argc, argv, "k:i:h", opts, NULL)) != -1) {
        switch (c) {
        case 'k': pubfile = optarg; break;
        case 'i': ident = optarg; break;
        case 'h':
            fprintf(stdout,
                "Usage: nox verify [-k PUBFILE | -i FP] SIGNATURE [MESSAGE]\n"
                "\n"
                "  -k, --key FILE   public key file to verify against\n"
                "  -i, --identity FP  key in the keyring to verify against\n"
                "\n"
                "Without -k or -i the fingerprint inside the signature picks\n"
                "the key.  MESSAGE (or \"-\") is stdin.  Nothing is printed but\n"
                "\"Good signature\"; the exit status carries the answer.\n");
            return 0;
        default:
            return 2;
        }
    }
    if (pubfile != NULL && ident != NULL) {
        nox_seterr("-k and -i cannot be combined");
        die();
    }
    if (optind >= argc) {
        nox_seterr("missing signature file");
        die();
    }
    sigpath = argv[optind++];
    if (optind < argc)
        msgpath = argv[optind];
    if (nox_read_file(sigpath, &sig, &sig_n, NOX_MAX_BLOB) < 0)
        die();

    nox_ident_init(&id);
    if (pubfile != NULL) {
        uint8_t *buf = NULL;
        size_t n = 0;
        if (nox_read_file(pubfile, &buf, &n, NOX_MAX_BLOB) < 0) {
            free(sig);
            die();
        }
        if (nox_ident_load_pub(&id, buf, n) < 0) {
            free(buf);
            free(sig);
            die();
        }
        free(buf);
    } else {
        uint8_t *raw = NULL;
        size_t rn = 0;
        nox_parser p;
        uint16_t type;
        int crit;
        const uint8_t *val;
        uint32_t vlen;
        char hex[65];
        const char *q = ident;

        if (nox_unwrap_blob(&raw, &rn, sig, sig_n) < 0) {
            free(sig);
            die();
        }
        nox_parser_init(&p, raw, rn);
        if (nox_skip_magic(&p) < 0 ||
            nox_pkt_next(&p, &type, &crit, &val, &vlen) < 0) {
            free(raw);
            free(sig);
            die();
        }
        if (type != NOX_PKT_DETSIG || vlen < 40) {
            free(raw);
            free(sig);
            nox_seterr("not a detached signature");
            die();
        }
        nox_hex(hex, val + 8, NOX_FP_LEN);
        free(raw);
        if (q == NULL)
            q = hex;
        if (nox_keyring_load_pub(q, &id) < 0) {
            free(sig);
            die();
        }
    }
    msg = open_in(msgpath, &msg_open);
    if (msg == NULL) {
        nox_ident_wipe(&id);
        free(sig);
        die();
    }
    if (nox_hash_file(msg, hash) < 0) {
        nox_ident_wipe(&id);
        free(sig);
        die();
    }
    if (msg_open)
        fclose(msg);
    if (nox_verify_detached(sig, sig_n, &id, hash) < 0) {
        nox_ident_wipe(&id);
        free(sig);
        die();
    }
    nox_ident_wipe(&id);
    free(sig);
    printf("Good signature\n");
    return 0;
}

static int
cmd_list(int argc, char **argv)
{
    const char *q = NULL;
    int c;

    optind = 1;
    while ((c = getopt_long(argc, argv, "h", help_only, NULL)) != -1) {
        if (c == 'h') {
            fprintf(stdout,
                "Usage: nox list [QUERY]\n"
                "\n"
                "Prints fingerprint and creation date (UTC) on one line, the\n"
                "algorithm profile on the next, then the comment in quotes.\n"
                "QUERY is a fingerprint prefix or a substring of a comment;\n"
                "without it the whole keyring is listed.\n");
            return 0;
        }
        return 2;
    }
    if (optind < argc)
        q = argv[optind];
    if (nox_keyring_list(stdout, q) < 0)
        die();
    return 0;
}

static int
cmd_export(int argc, char **argv)
{
    const char *out_path = NULL, *query = NULL;
    int armor = 0, secret = 0, c;
    FILE *out;
    int out_open = 0;

    static const struct option opts[] = {
        { "secret", no_argument,       0, 's' },
        { "armor",  no_argument,       0, 'a' },
        { "output", required_argument, 0, 'o' },
        { "help",   no_argument,       0, 'h' },
        { 0, 0, 0, 0 }
    };
    optind = 1;
    while ((c = getopt_long(argc, argv, "sao:h", opts, NULL)) != -1) {
        switch (c) {
        case 's': secret = 1; break;
        case 'a': armor = 1; break;
        case 'o': out_path = optarg; break;
        case 'h':
            fprintf(stdout,
                "Usage: nox export [-s] [-a] [-o FILE] FINGERPRINT\n"
                "\n"
                "  -s, --secret        export the secret key\n"
                "  -a, --armor         armor the output\n"
                "  -o, --output FILE   write to FILE instead of stdout\n"
                "\n"
                "An exported secret key is still locked with its passphrase, so\n"
                "the file is safe to copy around as long as the passphrase is.\n");
            return 0;
        default:
            return 2;
        }
    }
    if (optind >= argc) {
        nox_seterr("missing fingerprint");
        die();
    }
    query = argv[optind];
    out = open_out(out_path, &out_open, secret ? NOX_OUT_SECRET : NOX_OUT_DATA);
    if (out == NULL)
        die();
    if (refuse_binary(armor, out) < 0)
        die();
    if (secret) {
        uint8_t *blob = NULL, fp[NOX_FP_LEN];
        size_t n = 0;
        if (nox_keyring_load_sec_blob(query, &blob, &n, fp) < 0)
            die();
        if (emit_blob(out, blob, n, armor, NOX_KIND_SEC) < 0) {
            nox_wipe(blob, n);
            free(blob);
            die();
        }
        nox_wipe(blob, n);
        free(blob);
    } else {
        nox_ident id;
        uint8_t *blob = NULL;
        size_t n = 0;
        nox_ident_init(&id);
        if (nox_keyring_load_pub(query, &id) < 0)
            die();
        if (nox_ident_public_blob(&id, &blob, &n) < 0) {
            nox_ident_wipe(&id);
            die();
        }
        if (emit_blob(out, blob, n, armor, NOX_KIND_PUB) < 0) {
            nox_ident_wipe(&id);
            free(blob);
            die();
        }
        nox_ident_wipe(&id);
        free(blob);
    }
    if (finish_out(out, out_open) < 0)
        die();
    return 0;
}

static int
cmd_import(int argc, char **argv)
{
    const char *path = NULL, *passfile = NULL;
    uint8_t *buf = NULL, *raw = NULL;
    size_t n = 0, rn = 0;
    uint16_t type;
    int c;
    char hex[65];

    static const struct option opts[] = {
        { "passphrase-file", required_argument, 0, 'F' },
        { "help",            no_argument,       0, 'h' },
        { 0, 0, 0, 0 }
    };
    optind = 1;
    while ((c = getopt_long(argc, argv, "F:h", opts, NULL)) != -1) {
        switch (c) {
        case 'F': passfile = optarg; break;
        case 'h':
            fprintf(stdout,
                "Usage: nox import [-F FILE] FILE\n"
                "\n"
                "  -F, --passphrase-file FILE  read the passphrase from FILE\n"
                "\n"
                "Imports a public or a secret key.  A secret key is unlocked\n"
                "first, so a wrong passphrase fails before anything is written.\n"
                "The fingerprint is printed on stdout.\n");
            return 0;
        default:
            return 2;
        }
    }
    if (optind >= argc) {
        nox_seterr("missing file");
        die();
    }
    path = argv[optind];
    if (nox_read_file(path, &buf, &n, NOX_MAX_BLOB) < 0)
        die();
    if (nox_unwrap_blob(&raw, &rn, buf, n) < 0) {
        free(buf);
        die();
    }
    free(buf);
    if (nox_first_packet(raw, rn, &type) < 0) {
        free(raw);
        die();
    }
    if (type == NOX_PKT_IDENTITY) {
        nox_ident id;
        char algs[160];

        nox_ident_init(&id);
        if (nox_ident_parse(&id, raw, rn) < 0) {
            free(raw);
            die();
        }
        if (nox_keyring_store_pub(&id) < 0) {
            nox_ident_wipe(&id);
            free(raw);
            die();
        }
        nox_hex(hex, id.fp, NOX_FP_LEN);
        nox_ident_alg_list(&id, algs, sizeof algs);
        fprintf(stderr, "nox: imported %s: %s\n", nox_ident_profile(&id), algs);
        nox_ident_wipe(&id);
        printf("%s\n", hex);
        free(raw);
        return 0;
    }
    if (type == NOX_PKT_SECRET) {
        nox_ident id;
        char pass[NOX_PASS_MAX + 1];
        char algs[160];
        uint8_t *pub = NULL;
        size_t pn = 0;
        nox_ident_init(&id);
        if (get_pass(pass, sizeof pass, 0, passfile) < 0) {
            free(raw);
            die();
        }
        if (nox_secret_unlock(&id, raw, rn, pass, strlen(pass)) < 0) {
            nox_wipe(pass, sizeof pass);
            free(raw);
            die();
        }
        nox_wipe(pass, sizeof pass);
        if (nox_ident_public_blob(&id, &pub, &pn) < 0) {
            nox_ident_wipe(&id);
            free(raw);
            die();
        }
        if (nox_keyring_store_pub(&id) < 0 ||
            nox_keyring_store_sec(id.fp, raw, rn) < 0) {
            nox_ident_wipe(&id);
            free(pub);
            free(raw);
            die();
        }
        nox_hex(hex, id.fp, NOX_FP_LEN);
        nox_ident_alg_list(&id, algs, sizeof algs);
        fprintf(stderr, "nox: imported %s: %s\n", nox_ident_profile(&id), algs);
        nox_ident_wipe(&id);
        free(pub);
        free(raw);
        printf("%s\n", hex);
        return 0;
    }
    free(raw);
    nox_seterr("file is neither a public nor a secret key");
    die();
    return 1;
}

static int
cmd_delete(int argc, char **argv)
{
    int c;

    optind = 1;
    while ((c = getopt_long(argc, argv, "h", help_only, NULL)) != -1) {
        if (c == 'h') {
            fprintf(stdout,
                "Usage: nox delete FINGERPRINT\n"
                "\n"
                "Removes both the public and the secret key.  There is no undo;\n"
                "export the secret key first if you may want it back.\n");
            return 0;
        }
        return 2;
    }
    if (optind >= argc) {
        nox_seterr("missing fingerprint");
        die();
    }
    if (nox_keyring_delete(argv[optind]) < 0)
        die();
    return 0;
}

static const char *
plural(int n)
{
    return n == 1 ? "" : "s";
}

static int
cmd_info(int argc, char **argv)
{
    nox_keyring_info st;
    char dir[4096];
    int c, have_home;

    optind = 1;
    while ((c = getopt_long(argc, argv, "h", help_only, NULL)) != -1) {
        if (c == 'h') {
            fprintf(stdout,
                "Usage: nox info\n"
                "\n"
                "Prints the version, the author, the algorithms this build\n"
                "knows, and what is in the keyring.\n");
            return 0;
        }
        return 2;
    }

    printf("nox %s\n\n", NOX_VERSION);
    printf("  format      NOX v1, magic 4e 4f 58 01\n");
    printf("  algorithms  Ed25519, ML-DSA-44, X25519, ML-KEM-768\n");
    printf("  profiles    hybrid (all four), ecc (Ed25519 + X25519),\n");
    printf("              pqc (ML-DSA-44 + ML-KEM-768)\n");
    printf("  crypto      XChaCha20-Poly1305, BLAKE2b, Argon2id "
           "(t=%u, m=%u KiB, p=%u)\n",
           NOX_ARGON2_T, NOX_ARGON2_M, NOX_ARGON2_P);

    have_home = nox_keyring_dir(dir, sizeof dir) == 0 &&
                nox_keyring_stats(&st) == 0;
    if (have_home) {
        printf("  keyring     %s\n", dir);
        printf("              %d public key%s, %d secret key%s\n",
               st.pub, plural(st.pub), st.sec, plural(st.sec));
    } else {
        printf("  keyring     unavailable (%s)\n", nox_err);
    }
    printf("\nThe manual page is installed as nox(1).\n");
    return 0;
}

int
main(int argc, char **argv)
{
    char **av;
    int ac, i, n;
    const char *cmd;

    av = malloc((size_t)(argc + 1) * sizeof *av);
    if (av == NULL) {
        fprintf(stderr, "nox: out of memory\n");
        return 1;
    }
    av[0] = argv[0];
    n = 1;

    /*
     * Global options come before the command.  The first argument
     * that is not one of them ends the scan, so "nox gen --help"
     * reaches gen's own help instead of printing the summary.
     */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--faketime") == 0) {
            char *e = NULL;
            long long ts;
            if (i + 1 >= argc) {
                fprintf(stderr, "nox: --faketime needs a unix timestamp\n");
                free(av);
                return 2;
            }
            ts = strtoll(argv[++i], &e, 10);
            if (e == argv[i] || *e != 0 || ts < 0) {
                fprintf(stderr, "nox: invalid timestamp\n");
                free(av);
                return 2;
            }
            nox_set_faketime((int64_t)ts);
            continue;
        }
        if (strcmp(argv[i], "--home") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "nox: --home needs a directory\n");
                free(av);
                return 2;
            }
            nox_set_home(argv[++i]);
            continue;
        }
        if (strcmp(argv[i], "--version") == 0) {
            printf("nox %s\n", noxcrypt_version());
            free(av);
            return 0;
        }
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(stdout);
            free(av);
            return 0;
        }
        break;
    }
    for (; i < argc; i++)
        av[n++] = argv[i];
    av[n] = NULL;
    ac = n;
    if (ac < 2) {
        usage(stderr);
        free(av);
        return 2;
    }
    cmd = av[1];
    {
        int rc;
        if (strcmp(cmd, "gen") == 0)
            rc = cmd_gen(ac - 1, av + 1);
        else if (strcmp(cmd, "encrypt") == 0)
            rc = cmd_encrypt(ac - 1, av + 1);
        else if (strcmp(cmd, "decrypt") == 0)
            rc = cmd_decrypt(ac - 1, av + 1);
        else if (strcmp(cmd, "sign") == 0)
            rc = cmd_sign(ac - 1, av + 1);
        else if (strcmp(cmd, "verify") == 0)
            rc = cmd_verify(ac - 1, av + 1);
        else if (strcmp(cmd, "list") == 0)
            rc = cmd_list(ac - 1, av + 1);
        else if (strcmp(cmd, "export") == 0)
            rc = cmd_export(ac - 1, av + 1);
        else if (strcmp(cmd, "import") == 0)
            rc = cmd_import(ac - 1, av + 1);
        else if (strcmp(cmd, "delete") == 0)
            rc = cmd_delete(ac - 1, av + 1);
        else if (strcmp(cmd, "info") == 0)
            rc = cmd_info(ac - 1, av + 1);
        else if (strcmp(cmd, "help") == 0) {
            usage(stdout);
            rc = 0;
        } else {
            fprintf(stderr, "nox: unknown command '%s'\n", cmd);
            usage(stderr);
            rc = 2;
        }
        free(av);
        return rc;
    }
}
