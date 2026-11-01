#define _GNU_SOURCE

#include "passphrase.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static struct termios saved_term;
static int saved_fd = -1;
static volatile sig_atomic_t got_sig;
static const int catch_sigs[] = {
    SIGINT, SIGHUP, SIGTERM, SIGQUIT, SIGTSTP, SIGTTIN, SIGTTOU, SIGPIPE, SIGALRM
};
static struct sigaction old_sa[9];

static void
restore_tty(void)
{
    if (saved_fd >= 0) {
        tcsetattr(saved_fd, TCSAFLUSH, &saved_term);
        saved_fd = -1;
    }
}

static void
on_sig(int sig)
{
    got_sig = sig;
}

static void
install_sigs(void)
{
    struct sigaction sa;
    size_t i;

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sig;
    sigemptyset(&sa.sa_mask);
    for (i = 0; i < sizeof catch_sigs / sizeof catch_sigs[0]; i++)
        sigaction(catch_sigs[i], &sa, &old_sa[i]);
}

static void
restore_sigs(void)
{
    size_t i;

    for (i = 0; i < sizeof catch_sigs / sizeof catch_sigs[0]; i++)
        sigaction(catch_sigs[i], &old_sa[i], NULL);
}

int
nox_read_passphrase(char *buf, size_t n, const char *prompt)
{
    int fd, tty = 1;
    FILE *fp;
    struct termios t;
    size_t i;
    int rc = -1;

    if (n < 2)
        return nox_seterr("passphrase buffer too small");
    got_sig = 0;

    fd = open("/dev/tty", O_RDWR);
    if (fd < 0) {
        fd = STDIN_FILENO;
        tty = isatty(fd);
        if (!tty)
            return nox_seterr("no terminal for passphrase prompt (use --passphrase-file)");
        fp = stdin;
    } else {
        fp = fdopen(fd, "r+");
        if (fp == NULL) {
            close(fd);
            return nox_seterr("fdopen: %s", strerror(errno));
        }
    }

    if (tcgetattr(fd, &saved_term) < 0) {
        if (fp != stdin)
            fclose(fp);
        else if (fd != STDIN_FILENO)
            close(fd);
        return nox_seterr("tcgetattr: %s", strerror(errno));
    }
    t = saved_term;
    t.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
    saved_fd = fd;
    install_sigs();
    if (tcsetattr(fd, TCSAFLUSH, &t) < 0) {
        restore_sigs();
        saved_fd = -1;
        if (fp != stdin)
            fclose(fp);
        return nox_seterr("tcsetattr: %s", strerror(errno));
    }

    if (write(fd, prompt, strlen(prompt)) < 0) {
        /* still try to read */
    }

    i = 0;
    for (;;) {
        char c;
        ssize_t r;
        if (got_sig)
            break;
        r = read(fd, &c, 1);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            nox_seterr("read passphrase: %s", strerror(errno));
            goto done;
        }
        if (r == 0)
            break;
        if (c == '\n' || c == '\r')
            break;
        if (i + 1 >= n) {
            nox_wipe(buf, n);
            nox_seterr("passphrase too long");
            goto done;
        }
        buf[i++] = c;
    }
    buf[i] = 0;
    if (write(fd, "\n", 1) < 0) {
        /* echo the newline; failure does not affect the passphrase */
    }
    if (got_sig)
        nox_seterr("interrupted");
    else
        rc = 0;
done:
    restore_tty();
    restore_sigs();
    nox_wipe(&t, sizeof t);
    if (fp != stdin)
        fclose(fp); /* closes fd */
    if (got_sig) {
        int s = got_sig;
        nox_wipe(buf, n);
        raise(s);
        return -1;
    }
    return rc;
}

int
nox_confirm_passphrase(char *buf, size_t n)
{
    char again[NOX_PASS_MAX + 1];
    size_t a, b;
    uint8_t d = 0;
    size_t i, m;
    int rc;

    if (nox_read_passphrase(buf, n, "Passphrase: ") < 0)
        return -1;
    if (buf[0] == 0) {
        nox_wipe(buf, n);
        return nox_seterr("empty passphrase");
    }
    if (nox_read_passphrase(again, sizeof again, "Confirm passphrase: ") < 0) {
        nox_wipe(buf, n);
        return -1;
    }
    a = strlen(buf);
    b = strlen(again);
    m = a < b ? a : b;
    for (i = 0; i < m; i++)
        d |= (uint8_t)(buf[i] ^ again[i]);
    if (a != b)
        d = 1;
    nox_wipe(again, sizeof again);
    rc = (d == 0) ? 0 : nox_seterr("passphrases do not match");
    if (rc < 0)
        nox_wipe(buf, n);
    return rc;
}

int
nox_read_passfile(char *buf, size_t n, const char *path)
{
    FILE *fp;
    size_t i = 0;
    int c = EOF;

    if (n < 2)
        return nox_seterr("passphrase buffer too small");
    fp = fopen(path, "r");
    if (fp == NULL)
        return nox_seterr("open %s: %s", path, strerror(errno));
    while (i + 1 < n) {
        c = fgetc(fp);
        if (c == EOF || c == '\n' || c == '\r')
            break;
        buf[i++] = (char)c;
    }
    if (i + 1 >= n && c != EOF && c != '\n' && c != '\r') {
        /* the buffer filled up: the next byte decides truncation */
        c = fgetc(fp);
        if (c != EOF && c != '\n' && c != '\r') {
            nox_wipe(buf, n);
            fclose(fp);
            return nox_seterr("passphrase in %s is longer than %d bytes",
                              path, (int)n - 1);
        }
    }
    buf[i] = 0;
    fclose(fp);
    if (i == 0) {
        nox_wipe(buf, n);
        return nox_seterr("empty passphrase file");
    }
    return 0;
}
