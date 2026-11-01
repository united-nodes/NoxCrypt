// Shared helpers for the libncrypt test programs.

#ifndef NCRYPT_TEST_UTILS_H
#define NCRYPT_TEST_UTILS_H

// These helpers are shared by several test programs, so any one
// program uses only a subset of them.  Silence -Wunused-function once
// here rather than in every caller.  Warnings about everything else
// stay on.
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic ignored "-Wunused-function"
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Global pass/fail counters.
static int test_failures = 0;
static int test_checks   = 0;

#define CHECK(cond, ...) do {                                    \
	test_checks++;                                               \
	if (!(cond)) {                                               \
		test_failures++;                                         \
		fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);      \
		fprintf(stderr, __VA_ARGS__);                            \
		fputc('\n', stderr);                                     \
	}                                                            \
} while (0)

static int test_summary(const char *name)
{
	printf("%s: %d checks, %d failures\n", name, test_checks, test_failures);
	return test_failures == 0 ? 0 : 1;
}


// Decode a hexadecimal string. Returns the number of bytes written, or
// (size_t)-1 on malformed input or overflow of the output buffer.
static size_t from_hex(uint8_t *out, size_t out_size, const char *hex)
{
	size_t n = strlen(hex);
	size_t i;
	if (n % 2 != 0 || n / 2 > out_size) {
		return (size_t)-1;
	}
	for (i = 0; i < n; i += 2) {
		unsigned v = 0;
		size_t k;
		for (k = 0; k < 2; k++) {
			char c = hex[i + k];
			v <<= 4;
			if      (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
			else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
			else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
			else return (size_t)-1;
		}
		out[i / 2] = (uint8_t)v;
	}
	return n / 2;
}

// Deterministic pseudo-random bytes for tests that do not need
// cryptographic quality. Not for use outside the test programs.
static uint64_t test_rng_state = 0x9E3779B97F4A7C15ULL;

static void test_rng_seed(uint64_t seed)
{
	test_rng_state = seed ^ 0x9E3779B97F4A7C15ULL;
}

static uint64_t test_rng_next(void)
{
	// splitmix64
	uint64_t z = (test_rng_state += 0x9E3779B97F4A7C15ULL);
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
	z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
	return z ^ (z >> 31);
}

static void test_random(uint8_t *buf, size_t size)
{
	size_t i;
	for (i = 0; i < size; i++) {
		if (i % 8 == 0) {
			uint64_t r = test_rng_next();
			size_t j;
			for (j = 0; j < 8 && i + j < size; j++) {
				buf[i + j] = (uint8_t)(r >> (8 * j));
			}
		}
	}
}

// Minimal parser for the "key = value" vector files under tests/vectors.
// Records are separated by blank lines. Values are returned as strings
// and stay valid until the next call to vec_next().
#define VEC_MAX_FIELDS 16
#define VEC_LINE_MAX   (64 * 1024)

typedef struct {
	FILE *f;
	char *line;
	int   nfields;
	char *keys  [VEC_MAX_FIELDS];
	char *values[VEC_MAX_FIELDS];
	char *storage[VEC_MAX_FIELDS];
} vec_reader;

static int vec_open(vec_reader *r, const char *path)
{
	memset(r, 0, sizeof *r);
	r->f = fopen(path, "r");
	if (r->f == NULL) {
		fprintf(stderr, "cannot open %s\n", path);
		return -1;
	}
	r->line = (char *)malloc(VEC_LINE_MAX);
	return r->line == NULL ? -1 : 0;
}

static void vec_clear(vec_reader *r)
{
	int i;
	for (i = 0; i < r->nfields; i++) {
		free(r->storage[i]);
		r->storage[i] = NULL;
	}
	r->nfields = 0;
}

static void vec_close(vec_reader *r)
{
	vec_clear(r);
	free(r->line);
	if (r->f) fclose(r->f);
}

// Read the next record. Returns 1 if a record was read, 0 at EOF.
static int vec_next(vec_reader *r)
{
	vec_clear(r);
	while (fgets(r->line, VEC_LINE_MAX, r->f) != NULL) {
		char *eq, *key, *val, *end;
		size_t len = strlen(r->line);
		while (len > 0 && (r->line[len-1] == '\n' || r->line[len-1] == '\r')) {
			r->line[--len] = 0;
		}
		if (len == 0) {
			if (r->nfields > 0) return 1;
			continue;
		}
		eq = strchr(r->line, '=');
		if (eq == NULL || r->nfields == VEC_MAX_FIELDS) {
			continue;
		}
		*eq = 0;
		key = r->line;
		val = eq + 1;
		while (*val == ' ') val++;
		end = key + strlen(key);
		while (end > key && end[-1] == ' ') *--end = 0;
		{
			size_t klen = strlen(key), vlen = strlen(val);
			char *st = (char *)malloc(klen + vlen + 2);
			if (st == NULL) abort();
			memcpy(st, key, klen + 1);
			memcpy(st + klen + 1, val, vlen + 1);
			r->storage[r->nfields] = st;
			r->keys   [r->nfields] = st;
			r->values [r->nfields] = st + klen + 1;
			r->nfields++;
		}
	}
	return r->nfields > 0 ? 1 : 0;
}

static const char *vec_get(const vec_reader *r, const char *key)
{
	int i;
	for (i = 0; i < r->nfields; i++) {
		if (strcmp(r->keys[i], key) == 0) return r->values[i];
	}
	return NULL;
}

// Decode a hex field into a fixed buffer, failing the test on any
// mismatch of length.
static int vec_hex(const vec_reader *r, const char *key, uint8_t *out, size_t size)
{
	const char *v = vec_get(r, key);
	size_t n;
	if (v == NULL) {
		fprintf(stderr, "missing field %s\n", key);
		return -1;
	}
	n = from_hex(out, size, v);
	if (n != size) {
		fprintf(stderr, "field %s: expected %zu bytes, got %zu\n", key, size, n);
		return -1;
	}
	return 0;
}

// Decode a variable-length hex field into a malloc'd buffer.
static uint8_t *vec_hex_alloc(const vec_reader *r, const char *key, size_t *size)
{
	const char *v = vec_get(r, key);
	uint8_t *buf;
	size_t n;
	if (v == NULL) {
		*size = 0;
		return NULL;
	}
	n = strlen(v) / 2;
	buf = (uint8_t *)malloc(n == 0 ? 1 : n);
	if (buf == NULL) abort();
	if (from_hex(buf, n, v) != n) {
		fprintf(stderr, "field %s: malformed hex\n", key);
		free(buf);
		*size = 0;
		return NULL;
	}
	*size = n;
	return buf;
}

#endif // NCRYPT_TEST_UTILS_H
