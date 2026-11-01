// Helpers for test_classic.c, merged from the Monocypher 4.0.3 test
// helpers (tests/utils.h and tests/utils.c), which are released under
// CC0-1.0 with a BSD-2-Clause fallback (see test_classic.c).

#ifndef NCRYPT_CLASSIC_TEST_UTILS_H
#define NCRYPT_CLASSIC_TEST_UTILS_H

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>

typedef int8_t   i8;
typedef uint8_t  u8;
typedef uint32_t u32;
typedef int32_t  i32;
typedef int64_t  i64;
typedef uint64_t u64;

#define FOR(i, start, end) for (size_t i = (start); i < (end); i++)
#define RANDOM_INPUT(name, size) u8 name[size]; p_random(name, size)
#define ASSERT(condition) do {	\
		if (!(condition)) { \
			fprintf(stderr, "Assert failure(%s, %d): %s\n", \
			        __FILE__, __LINE__, #condition); \
			exit(1); \
		} \
	} while (0)
#define ASSERT_EQUAL(a, b, size)     ASSERT(memcmp(a, b, size) == 0)
#define ASSERT_DIFFERENT(a, b, size) ASSERT(memcmp(a, b, size) != 0)
#define ASSERT_OK(exp)               ASSERT((exp) == 0)
#define ASSERT_KO(exp)               ASSERT((exp) != 0)


typedef struct {
	u8     *buf;
	size_t  size;
} vector;

typedef struct {
	const char **next;
	size_t       size;
	vector       inputs[10];
	size_t       nb_inputs;
	vector       expected;
	vector       out;
} vector_reader;

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static u32 load32_le(const u8 s[4])
{
	return
		((u32)s[0] <<  0) |
		((u32)s[1] <<  8) |
		((u32)s[2] << 16) |
		((u32)s[3] << 24);
}

static u64 load64_le(const u8 s[8])
{
	return load32_le(s) | ((u64)load32_le(s+4) << 32);
}

// Must be seeded with a nonzero value.
// Accessible from the outside so we can modify it
static u64 random_state = 12345;

// Pseudo-random 64 bit number, based on xorshift*
static u64 rand64(void)
{
	random_state ^= random_state >> 12;
	random_state ^= random_state << 25;
	random_state ^= random_state >> 27;
	return random_state * 0x2545F4914F6CDD1D; // magic constant
}

static void p_random(u8 *stream, size_t size)
{
	FOR (i, 0, size) {
		stream[i] = (u8)rand64();
	}
}

static void* alloc(size_t size)
{
	if (size == 0) {
		// Some systems refuse to allocate zero bytes.
		// So we don't.  Instead, we just return a non-sensical pointer.
		// It shouldn't be dereferenced anyway.
		return NULL;
	}
	void *buf = malloc(size);
	ASSERT(buf != NULL);
	return buf;
}

static int to_num(char c)
{
	return c >= '0' && c <= '9' ? c - '0'
		:  c >= 'a' && c <= 'f' ? c - 'a' + 10
		:                         c - 'A' + 10;
}

static vector vector_of_string(const char *s)
{
	vector v;
	v.size = strlen(s) / 2;
	v.buf  = v.size == 0 ? 0 : (u8*)alloc(v.size);
	FOR (i, 0, v.size) {
		int msb = to_num(*s);  s++;
		int lsb = to_num(*s);  s++;
		v.buf[i] = (u8)(msb * 16 + lsb);
	}
	return v;
}

static vector next_input(vector_reader *reader)
{
	ASSERT(reader->size > 0);
	ASSERT(reader->nb_inputs < 10);

	const char *next = *(reader->next);
	vector *input = reader->inputs + reader->nb_inputs;
	reader->next++;
	reader->size--;
	*input = vector_of_string(next);
	reader->nb_inputs++;
	return *input;
}

static vector next_output(vector_reader *reader)
{
	ASSERT(reader->size > 0);
	ASSERT(reader->nb_inputs < 10);

	const char *next = *(reader->next);
	reader->next++;
	reader->size--;
	reader->expected = vector_of_string(next);
	reader->out.size = reader->expected.size;
	reader->out.buf  = (u8*)alloc(reader->out.size);
	return reader->out;
}

static int vector_test(void (*f)(vector_reader*),
                const char *name, size_t nb_vectors, const char *vectors[])
{
	int status = 0;
	printf("\t%s\n", name);

	vector_reader in;
	in.size = nb_vectors;
	in.next = vectors;

	while (in.size > 0) {
		in.nb_inputs = 0;
		f(&in);
		if (in.expected.size != 0) {
			status |= memcmp(in.out.buf, in.expected.buf, in.expected.size);
		}
		FOR (i, 0, in.nb_inputs) {
			free(in.inputs[i].buf);
		}
		free(in.out.buf);
		free(in.expected.buf);
	}
	return status;
}

#endif // NCRYPT_CLASSIC_TEST_UTILS_H
