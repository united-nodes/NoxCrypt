// Known-answer tests for ML-KEM-768 and ML-DSA-44 against the NIST ACVP
// vectors stored under tests/vectors. See doc/TESTING.md for the origin
// of those files and how to regenerate them.
//
// Usage: test_kat [vector-directory]

#include "../ncrypt-pqc.h"
#include "utils.h"

static char path_buf[4096];

static const char *vec_path(const char *dir, const char *name)
{
	snprintf(path_buf, sizeof path_buf, "%s/%s", dir, name);
	return path_buf;
}

////////////////
/// ML-KEM   ///
////////////////

static void kat_mlkem_keygen(const char *dir)
{
	vec_reader r;
	int n = 0;
	if (vec_open(&r, vec_path(dir, "mlkem768_keygen.txt")) != 0) {
		CHECK(0, "cannot read vectors");
		return;
	}
	while (vec_next(&r)) {
		uint8_t seed[64], ek[1184], dk[2400], pk[1184], sk[2400];
		uint8_t zero[64] = {0};
		if (vec_hex(&r, "d", seed,      32) || vec_hex(&r, "z", seed + 32, 32) ||
		    vec_hex(&r, "ek", ek, sizeof ek) || vec_hex(&r, "dk", dk, sizeof dk)) {
			CHECK(0, "malformed record");
			continue;
		}
		ncrypt_mlkem768_key_pair(sk, pk, seed);
		CHECK(memcmp(pk, ek, sizeof ek) == 0, "keygen %s: public key", vec_get(&r, "count"));
		CHECK(memcmp(sk, dk, sizeof dk) == 0, "keygen %s: secret key", vec_get(&r, "count"));
		CHECK(memcmp(seed, zero, sizeof zero) == 0, "keygen %s: seed not wiped", vec_get(&r, "count"));
		n++;
	}
	vec_close(&r);
	CHECK(n == 25, "expected 25 ML-KEM keygen vectors, ran %d", n);
}

static void kat_mlkem_encap(const char *dir)
{
	vec_reader r;
	int n = 0;
	if (vec_open(&r, vec_path(dir, "mlkem768_encap.txt")) != 0) {
		CHECK(0, "cannot read vectors");
		return;
	}
	while (vec_next(&r)) {
		uint8_t ek[1184], m[32], c[1088], k[32], ct[1088], ss[32];
		if (vec_hex(&r, "ek", ek, sizeof ek) || vec_hex(&r, "m", m, sizeof m) ||
		    vec_hex(&r, "c", c, sizeof c)    || vec_hex(&r, "k", k, sizeof k)) {
			CHECK(0, "malformed record");
			continue;
		}
		CHECK(ncrypt_mlkem768_encapsulate(ct, ss, ek, m) == 0, "encap %s: rejected valid key", vec_get(&r, "count"));
		CHECK(memcmp(ct, c, sizeof c) == 0, "encap %s: ciphertext", vec_get(&r, "count"));
		CHECK(memcmp(ss, k, sizeof k) == 0, "encap %s: shared secret", vec_get(&r, "count"));
		n++;
	}
	vec_close(&r);
	CHECK(n == 25, "expected 25 ML-KEM encap vectors, ran %d", n);
}

static void kat_mlkem_decap(const char *dir)
{
	vec_reader r;
	int n = 0;
	if (vec_open(&r, vec_path(dir, "mlkem768_decap.txt")) != 0) {
		CHECK(0, "cannot read vectors");
		return;
	}
	while (vec_next(&r)) {
		uint8_t dk[2400], c[1088], k[32], ss[32];
		if (vec_hex(&r, "dk", dk, sizeof dk) || vec_hex(&r, "c", c, sizeof c) ||
		    vec_hex(&r, "k", k, sizeof k)) {
			CHECK(0, "malformed record");
			continue;
		}
		CHECK(ncrypt_mlkem768_decapsulate(ss, c, dk) == 0, "decap %s: rejected valid key", vec_get(&r, "count"));
		// Both the valid case and the implicit-rejection case must
		// reproduce the expected k exactly.
		CHECK(memcmp(ss, k, sizeof k) == 0, "decap %s (%s): shared secret",
		      vec_get(&r, "count"), vec_get(&r, "reason"));
		n++;
	}
	vec_close(&r);
	CHECK(n == 10, "expected 10 ML-KEM decap vectors, ran %d", n);
}

static void kat_mlkem_keycheck(const char *dir)
{
	vec_reader r;
	int n = 0;
	// Encapsulation key check: keys with coefficients >= q are rejected.
	if (vec_open(&r, vec_path(dir, "mlkem768_ekcheck.txt")) != 0) {
		CHECK(0, "cannot read vectors");
		return;
	}
	while (vec_next(&r)) {
		uint8_t ek[1184], m[32] = {1}, ct[1088], ss[32];
		int expected;
		const char *tp = vec_get(&r, "testPassed");
		if (vec_hex(&r, "ek", ek, sizeof ek) || tp == NULL) {
			CHECK(0, "malformed record");
			continue;
		}
		expected = strcmp(tp, "true") == 0 ? 0 : -1;
		CHECK(ncrypt_mlkem768_encapsulate(ct, ss, ek, m) == expected,
		      "ekcheck %s (%s): wrong result", vec_get(&r, "count"), vec_get(&r, "reason"));
		n++;
	}
	vec_close(&r);
	CHECK(n == 10, "expected 10 ML-KEM ekcheck vectors, ran %d", n);

	// Decapsulation key check: keys with a wrong H(ek) are rejected.
	n = 0;
	if (vec_open(&r, vec_path(dir, "mlkem768_dkcheck.txt")) != 0) {
		CHECK(0, "cannot read vectors");
		return;
	}
	while (vec_next(&r)) {
		uint8_t dk[2400], c[1088] = {0}, ss[32];
		int expected;
		const char *tp = vec_get(&r, "testPassed");
		if (vec_hex(&r, "dk", dk, sizeof dk) || tp == NULL) {
			CHECK(0, "malformed record");
			continue;
		}
		expected = strcmp(tp, "true") == 0 ? 0 : -1;
		CHECK(ncrypt_mlkem768_decapsulate(ss, c, dk) == expected,
		      "dkcheck %s (%s): wrong result", vec_get(&r, "count"), vec_get(&r, "reason"));
		n++;
	}
	vec_close(&r);
	CHECK(n == 10, "expected 10 ML-KEM dkcheck vectors, ran %d", n);
}

////////////////
/// ML-DSA   ///
////////////////

static void kat_mldsa_keygen(const char *dir)
{
	vec_reader r;
	int n = 0;
	if (vec_open(&r, vec_path(dir, "mldsa44_keygen.txt")) != 0) {
		CHECK(0, "cannot read vectors");
		return;
	}
	while (vec_next(&r)) {
		uint8_t seed[32], pk[1312], sk[2560], pk2[1312], sk2[2560];
		if (vec_hex(&r, "seed", seed, sizeof seed) || vec_hex(&r, "pk", pk, sizeof pk) ||
		    vec_hex(&r, "sk", sk, sizeof sk)) {
			CHECK(0, "malformed record");
			continue;
		}
		ncrypt_mldsa44_key_pair(sk2, pk2, seed);
		CHECK(memcmp(pk, pk2, sizeof pk) == 0, "mldsa keygen %s: public key", vec_get(&r, "count"));
		CHECK(memcmp(sk, sk2, sizeof sk) == 0, "mldsa keygen %s: secret key", vec_get(&r, "count"));
		n++;
	}
	vec_close(&r);
	CHECK(n == 25, "expected 25 ML-DSA keygen vectors, ran %d", n);
}

// The sigGen vectors cover four groups: deterministic and hedged, each
// through the "external" interface (message plus context, which is
// what the public API implements) and through the "internal"
// interface (raw message representative input without the domain
// separator). The internal interface is not exposed by libncrypt, so
// those vectors are skipped; they are kept in the file for
// completeness.
static void kat_mldsa_siggen(const char *dir)
{
	vec_reader r;
	int n = 0, skipped = 0;
	if (vec_open(&r, vec_path(dir, "mldsa44_siggen.txt")) != 0) {
		CHECK(0, "cannot read vectors");
		return;
	}
	while (vec_next(&r)) {
		uint8_t sk[2560], sig[2420], expected[2420], rnd[32];
		uint8_t *msg, *ctx;
		size_t msg_size, ctx_size;
		int deterministic;
		const char *iface = vec_get(&r, "interface");
		const char *det   = vec_get(&r, "deterministic");
		if (iface == NULL || det == NULL) {
			CHECK(0, "malformed record");
			continue;
		}
		if (strcmp(iface, "external") != 0) {
			skipped++;
			continue;
		}
		deterministic = strcmp(det, "true") == 0;
		if (vec_hex(&r, "sk", sk, sizeof sk) || vec_hex(&r, "signature", expected, sizeof expected)) {
			CHECK(0, "malformed record");
			continue;
		}
		msg = vec_hex_alloc(&r, "message", &msg_size);
		ctx = vec_hex_alloc(&r, "context", &ctx_size);
		if (deterministic) {
			CHECK(ncrypt_mldsa44_sign_deterministic(sig, sk, ctx, ctx_size, msg, msg_size) == 0,
			      "siggen %s: sign failed", vec_get(&r, "count"));
		} else {
			if (vec_hex(&r, "rnd", rnd, sizeof rnd)) {
				CHECK(0, "malformed record");
				free(msg); free(ctx);
				continue;
			}
			CHECK(ncrypt_mldsa44_sign(sig, sk, rnd, ctx, ctx_size, msg, msg_size) == 0,
			      "siggen %s: sign failed", vec_get(&r, "count"));
		}
		CHECK(memcmp(sig, expected, sizeof sig) == 0, "siggen %s (%s): signature",
		      vec_get(&r, "count"), deterministic ? "deterministic" : "hedged");
		free(msg);
		free(ctx);
		n++;
	}
	vec_close(&r);
	CHECK(n == 30, "expected 30 external ML-DSA siggen vectors, ran %d (skipped %d internal)", n, skipped);
}

static void kat_mldsa_sigver(const char *dir)
{
	vec_reader r;
	int n = 0, skipped = 0;
	if (vec_open(&r, vec_path(dir, "mldsa44_sigver.txt")) != 0) {
		CHECK(0, "cannot read vectors");
		return;
	}
	while (vec_next(&r)) {
		uint8_t pk[1312], sig[2420];
		uint8_t *msg, *ctx;
		size_t msg_size, ctx_size;
		int expected;
		const char *iface = vec_get(&r, "interface");
		const char *tp    = vec_get(&r, "testPassed");
		if (iface == NULL || tp == NULL) {
			CHECK(0, "malformed record");
			continue;
		}
		if (strcmp(iface, "external") != 0) {
			skipped++;
			continue;
		}
		if (vec_hex(&r, "pk", pk, sizeof pk) || vec_hex(&r, "signature", sig, sizeof sig)) {
			CHECK(0, "malformed record");
			continue;
		}
		msg = vec_hex_alloc(&r, "message", &msg_size);
		ctx = vec_hex_alloc(&r, "context", &ctx_size);
		expected = strcmp(tp, "true") == 0 ? 0 : -1;
		CHECK(ncrypt_mldsa44_check(sig, pk, ctx, ctx_size, msg, msg_size) == expected,
		      "sigver %s (%s): wrong result", vec_get(&r, "count"), vec_get(&r, "reason"));
		free(msg);
		free(ctx);
		n++;
	}
	vec_close(&r);
	CHECK(n == 15, "expected 15 external ML-DSA sigver vectors, ran %d (skipped %d internal)", n, skipped);
}

int main(int argc, char **argv)
{
	const char *dir = argc > 1 ? argv[1] : "tests/vectors";
	kat_mlkem_keygen(dir);
	kat_mlkem_encap(dir);
	kat_mlkem_decap(dir);
	kat_mlkem_keycheck(dir);
	kat_mldsa_keygen(dir);
	kat_mldsa_siggen(dir);
	kat_mldsa_sigver(dir);
	return test_summary("test_kat");
}
