// Functional, negative, and API-contract tests for ncrypt-pqc.
//
// These tests do not depend on external vectors. They exercise every
// public function for round trips, tampering, boundary message sizes,
// seed wiping, and the documented failure behaviour (outputs untouched
// on failure, seeds wiped on every path).

#include "../ncrypt-pqc.h"
#include "utils.h"

#define KEM_PK NCRYPT_MLKEM768_PUBLIC_KEY_SIZE
#define KEM_SK NCRYPT_MLKEM768_SECRET_KEY_SIZE
#define KEM_CT NCRYPT_MLKEM768_CIPHERTEXT_SIZE
#define SIG_PK NCRYPT_MLDSA44_PUBLIC_KEY_SIZE
#define SIG_SK NCRYPT_MLDSA44_SECRET_KEY_SIZE
#define SIG_SZ NCRYPT_MLDSA44_SIGNATURE_SIZE

static int is_zero(const uint8_t *p, size_t n)
{
	uint8_t acc = 0;
	size_t i;
	for (i = 0; i < n; i++) acc |= p[i];
	return acc == 0;
}

///////////////
/// ML-KEM  ///
///////////////

static void test_mlkem_roundtrip(void)
{
	uint8_t seed[64], eseed[32], pk[KEM_PK], sk[KEM_SK], ct[KEM_CT];
	uint8_t ss1[32], ss2[32];
	int i;

	for (i = 0; i < 20; i++) {
		test_random(seed, sizeof seed);
		test_random(eseed, sizeof eseed);
		ncrypt_mlkem768_key_pair(sk, pk, seed);
		CHECK(is_zero(seed, sizeof seed), "key seed not wiped");
		CHECK(ncrypt_mlkem768_encapsulate(ct, ss1, pk, eseed) == 0, "encapsulate failed");
		CHECK(is_zero(eseed, sizeof eseed), "encapsulation seed not wiped");
		CHECK(ncrypt_mlkem768_decapsulate(ss2, ct, sk) == 0, "decapsulate failed");
		CHECK(memcmp(ss1, ss2, 32) == 0, "shared secrets differ (%d)", i);
	}
}

static void test_mlkem_determinism(void)
{
	uint8_t seed[64], seed2[64], eseed[32], eseed2[32];
	uint8_t pk[KEM_PK], sk[KEM_SK], pk2[KEM_PK], sk2[KEM_SK];
	uint8_t ct[KEM_CT], ct2[KEM_CT], ss[32], ss2[32];

	test_random(seed, sizeof seed);   memcpy(seed2, seed, sizeof seed);
	test_random(eseed, sizeof eseed); memcpy(eseed2, eseed, sizeof eseed);
	ncrypt_mlkem768_key_pair(sk, pk, seed);
	ncrypt_mlkem768_key_pair(sk2, pk2, seed2);
	CHECK(memcmp(pk, pk2, KEM_PK) == 0 && memcmp(sk, sk2, KEM_SK) == 0,
	      "key generation is not deterministic in the seed");
	CHECK(ncrypt_mlkem768_encapsulate(ct, ss, pk, eseed) == 0, "encapsulate");
	CHECK(ncrypt_mlkem768_encapsulate(ct2, ss2, pk, eseed2) == 0, "encapsulate");
	CHECK(memcmp(ct, ct2, KEM_CT) == 0 && memcmp(ss, ss2, 32) == 0,
	      "encapsulation is not deterministic in the seed");
}

static void test_mlkem_implicit_rejection(void)
{
	uint8_t seed[64], eseed[32], pk[KEM_PK], sk[KEM_SK], ct[KEM_CT];
	uint8_t ss1[32], ss2[32], ss3[32];
	size_t pos;

	test_random(seed, sizeof seed);
	test_random(eseed, sizeof eseed);
	ncrypt_mlkem768_key_pair(sk, pk, seed);
	CHECK(ncrypt_mlkem768_encapsulate(ct, ss1, pk, eseed) == 0, "encapsulate");

	// Every single-bit flip of the ciphertext must decapsulate without
	// error to a different, but deterministic, shared secret.
	for (pos = 0; pos < KEM_CT; pos += 97) {
		ct[pos] ^= 1;
		CHECK(ncrypt_mlkem768_decapsulate(ss2, ct, sk) == 0, "decapsulate returned error on bad ct");
		CHECK(memcmp(ss1, ss2, 32) != 0, "modified ciphertext gave the original secret (byte %zu)", pos);
		CHECK(ncrypt_mlkem768_decapsulate(ss3, ct, sk) == 0, "decapsulate");
		CHECK(memcmp(ss2, ss3, 32) == 0, "implicit rejection is not deterministic (byte %zu)", pos);
		ct[pos] ^= 1;
	}
	// The rejection secret must also depend on the secret key's z value.
	ct[0] ^= 1;
	CHECK(ncrypt_mlkem768_decapsulate(ss2, ct, sk) == 0, "decapsulate");
	sk[KEM_SK - 1] ^= 1;
	CHECK(ncrypt_mlkem768_decapsulate(ss3, ct, sk) == 0, "decapsulate");
	CHECK(memcmp(ss2, ss3, 32) != 0, "rejection secret does not depend on z");
}

static void test_mlkem_malformed_keys(void)
{
	uint8_t seed[64], eseed[32], pk[KEM_PK], sk[KEM_SK], ct[KEM_CT], ss[32];
	uint8_t ct_before[KEM_CT], ss_before[32];

	test_random(seed, sizeof seed);
	ncrypt_mlkem768_key_pair(sk, pk, seed);

	// Public key with a coefficient of exactly q (3329 = 0xD01). The
	// first coefficient is the low 12 bits of bytes 0 and 1.
	pk[0] = 0x01;
	pk[1] = (uint8_t)((pk[1] & 0xF0) | 0x0D);
	test_random(eseed, sizeof eseed);
	test_random(ct, sizeof ct); memcpy(ct_before, ct, sizeof ct);
	test_random(ss, sizeof ss); memcpy(ss_before, ss, sizeof ss);
	CHECK(ncrypt_mlkem768_encapsulate(ct, ss, pk, eseed) == -1, "coefficient q accepted");
	CHECK(is_zero(eseed, sizeof eseed), "seed not wiped on rejected public key");
	CHECK(memcmp(ct, ct_before, sizeof ct) == 0, "ciphertext modified on failure");
	CHECK(memcmp(ss, ss_before, sizeof ss) == 0, "shared secret modified on failure");

	// q - 1 must be accepted.
	pk[0] = 0x00;
	pk[1] = (uint8_t)((pk[1] & 0xF0) | 0x0D);
	test_random(eseed, sizeof eseed);
	CHECK(ncrypt_mlkem768_encapsulate(ct, ss, pk, eseed) == 0, "coefficient q-1 rejected");

	// Out-of-range coefficient in the last polynomial (second half of a
	// byte triple: coefficient 2i+1 is bytes 3i+1 (high nibble) and 3i+2).
	pk[3*383 + 1] |= 0xF0;
	pk[3*383 + 2]  = 0xFF;
	test_random(eseed, sizeof eseed);
	CHECK(ncrypt_mlkem768_encapsulate(ct, ss, pk, eseed) == -1, "large last coefficient accepted");

	// Secret key with a damaged public-key hash.
	test_random(seed, sizeof seed);
	ncrypt_mlkem768_key_pair(sk, pk, seed);
	test_random(eseed, sizeof eseed);
	CHECK(ncrypt_mlkem768_encapsulate(ct, ss, pk, eseed) == 0, "encapsulate");
	sk[KEM_SK - 64] ^= 0x80;
	memcpy(ss_before, ss, 32);
	CHECK(ncrypt_mlkem768_decapsulate(ss, ct, sk) == -1, "damaged H(ek) accepted");
	CHECK(memcmp(ss, ss_before, 32) == 0, "shared secret modified on failure");
	sk[KEM_SK - 64] ^= 0x80;
	// Damaged public key inside the secret key must also be caught.
	sk[KEM_SK - 64 - KEM_PK] ^= 0x01;
	CHECK(ncrypt_mlkem768_decapsulate(ss, ct, sk) == -1, "damaged embedded ek accepted");
}

///////////////
/// ML-DSA  ///
///////////////

static void test_mldsa_roundtrip(void)
{
	uint8_t seed[32], rnd[32], pk[SIG_PK], sk[SIG_SK], sig[SIG_SZ];
	uint8_t msg[4096];
	static const size_t sizes[] = {0, 1, 2, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 1000, 4096};
	size_t i;

	test_random(seed, sizeof seed);
	ncrypt_mldsa44_key_pair(sk, pk, seed);
	CHECK(is_zero(seed, sizeof seed), "seed not wiped");
	test_random(msg, sizeof msg);

	for (i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
		size_t n = sizes[i];
		const uint8_t *m = n == 0 ? NULL : msg;
		test_random(rnd, sizeof rnd);
		CHECK(ncrypt_mldsa44_sign(sig, sk, rnd, NULL, 0, m, n) == 0, "sign size %zu", n);
		CHECK(is_zero(rnd, sizeof rnd), "rnd not wiped");
		CHECK(ncrypt_mldsa44_check(sig, pk, NULL, 0, m, n) == 0, "check size %zu", n);
		CHECK(ncrypt_mldsa44_sign_deterministic(sig, sk, NULL, 0, m, n) == 0, "sign det size %zu", n);
		CHECK(ncrypt_mldsa44_check(sig, pk, NULL, 0, m, n) == 0, "check det size %zu", n);
		CHECK(ncrypt_pqc_check(sig, pk, m, n) == 0, "pqc_check det size %zu", n);
	}
}

static void test_mldsa_hedged_vs_deterministic(void)
{
	uint8_t seed[32], rnd[32], pk[SIG_PK], sk[SIG_SK];
	uint8_t s1[SIG_SZ], s2[SIG_SZ], s3[SIG_SZ];
	const uint8_t msg[] = "hedged signing test message";

	test_random(seed, sizeof seed);
	ncrypt_mldsa44_key_pair(sk, pk, seed);

	CHECK(ncrypt_mldsa44_sign_deterministic(s1, sk, NULL, 0, msg, sizeof msg) == 0, "sign");
	CHECK(ncrypt_mldsa44_sign_deterministic(s2, sk, NULL, 0, msg, sizeof msg) == 0, "sign");
	CHECK(memcmp(s1, s2, SIG_SZ) == 0, "deterministic signing is not deterministic");

	// Hedged with rnd = 0 must equal the deterministic variant.
	memset(rnd, 0, sizeof rnd);
	CHECK(ncrypt_mldsa44_sign(s3, sk, rnd, NULL, 0, msg, sizeof msg) == 0, "sign");
	CHECK(memcmp(s1, s3, SIG_SZ) == 0, "hedged with zero rnd differs from deterministic");

	// Different rnd gives a different but valid signature.
	test_random(rnd, sizeof rnd);
	CHECK(ncrypt_mldsa44_sign(s3, sk, rnd, NULL, 0, msg, sizeof msg) == 0, "sign");
	CHECK(memcmp(s1, s3, SIG_SZ) != 0, "hedged signature equals deterministic one");
	CHECK(ncrypt_mldsa44_check(s3, pk, NULL, 0, msg, sizeof msg) == 0, "hedged signature invalid");

	// High-level wrappers.
	test_random(rnd, sizeof rnd);
	ncrypt_pqc_sign(s3, sk, rnd, msg, sizeof msg);
	CHECK(is_zero(rnd, sizeof rnd), "rnd not wiped by ncrypt_pqc_sign");
	CHECK(ncrypt_pqc_check(s3, pk, msg, sizeof msg) == 0, "ncrypt_pqc_check");
}

static void test_mldsa_context(void)
{
	uint8_t seed[32], pk[SIG_PK], sk[SIG_SK], sig[SIG_SZ], sig_before[SIG_SZ];
	uint8_t ctx[256], rnd[32];
	const uint8_t msg[] = "context test";

	test_random(seed, sizeof seed);
	ncrypt_mldsa44_key_pair(sk, pk, seed);
	test_random(ctx, sizeof ctx);

	CHECK(ncrypt_mldsa44_sign_deterministic(sig, sk, ctx, 5, msg, sizeof msg) == 0, "sign ctx");
	CHECK(ncrypt_mldsa44_check(sig, pk, ctx, 5, msg, sizeof msg) == 0, "check ctx");
	CHECK(ncrypt_mldsa44_check(sig, pk, ctx, 4, msg, sizeof msg) == -1, "shorter ctx accepted");
	CHECK(ncrypt_mldsa44_check(sig, pk, ctx, 6, msg, sizeof msg) == -1, "longer ctx accepted");
	CHECK(ncrypt_mldsa44_check(sig, pk, NULL, 0, msg, sizeof msg) == -1, "empty ctx accepted");
	ctx[2] ^= 1;
	CHECK(ncrypt_mldsa44_check(sig, pk, ctx, 5, msg, sizeof msg) == -1, "modified ctx accepted");
	ctx[2] ^= 1;

	// Maximum context length is accepted, one more is rejected without
	// touching the signature buffer, and rnd is still wiped.
	CHECK(ncrypt_mldsa44_sign_deterministic(sig, sk, ctx, 255, msg, sizeof msg) == 0, "255-byte ctx rejected");
	CHECK(ncrypt_mldsa44_check(sig, pk, ctx, 255, msg, sizeof msg) == 0, "255-byte ctx check");
	memcpy(sig_before, sig, sizeof sig);
	test_random(rnd, sizeof rnd);
	CHECK(ncrypt_mldsa44_sign(sig, sk, rnd, ctx, 256, msg, sizeof msg) == -1, "256-byte ctx accepted");
	CHECK(memcmp(sig, sig_before, sizeof sig) == 0, "signature modified on failure");
	CHECK(is_zero(rnd, sizeof rnd), "rnd not wiped on failure");
	CHECK(ncrypt_mldsa44_sign_deterministic(sig, sk, ctx, 256, msg, sizeof msg) == -1, "256-byte ctx accepted");
	CHECK(ncrypt_mldsa44_check(sig, pk, ctx, 256, msg, sizeof msg) == -1, "256-byte ctx verified");
}

static void test_mldsa_tamper(void)
{
	uint8_t seed[32], pk[SIG_PK], sk[SIG_SK], sig[SIG_SZ];
	uint8_t msg[300];
	size_t pos;

	test_random(seed, sizeof seed);
	ncrypt_mldsa44_key_pair(sk, pk, seed);
	test_random(msg, sizeof msg);
	CHECK(ncrypt_mldsa44_sign_deterministic(sig, sk, NULL, 0, msg, sizeof msg) == 0, "sign");
	CHECK(ncrypt_mldsa44_check(sig, pk, NULL, 0, msg, sizeof msg) == 0, "check");

	// Flip one bit at a spread of positions covering c~, z, and h.
	for (pos = 0; pos < SIG_SZ; pos += 53) {
		sig[pos] ^= 0x10;
		CHECK(ncrypt_mldsa44_check(sig, pk, NULL, 0, msg, sizeof msg) == -1,
		      "modified signature byte %zu accepted", pos);
		sig[pos] ^= 0x10;
	}
	// Hint encoding malleability: reorder two hint indices, or add a
	// non-zero byte in the unused hint area. FIPS 204 requires both to
	// be rejected.
	{
		uint8_t saved[SIG_SZ];
		unsigned hint_base = 32 + 4*576;   // start of the hint vector
		unsigned count = sig[hint_base + 80]; // hints in polynomial 0
		memcpy(saved, sig, SIG_SZ);
		if (count >= 2) {
			uint8_t t = sig[hint_base]; sig[hint_base] = sig[hint_base + 1]; sig[hint_base + 1] = t;
			CHECK(ncrypt_mldsa44_check(sig, pk, NULL, 0, msg, sizeof msg) == -1, "reordered hints accepted");
			memcpy(sig, saved, SIG_SZ);
		}
		{
			unsigned total = sig[hint_base + 83];
			if (total < 80) {
				sig[hint_base + total] = 1;
				CHECK(ncrypt_mldsa44_check(sig, pk, NULL, 0, msg, sizeof msg) == -1, "garbage in unused hint area accepted");
				memcpy(sig, saved, SIG_SZ);
			}
		}
	}
	// Modified message, truncated message, wrong key.
	msg[100] ^= 1;
	CHECK(ncrypt_mldsa44_check(sig, pk, NULL, 0, msg, sizeof msg) == -1, "modified message accepted");
	msg[100] ^= 1;
	CHECK(ncrypt_mldsa44_check(sig, pk, NULL, 0, msg, sizeof msg - 1) == -1, "truncated message accepted");
	pk[40] ^= 1;
	CHECK(ncrypt_mldsa44_check(sig, pk, NULL, 0, msg, sizeof msg) == -1, "wrong public key accepted");
	pk[40] ^= 1;
	CHECK(ncrypt_mldsa44_check(sig, pk, NULL, 0, msg, sizeof msg) == 0, "restored state fails");
}

//////////////////////
/// Hybrid scheme  ///
//////////////////////

static void test_hybrid_roundtrip(void)
{
	uint8_t seed[64], eseed[32], pk[KEM_PK], sk[KEM_SK];
	uint8_t kem_ct[KEM_CT], mac[16];
	uint8_t pt[5000], ct[5000], out[5000], ad[64];
	static const size_t sizes[] = {0, 1, 63, 64, 65, 1000, 5000};
	size_t i;

	test_random(seed, sizeof seed);
	ncrypt_pqc_key_pair(sk, pk, seed);
	test_random(pt, sizeof pt);
	test_random(ad, sizeof ad);

	for (i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
		size_t n = sizes[i];
		const uint8_t *p = n == 0 ? NULL : pt;
		uint8_t *c = n == 0 ? NULL : ct;
		uint8_t *o = n == 0 ? NULL : out;
		test_random(eseed, sizeof eseed);
		CHECK(ncrypt_pqc_encrypt(c, mac, kem_ct, pk, eseed, ad, sizeof ad, p, n) == 0, "encrypt %zu", n);
		CHECK(is_zero(eseed, sizeof eseed), "seed not wiped");
		if (n > 0) CHECK(memcmp(ct, pt, n) != 0, "ciphertext equals plaintext");
		CHECK(ncrypt_pqc_decrypt(o, kem_ct, mac, sk, ad, sizeof ad, c, n) == 0, "decrypt %zu", n);
		if (n > 0) CHECK(memcmp(out, pt, n) == 0, "plaintext mismatch %zu", n);
		// Without associated data.
		test_random(eseed, sizeof eseed);
		CHECK(ncrypt_pqc_encrypt(c, mac, kem_ct, pk, eseed, NULL, 0, p, n) == 0, "encrypt no-ad %zu", n);
		CHECK(ncrypt_pqc_decrypt(o, kem_ct, mac, sk, NULL, 0, c, n) == 0, "decrypt no-ad %zu", n);
		if (n > 0) CHECK(memcmp(out, pt, n) == 0, "plaintext mismatch no-ad %zu", n);
	}
}

static void test_hybrid_in_place(void)
{
	uint8_t seed[64], eseed[32], pk[KEM_PK], sk[KEM_SK], kem_ct[KEM_CT], mac[16];
	uint8_t buf[777], copy[777];

	test_random(seed, sizeof seed);
	ncrypt_pqc_key_pair(sk, pk, seed);
	test_random(buf, sizeof buf);
	memcpy(copy, buf, sizeof buf);
	test_random(eseed, sizeof eseed);
	CHECK(ncrypt_pqc_encrypt(buf, mac, kem_ct, pk, eseed, NULL, 0, buf, sizeof buf) == 0, "encrypt in place");
	CHECK(memcmp(buf, copy, sizeof buf) != 0, "in-place encryption did nothing");
	CHECK(ncrypt_pqc_decrypt(buf, kem_ct, mac, sk, NULL, 0, buf, sizeof buf) == 0, "decrypt in place");
	CHECK(memcmp(buf, copy, sizeof buf) == 0, "in-place round trip mismatch");
}

// Failure atomicity in place.  The tamper test above decrypts into a
// buffer separate from the ciphertext, which never exercises the case
// where plain_text and cipher_text are the same memory.  That is the
// case an application is most likely to use, and the one where a
// partially written plaintext would be indistinguishable from a
// successful decryption of garbage.
static void test_hybrid_tamper_in_place(void)
{
	uint8_t seed[64], eseed[32], pk[KEM_PK], sk[KEM_SK], kem_ct[KEM_CT], mac[16];
	uint8_t buf[515], copy[515], ad[24];

	test_random(seed, sizeof seed);
	ncrypt_pqc_key_pair(sk, pk, seed);
	test_random(buf, sizeof buf);
	test_random(ad, sizeof ad);
	test_random(eseed, sizeof eseed);
	CHECK(ncrypt_pqc_encrypt(buf, mac, kem_ct, pk, eseed, ad, sizeof ad,
	                         buf, sizeof buf) == 0, "encrypt in place");
	memcpy(copy, buf, sizeof copy);    // the ciphertext, as transmitted

	// Every one of these must fail *and* leave the ciphertext intact.
	buf[0] ^= 1;
	CHECK(ncrypt_pqc_decrypt(buf, kem_ct, mac, sk, ad, sizeof ad, buf, sizeof buf) == -1,
	      "in-place decrypt accepted a modified ciphertext");
	buf[0] ^= 1;
	CHECK(memcmp(buf, copy, sizeof buf) == 0, "in-place failure damaged the input");

	mac[0] ^= 1;
	CHECK(ncrypt_pqc_decrypt(buf, kem_ct, mac, sk, ad, sizeof ad, buf, sizeof buf) == -1,
	      "in-place decrypt accepted a modified tag");
	mac[0] ^= 1;
	CHECK(memcmp(buf, copy, sizeof buf) == 0, "in-place tag failure damaged the input");

	kem_ct[0] ^= 1;
	CHECK(ncrypt_pqc_decrypt(buf, kem_ct, mac, sk, ad, sizeof ad, buf, sizeof buf) == -1,
	      "in-place decrypt accepted a modified encapsulation");
	kem_ct[0] ^= 1;
	CHECK(memcmp(buf, copy, sizeof buf) == 0, "in-place kem_ct failure damaged the input");

	ad[0] ^= 1;
	CHECK(ncrypt_pqc_decrypt(buf, kem_ct, mac, sk, ad, sizeof ad, buf, sizeof buf) == -1,
	      "in-place decrypt accepted modified associated data");
	ad[0] ^= 1;
	CHECK(memcmp(buf, copy, sizeof buf) == 0, "in-place ad failure damaged the input");

	// And the untouched record still decrypts.
	CHECK(ncrypt_pqc_decrypt(buf, kem_ct, mac, sk, ad, sizeof ad, buf, sizeof buf) == 0,
	      "in-place decrypt failed on the restored record");
}

// The documented contract for every verifier is "0 or -1", and callers
// are told to test against -1.  Anything else -- a -2, a positive
// value -- would read as success to such a caller.
static void test_verdict_is_zero_or_minus_one(void)
{
	uint8_t seed[64], sk[KEM_SK], pk[KEM_PK], kem_ct[KEM_CT], mac[16];
	uint8_t msg[32], sig[SIG_SZ], sig2[SIG_SZ], pt[32];
	uint8_t spk[SIG_PK], ssk[SIG_SK];
	uint8_t eseed[32], tpk[KEM_PK];
	int r;

	test_random(seed, sizeof seed);
	ncrypt_pqc_key_pair(sk, pk, seed);
	test_random(seed, sizeof seed);
	ncrypt_pqc_sign_key_pair(ssk, spk, seed);
	test_random(msg, sizeof msg);
	test_random(seed, sizeof seed);
	ncrypt_pqc_sign(sig, ssk, seed, msg, sizeof msg);

	// Signature: success, and a dozen distinct ways to fail.
	r = ncrypt_pqc_check(sig, spk, msg, sizeof msg);
	CHECK(r == 0, "valid signature rejected");
	memcpy(sig2, sig, sizeof sig2);
	sig2[0] ^= 1;
	CHECK(ncrypt_pqc_check(sig2, spk, msg, sizeof msg) == -1, "bad c_tilde not -1");
	sig2[0] ^= 1;
	// Out-of-range z encoding: all ones makes every coefficient too large.
	memset(sig2 + 32, 0xFF, 4 * 576);
	CHECK(ncrypt_pqc_check(sig2, spk, msg, sizeof msg) == -1, "bad z not -1");
	// Bad hint encoding: an index above omega.
	memcpy(sig2, sig, sizeof sig2);
	memset(sig2 + 32 + 4 * 576, 0, 84);
	sig2[32 + 4 * 576 + 4] = 0xFF;   // cumulative count beyond omega
	CHECK(ncrypt_pqc_check(sig2, spk, msg, sizeof msg) == -1, "bad hint not -1");
	CHECK(ncrypt_pqc_check(sig, spk, msg, sizeof msg - 1) == -1,
	      "short message not -1");

	// Hybrid decryption: same rule, on both the KEM failure path and the
	// AEAD failure path.
	test_random(eseed, sizeof eseed);
	CHECK(ncrypt_pqc_encrypt(pt, mac, kem_ct, pk, eseed, NULL, 0, msg, sizeof msg) == 0,
	      "encrypt");
	CHECK(ncrypt_pqc_decrypt(pt, kem_ct, mac, sk, NULL, 0, pt, sizeof msg) == 0,
	      "valid record rejected");
	mac[0] ^= 1;
	CHECK(ncrypt_pqc_decrypt(pt, kem_ct, mac, sk, NULL, 0, pt, sizeof msg) == -1,
	      "bad tag not -1");
	mac[0] ^= 1;
	sk[KEM_SK - 1] ^= 1;   // breaks the stored key hash
	CHECK(ncrypt_pqc_decrypt(pt, kem_ct, mac, sk, NULL, 0, pt, sizeof msg) == -1,
	      "bad secret key not -1");
	sk[KEM_SK - 1] ^= 1;

	// Encapsulation: a malformed public key must report -1.
	tpk[0] = 0xFF; tpk[1] = 0xFF;   // coefficient >= q
	CHECK(ncrypt_mlkem768_encapsulate(kem_ct, pt, tpk, eseed) == -1,
	      "malformed public key not -1");
}

static void test_hybrid_tamper(void)
{
	uint8_t seed[64], eseed[32], pk[KEM_PK], sk[KEM_SK], sk2[KEM_SK], pk2[KEM_PK];
	uint8_t kem_ct[KEM_CT], mac[16], pt[256], ct[256], out[256], canary[256], ad[16];
	size_t pos;

	test_random(seed, sizeof seed);
	ncrypt_pqc_key_pair(sk, pk, seed);
	test_random(seed, sizeof seed);
	ncrypt_pqc_key_pair(sk2, pk2, seed);
	test_random(pt, sizeof pt);
	test_random(ad, sizeof ad);
	test_random(canary, sizeof canary);
	test_random(eseed, sizeof eseed);
	CHECK(ncrypt_pqc_encrypt(ct, mac, kem_ct, pk, eseed, ad, sizeof ad, pt, sizeof pt) == 0, "encrypt");

#define EXPECT_REJECT(what) do {                                                        \
	memcpy(out, canary, sizeof out);                                                    \
	CHECK(ncrypt_pqc_decrypt(out, kem_ct, mac, sk, ad, sizeof ad, ct, sizeof ct) == -1, \
	      "%s accepted", what);                                                         \
	CHECK(memcmp(out, canary, sizeof out) == 0, "plaintext modified after %s", what);   \
} while (0)

	for (pos = 0; pos < KEM_CT; pos += 131) {
		kem_ct[pos] ^= 1; EXPECT_REJECT("modified kem_ct"); kem_ct[pos] ^= 1;
	}
	for (pos = 0; pos < 16; pos++) {
		mac[pos] ^= 0x80; EXPECT_REJECT("modified mac"); mac[pos] ^= 0x80;
	}
	for (pos = 0; pos < sizeof ct; pos += 37) {
		ct[pos] ^= 1; EXPECT_REJECT("modified ciphertext"); ct[pos] ^= 1;
	}
	ad[3] ^= 1; EXPECT_REJECT("modified ad"); ad[3] ^= 1;
	memcpy(out, canary, sizeof out);
	CHECK(ncrypt_pqc_decrypt(out, kem_ct, mac, sk, ad, sizeof ad - 1, ct, sizeof ct) == -1, "truncated ad accepted");
	CHECK(ncrypt_pqc_decrypt(out, kem_ct, mac, sk, NULL, 0, ct, sizeof ct) == -1, "missing ad accepted");
	CHECK(ncrypt_pqc_decrypt(out, kem_ct, mac, sk, ad, sizeof ad, ct, sizeof ct - 1) == -1, "truncated ciphertext accepted");
	CHECK(ncrypt_pqc_decrypt(out, kem_ct, mac, sk2, ad, sizeof ad, ct, sizeof ct) == -1, "wrong key accepted");
	CHECK(memcmp(out, canary, sizeof out) == 0, "plaintext modified after wrong key");
	// Damaged secret key.
	sk[KEM_SK - 40] ^= 1;
	EXPECT_REJECT("inconsistent secret key");
	sk[KEM_SK - 40] ^= 1;
	// Unmodified record still decrypts.
	CHECK(ncrypt_pqc_decrypt(out, kem_ct, mac, sk, ad, sizeof ad, ct, sizeof ct) == 0, "restored record fails");
	CHECK(memcmp(out, pt, sizeof pt) == 0, "plaintext mismatch");
#undef EXPECT_REJECT
}

static void test_hybrid_failure_leaves_outputs(void)
{
	uint8_t seed[64], eseed[32], pk[KEM_PK], sk[KEM_SK];
	uint8_t kem_ct[KEM_CT], kem_ct0[KEM_CT], mac[16], mac0[16], ct[64], ct0[64], pt[64];

	test_random(seed, sizeof seed);
	ncrypt_pqc_key_pair(sk, pk, seed);
	pk[0] = 0x01; pk[1] = (uint8_t)((pk[1] & 0xF0) | 0x0D); // coefficient q
	test_random(pt, sizeof pt);
	test_random(kem_ct, sizeof kem_ct); memcpy(kem_ct0, kem_ct, sizeof kem_ct);
	test_random(mac, sizeof mac);       memcpy(mac0, mac, sizeof mac);
	test_random(ct, sizeof ct);         memcpy(ct0, ct, sizeof ct);
	test_random(eseed, sizeof eseed);
	CHECK(ncrypt_pqc_encrypt(ct, mac, kem_ct, pk, eseed, NULL, 0, pt, sizeof pt) == -1, "malformed pk accepted");
	CHECK(is_zero(eseed, sizeof eseed), "seed not wiped on failure");
	CHECK(memcmp(kem_ct, kem_ct0, sizeof kem_ct) == 0, "kem_ct modified on failure");
	CHECK(memcmp(mac, mac0, sizeof mac) == 0, "mac modified on failure");
	CHECK(memcmp(ct, ct0, sizeof ct) == 0, "cipher_text modified on failure");
}

// Two encryptions under different seeds must produce different KEM
// ciphertexts and unrelated keystreams. Two encryptions under the same
// seed are byte-identical, which documents why seeds must be fresh.
static void test_hybrid_seed_dependence(void)
{
	uint8_t seed[64], e1[32], e2[32], pk[KEM_PK], sk[KEM_SK];
	uint8_t k1[KEM_CT], k2[KEM_CT], m1[16], m2[16], c1[128], c2[128], pt[128] = {0};

	test_random(seed, sizeof seed);
	ncrypt_pqc_key_pair(sk, pk, seed);
	test_random(e1, sizeof e1);
	memcpy(e2, e1, sizeof e1);
	e2[0] ^= 1;
	CHECK(ncrypt_pqc_encrypt(c1, m1, k1, pk, e1, NULL, 0, pt, sizeof pt) == 0, "encrypt");
	CHECK(ncrypt_pqc_encrypt(c2, m2, k2, pk, e2, NULL, 0, pt, sizeof pt) == 0, "encrypt");
	CHECK(memcmp(k1, k2, KEM_CT) != 0, "kem_ct independent of seed");
	CHECK(memcmp(c1, c2, sizeof c1) != 0, "keystream independent of seed");
	CHECK(memcmp(m1, m2, 16) != 0, "mac independent of seed");
}

int main(void)
{
	test_rng_seed(20260919);
	test_mlkem_roundtrip();
	test_mlkem_determinism();
	test_mlkem_implicit_rejection();
	test_mlkem_malformed_keys();
	test_mldsa_roundtrip();
	test_mldsa_hedged_vs_deterministic();
	test_mldsa_context();
	test_mldsa_tamper();
	test_hybrid_roundtrip();
	test_hybrid_in_place();
	test_hybrid_tamper();
	test_hybrid_tamper_in_place();
	test_hybrid_failure_leaves_outputs();
	test_hybrid_seed_dependence();
	test_verdict_is_zero_or_minus_one();
	return test_summary("test_pqc");
}
