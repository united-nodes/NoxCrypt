// Constant-time test, in the style of Monocypher's ctgrind.
//
// Run it through `make ct`, which runs Valgrind with tests/ct.supp.
//
// The idea (Adam Langley's ctgrind) is to mark every secret input as
// "undefined" and let Valgrind's memcheck look for uses of undefined
// values.  Memcheck then reports two things we care about:
//
//   - "Conditional jump or move depends on uninitialised value(s)":
//     a branch, or a conditional move, whose outcome depends on a
//     secret.
//   - "Use of uninitialised value of size N": a load or a store at an
//     address that depends on a secret.
//
// Whatever Valgrind reports is either a leak or a report we have
// reviewed and suppressed.  `make ct` therefore passes only when every
// report is covered by tests/ct.supp; each suppression there names the
// function and explains why the branch is public.  A new secret-
// dependent branch anywhere in the library shows up as an unsuppressed
// report and fails the run.
//
// Outside Valgrind the client requests do nothing, so the program can
// also be run as a plain smoke test of every public function.
//
// Secrets are marked undefined, never initialised "for real": the
// buffers hold a fixed public pattern so that a report is only ever
// about the marks, not about the values.

#include "../ncrypt.h"
#include "../ncrypt-pqc.h"

#include <stdio.h>
#include <string.h>

#ifdef HAVE_VALGRIND
#include <valgrind/memcheck.h>
#else
#define VALGRIND_MAKE_MEM_UNDEFINED(p, n) ((void)0)
#define VALGRIND_MAKE_MEM_DEFINED(p, n)   ((void)0)
#define RUNNING_ON_VALGRIND               0
#endif

#define SECRET(buf) VALGRIND_MAKE_MEM_UNDEFINED((buf), sizeof(buf))
#define PUBLIC(buf) VALGRIND_MAKE_MEM_DEFINED((buf), sizeof(buf))

// Buffers live in static storage so that Valgrind always sees them as
// addressable, whatever the optimisation level.
static uint8_t key    [32];
static uint8_t key2   [32];
static uint8_t nonce  [24];
static uint8_t mac    [16];
static uint8_t msg    [256];
static uint8_t ct_buf [300];
static uint8_t pt_buf [300];

static uint8_t kem_pk [NCRYPT_MLKEM768_PUBLIC_KEY_SIZE];
static uint8_t kem_sk [NCRYPT_MLKEM768_SECRET_KEY_SIZE];
static uint8_t kem_ct [NCRYPT_MLKEM768_CIPHERTEXT_SIZE];
static uint8_t kem_ss [NCRYPT_MLKEM768_SHARED_SECRET_SIZE];
static uint8_t sig_pk [NCRYPT_MLDSA44_PUBLIC_KEY_SIZE];
static uint8_t sig_sk [NCRYPT_MLDSA44_SECRET_KEY_SIZE];
static uint8_t sig    [NCRYPT_MLDSA44_SIGNATURE_SIZE];
static uint8_t seed64 [NCRYPT_MLKEM768_KEY_SEED_SIZE];
static uint8_t seed32 [32];
static uint8_t rnd    [NCRYPT_MLDSA44_RND_SIZE];
static size_t  msg_size = sizeof msg;

// Fill a buffer with a fixed pattern.  The pattern is public; the
// SECRET() marks are what Valgrind reacts to.
static void fill(uint8_t *buf, size_t size, unsigned char x)
{
	size_t i;
	for (i = 0; i < size; i++) {
		buf[i] = (uint8_t)(x + i * 7u + (i >> 3));
	}
}

static void run(const char *name, void (*op)(void))
{
	printf("%s\n", name);
	fflush(stdout);
	op();
	fflush(stdout);
}

/////////////////
/// Classical ///
/////////////////

static void op_verify(void)
{
	// The results must not be branched on here: this harness measures
	// the library, not itself.
	volatile int sink = 0;
	sink |= ncrypt_verify16(mac, mac + 0);
	sink |= ncrypt_verify32(key, key2);
	sink |= ncrypt_verify64(ct_buf, pt_buf);
	(void)sink;
}

static void op_wipe(void)
{
	ncrypt_wipe(pt_buf, sizeof pt_buf);
}

static void op_aead_lock(void)
{
	ncrypt_aead_lock(ct_buf, mac, key, nonce, msg, 200, pt_buf, 200);
}

static void op_aead_unlock(void)
{
	static uint8_t plain[200];
	(void)ncrypt_aead_unlock(plain, mac, key, nonce, msg, 200,
	                         ct_buf, 200);
}

static void op_blake2b(void)
{
	static uint8_t hash[64];
	ncrypt_blake2b_keyed(hash, sizeof hash, key, sizeof key, msg, sizeof msg);
	ncrypt_blake2b(hash, 32, msg, sizeof msg);
}

static void op_argon2(void)
{
	// A small work area: Argon2 is otherwise slow under Valgrind.
	static uint8_t work[64 * 1024];
	static uint8_t hash[32];
	ncrypt_argon2_config config;
	ncrypt_argon2_inputs inputs;
	config.algorithm = NCRYPT_ARGON2_ID;
	config.nb_blocks = 64;
	config.nb_passes = 1;
	config.nb_lanes  = 1;
	inputs.pass      = msg;
	inputs.salt      = key;
	inputs.pass_size = 16;
	inputs.salt_size = 16;
	ncrypt_argon2(hash, sizeof hash, work, config, inputs,
	              ncrypt_argon2_no_extras);
}

static void op_x25519(void)
{
	static uint8_t shared[32];
	static uint8_t pub   [32];
	ncrypt_x25519_public_key(pub, key);
	ncrypt_x25519(shared, key2, pub);
	ncrypt_x25519_to_eddsa(shared, pub);
}

static void op_x25519_inverse(void)
{
	static uint8_t blind[32];
	ncrypt_x25519_inverse(blind, key, key2);
}

static void op_x25519_dirty(void)
{
	static uint8_t pub[32];
	ncrypt_x25519_dirty_fast (pub, key);
	ncrypt_x25519_dirty_small(pub, key);
}

static void op_elligator(void)
{
	static uint8_t hidden[32];
	static uint8_t curve [32];
	fill(hidden, sizeof hidden, 12);
	SECRET(hidden);
	ncrypt_elligator_map(curve, hidden);
	PUBLIC(curve);
	(void)ncrypt_elligator_rev(hidden, curve, key[0]);
}

static void op_elligator_key_pair(void)
{
	static uint8_t hidden[32];
	static uint8_t sk    [32];
	static uint8_t seed  [32];
	fill(seed, sizeof seed, 1);
	SECRET(seed);
	ncrypt_elligator_key_pair(hidden, sk, seed);
}

static void op_eddsa(void)
{
	static uint8_t pk[32];
	static uint8_t sk[64];
	static uint8_t signature[64];
	fill(seed32, sizeof seed32, 3);
	SECRET(seed32);
	ncrypt_eddsa_key_pair(sk, pk, seed32);
	fill(seed32, sizeof seed32, 4);
	SECRET(seed32);
	ncrypt_eddsa_sign(signature, sk, msg, sizeof msg);
	PUBLIC(pk);
	PUBLIC(signature);
	ncrypt_eddsa_to_x25519(pk, pk);
}

static void op_ed25519(void)
{
	static uint8_t pk[32];
	static uint8_t sk[64];
	static uint8_t signature[64];
	fill(seed32, sizeof seed32, 5);
	SECRET(seed32);
	ncrypt_ed25519_key_pair(sk, pk, seed32);
	fill(seed32, sizeof seed32, 6);
	SECRET(seed32);
	ncrypt_ed25519_sign(signature, sk, msg, sizeof msg);
	ncrypt_ed25519_ph_sign(signature, sk, ct_buf);
}

static void op_chacha20(void)
{
	(void)ncrypt_chacha20_djb (ct_buf, pt_buf, 200, key, nonce, 0);
	(void)ncrypt_chacha20_ietf(ct_buf, pt_buf, 200, key, nonce, 0);
	(void)ncrypt_chacha20_x   (ct_buf, pt_buf, 200, key, nonce, 0);
	ncrypt_chacha20_h(key2, key, nonce);
}

static void op_poly1305(void)
{
	ncrypt_poly1305(mac, msg, sizeof msg, key);
}

static void op_sha512(void)
{
	static uint8_t hash[64];
	static uint8_t okm [128];
	ncrypt_sha512(hash, msg, sizeof msg);
	ncrypt_sha512_hmac(hash, key, sizeof key, msg, sizeof msg);
	ncrypt_sha512_hkdf(okm, sizeof okm, key, sizeof key,
	                   key2, sizeof key2, msg, sizeof msg);
	ncrypt_sha512_hkdf_expand(okm, sizeof okm, key, sizeof key,
	                          msg, sizeof msg);
}

////////////////////
/// Post-quantum ///
////////////////////

static void op_mlkem(void)
{
	fill(seed64, sizeof seed64, 7);
	SECRET(seed64);
	ncrypt_mlkem768_key_pair(kem_sk, kem_pk, seed64);
	PUBLIC(kem_pk);          // the encapsulation key is published

	fill(seed32, sizeof seed32, 8);
	SECRET(seed32);
	(void)ncrypt_mlkem768_encapsulate(kem_ct, kem_ss, kem_pk, seed32);
	PUBLIC(kem_ct);          // the ciphertext travels over the wire

	(void)ncrypt_mlkem768_decapsulate(kem_ss, kem_ct, kem_sk);
}

static void op_mldsa_sign(void)
{
	fill(seed32, sizeof seed32, 9);
	SECRET(seed32);
	ncrypt_mldsa44_key_pair(sig_sk, sig_pk, seed32);
	PUBLIC(sig_pk);

	fill(rnd, sizeof rnd, 10);
	SECRET(rnd);
	(void)ncrypt_mldsa44_sign(sig, sig_sk, rnd, NULL, 0, msg, msg_size);
	PUBLIC(sig);
	(void)ncrypt_mldsa44_sign_deterministic(sig, sig_sk, msg, 4,
	                                        msg, msg_size);
	(void)ncrypt_pqc_sign(sig, sig_sk, rnd, msg, msg_size);
}

static void op_mldsa_check(void)
{
	(void)ncrypt_mldsa44_check(sig, sig_pk, NULL, 0, msg, msg_size);
	(void)ncrypt_pqc_check(sig, sig_pk, msg, msg_size);
}

static void op_pqc_encrypt(void)
{
	static uint8_t seed  [NCRYPT_PQC_SEED_SIZE];
	static uint8_t tag   [NCRYPT_PQC_MAC_SIZE];
	static uint8_t kemct [NCRYPT_PQC_KEM_CT_SIZE];
	fill(seed, sizeof seed, 11);
	SECRET(seed);
	(void)ncrypt_pqc_encrypt(ct_buf, tag, kemct, kem_pk, seed,
	                         NULL, 0, pt_buf, 200);
}

static void op_pqc_decrypt(void)
{
	// kem_ct from op_pqc_encrypt is public; the tag is in mac[] from
	// the other operations, which is secret-marked, so rebuild a
	// ciphertext here to decrypt.
	static uint8_t plain[200];
	static uint8_t seed [NCRYPT_PQC_SEED_SIZE];
	static uint8_t tag  [NCRYPT_PQC_MAC_SIZE];
	static uint8_t kemct[NCRYPT_PQC_KEM_CT_SIZE];
	fill(seed, sizeof seed, 13);
	SECRET(seed);
	(void)ncrypt_pqc_encrypt(pt_buf, tag, kemct, kem_pk, seed,
	                         NULL, 0, pt_buf, 200);
	PUBLIC(pt_buf);
	(void)ncrypt_pqc_decrypt(plain, kemct, tag, kem_sk, NULL, 0,
	                         pt_buf, 200);
}

int main(void)
{
	// Public material: everything an attacker can see.  Secret
	// material: keys, seeds, nonces, plaintext.  Both kinds are filled
	// with the same pattern, so only the marks differ.
	fill(key,    sizeof key,    1);
	fill(key2,   sizeof key2,   2);
	fill(nonce,  sizeof nonce,  3);
	fill(mac,    sizeof mac,    4);
	fill(msg,    sizeof msg,    5);
	fill(ct_buf, sizeof ct_buf, 6);
	fill(pt_buf, sizeof pt_buf, 7);
	fill(seed32, sizeof seed32, 8);
	fill(seed64, sizeof seed64, 9);
	fill(rnd,    sizeof rnd,   10);

	SECRET(key);   SECRET(key2);   SECRET(nonce);  SECRET(mac);
	SECRET(pt_buf); SECRET(seed32); SECRET(seed64); SECRET(rnd);
	SECRET(kem_sk); SECRET(sig_sk); SECRET(kem_ss);
	PUBLIC(msg);   PUBLIC(ct_buf); PUBLIC(kem_pk); PUBLIC(kem_ct);
	PUBLIC(sig_pk); PUBLIC(sig);

	printf("constant time harness, valgrind: %s\n",
	       RUNNING_ON_VALGRIND ? "yes" : "no");

	run("ncrypt_verify16/32/64",     op_verify);
	run("ncrypt_wipe",               op_wipe);
	run("ncrypt_aead_lock",          op_aead_lock);
	run("ncrypt_aead_unlock",        op_aead_unlock);
	run("ncrypt_blake2b*",           op_blake2b);
	run("ncrypt_argon2",             op_argon2);
	run("ncrypt_x25519*",            op_x25519);
	run("ncrypt_x25519_inverse",     op_x25519_inverse);
	run("ncrypt_x25519_dirty_*",     op_x25519_dirty);
	run("ncrypt_elligator_*",        op_elligator);
	run("ncrypt_elligator_key_pair", op_elligator_key_pair);
	run("ncrypt_eddsa_*",            op_eddsa);
	run("ncrypt_ed25519_*",          op_ed25519);
	run("ncrypt_chacha20_*",         op_chacha20);
	run("ncrypt_poly1305",           op_poly1305);
	run("ncrypt_sha512_*",           op_sha512);
	run("ncrypt_mlkem768_*",         op_mlkem);
	run("ncrypt_mldsa44_sign*",      op_mldsa_sign);
	run("ncrypt_mldsa44_check",      op_mldsa_check);
	run("ncrypt_pqc_encrypt",        op_pqc_encrypt);
	run("ncrypt_pqc_decrypt",        op_pqc_decrypt);

	printf("constant time harness: done\n");
	return 0;
}
