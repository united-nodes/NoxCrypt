// Fuzz harness for the parsers on the untrusted side of ncrypt-pqc:
// ML-KEM decapsulation, ML-KEM encapsulation key checking, ML-DSA
// verification, and hybrid decryption.
//
// Build with clang -fsanitize=fuzzer,address,undefined for libFuzzer,
// or with -DFUZZ_STANDALONE to obtain a main() that feeds the files
// named on the command line to the same entry point.

#include "../ncrypt-pqc.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t kem_pk[NCRYPT_MLKEM768_PUBLIC_KEY_SIZE];
static uint8_t kem_sk[NCRYPT_MLKEM768_SECRET_KEY_SIZE];
static uint8_t sig_pk[NCRYPT_MLDSA44_PUBLIC_KEY_SIZE];
static uint8_t sig_sk[NCRYPT_MLDSA44_SECRET_KEY_SIZE];
// A well-formed signature and the message it covers.  The decoders in
// the verification path (z, hints, public key) only run to completion
// on encodings that are mostly well formed, so fuzzing from random
// bytes never reaches them.  Mutating these does.
static uint8_t sig_valid[NCRYPT_MLDSA44_SIGNATURE_SIZE];
// The message buffer is larger than the message actually used, because
// one of the cases below passes a length taken from the input: the
// library is allowed to read exactly as many bytes as it is told, so
// the buffer must really be that long.  (The first version of this
// harness passed a length of up to 255 with a 5-byte buffer, and ASan
// reported the read as a library bug.)
#define FUZZ_MSG_SIZE 5
static uint8_t fuzz_msg[256] = "fuzz";
static int     keys_ready;

static void init_keys(void)
{
	uint8_t seed[64];
	size_t i;
	if (keys_ready) return;
	for (i = 0; i < 64; i++) seed[i] = (uint8_t)(i * 7 + 3);
	ncrypt_mlkem768_key_pair(kem_sk, kem_pk, seed);
	for (i = 0; i < 32; i++) seed[i] = (uint8_t)(i * 13 + 5);
	ncrypt_mldsa44_key_pair(sig_sk, sig_pk, seed);
	ncrypt_mldsa44_sign_deterministic(sig_valid, sig_sk, 0, 0,
	                                  fuzz_msg, FUZZ_MSG_SIZE);
	keys_ready = 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t selector;
	init_keys();
	if (size == 0) return 0;
	selector = data[0];
	data++;
	size--;

	switch (selector & 3) {
	case 0: {
		// Decapsulate arbitrary ciphertext bytes under a good key, and
		// arbitrary secret key bytes with a fixed ciphertext.
		uint8_t ct[NCRYPT_MLKEM768_CIPHERTEXT_SIZE] = {0};
		uint8_t sk[NCRYPT_MLKEM768_SECRET_KEY_SIZE];
		uint8_t ss[32];
		memcpy(ct, data, size < sizeof ct ? size : sizeof ct);
		(void)ncrypt_mlkem768_decapsulate(ss, ct, kem_sk);
		memcpy(sk, kem_sk, sizeof sk);
		memcpy(sk, data, size < sizeof sk ? size : sizeof sk);
		(void)ncrypt_mlkem768_decapsulate(ss, ct, sk);
		break;
	}
	case 1: {
		// Encapsulate to arbitrary public key bytes.
		uint8_t pk[NCRYPT_MLKEM768_PUBLIC_KEY_SIZE];
		uint8_t seed[32] = {1};
		uint8_t ct[NCRYPT_MLKEM768_CIPHERTEXT_SIZE], ss[32];
		memcpy(pk, kem_pk, sizeof pk);
		memcpy(pk, data, size < sizeof pk ? size : sizeof pk);
		(void)ncrypt_mlkem768_encapsulate(ct, ss, pk, seed);
		break;
	}
	case 2: {
		// ML-DSA verification, from both directions.
		//
		// First on a signature derived from the raw input, then on a
		// well-formed signature XORed with the input: the first reaches
		// the top-level length and hint checks, the second reaches the
		// z decoder, the NTT and the hint application, which is where a
		// coefficient can go out of range or out of bounds.
		uint8_t sig[NCRYPT_MLDSA44_SIGNATURE_SIZE];
		uint8_t pk[NCRYPT_MLDSA44_PUBLIC_KEY_SIZE];
		size_t i, take = size < sizeof sig ? size : sizeof sig;
		const uint8_t *ctx = data + take;
		size_t ctx_size = size - take;

		memset(sig, 0, sizeof sig);
		memcpy(sig, data, take);
		(void)ncrypt_mldsa44_check(sig, sig_pk, 0, 0,
		                           fuzz_msg, FUZZ_MSG_SIZE);

		for (i = 0; i < take; i++) sig[i] = (uint8_t)(sig_valid[i] ^ data[i]);
		// Keep the context within what the API accepts, and use the
		// bytes after the signature as its contents.
		if (ctx_size > 255) ctx_size = 255;
		(void)ncrypt_mldsa44_check(sig, sig_pk, ctx, ctx_size,
		                           fuzz_msg, FUZZ_MSG_SIZE);

		// A mutated public key against the valid signature.
		memcpy(pk, sig_pk, sizeof pk);
		for (i = 0; i < take && i < sizeof pk; i++)
			pk[i] = (uint8_t)(sig_pk[i] ^ data[i]);
		(void)ncrypt_mldsa44_check(sig_valid, pk, 0, 0,
		                           fuzz_msg, FUZZ_MSG_SIZE);

		// And a mutated message length, which is a size argument the
		// caller controls.
		(void)ncrypt_mldsa44_check(sig_valid, sig_pk, 0, 0, fuzz_msg,
		                           ctx_size);
		break;
	}
	default: {
		// Hybrid decryption of an arbitrary record.
		uint8_t kem_ct[NCRYPT_PQC_KEM_CT_SIZE] = {0};
		uint8_t mac[16] = {0};
		const uint8_t *ct;
		size_t ct_size, take;
		uint8_t *pt;
		take = size < sizeof kem_ct ? size : sizeof kem_ct;
		memcpy(kem_ct, data, take);
		data += take; size -= take;
		take = size < sizeof mac ? size : sizeof mac;
		memcpy(mac, data, take);
		data += take; size -= take;
		ct = data;
		ct_size = size;
		pt = (uint8_t *)malloc(ct_size == 0 ? 1 : ct_size);
		if (pt == NULL) return 0;
		(void)ncrypt_pqc_decrypt(pt, kem_ct, mac, kem_sk, 0, 0,
		                         ct_size == 0 ? 0 : ct, ct_size);
		free(pt);
		break;
	}
	}
	return 0;
}

#ifdef FUZZ_STANDALONE
int main(int argc, char **argv)
{
	int i;
	for (i = 1; i < argc; i++) {
		FILE *f = fopen(argv[i], "rb");
		uint8_t *buf;
		long n;
		if (f == NULL) continue;
		fseek(f, 0, SEEK_END);
		n = ftell(f);
		fseek(f, 0, SEEK_SET);
		buf = (uint8_t *)malloc(n <= 0 ? 1 : (size_t)n);
		if (buf != NULL && n > 0 && fread(buf, 1, (size_t)n, f) == (size_t)n) {
			LLVMFuzzerTestOneInput(buf, (size_t)n);
		}
		free(buf);
		fclose(f);
	}
	// Also run a deterministic sweep over selector bytes and sizes so
	// that the standalone build performs some work without a corpus.
	{
		uint8_t buf[4096];
		size_t s;
		unsigned k;
		for (k = 0; k < 64; k++) {
			for (s = 1; s <= sizeof buf; s = s * 2 + 1) {
				size_t j;
				for (j = 0; j < s; j++) buf[j] = (uint8_t)(j * 31 + k * 17 + 1);
				buf[0] = (uint8_t)k;
				LLVMFuzzerTestOneInput(buf, s);
			}
		}
	}
	printf("fuzz_pqc: standalone sweep completed\n");
	return 0;
}
#endif
