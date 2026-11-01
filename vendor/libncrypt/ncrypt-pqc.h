// libncrypt -- post-quantum layer interface.
//
// ML-KEM-768 (FIPS 203) and ML-DSA-44 (FIPS 204), plus a hybrid KEM/DEM
// construction that uses the XChaCha20-Poly1305 and BLAKE2b primitives
// from ncrypt.h.
//
// This header is self-contained apart from ncrypt.h. Compile
// ncrypt-pqc.c together with ncrypt.c.
//
// General contract, shared by every function below:
//
// - Buffers are exactly the size given by the NCRYPT_* constants or by
//   the array bound in the prototype. Nothing is checked at run time.
// - Input and output buffers must not overlap, except where a function
//   comment says otherwise.
// - A pointer may be NULL only when the matching size is zero.
// - No function allocates memory or reads a random source. Seeds and
//   signing randomness are supplied by the caller, must come from a
//   cryptographically secure generator, and are wiped by the callee
//   before it returns (on every code path, including failures).
// - Return value 0 means success, -1 means failure, following the
//   convention used by ncrypt.h.

#ifndef NCRYPT_PQC_H
#define NCRYPT_PQC_H

#include "ncrypt.h"

#ifdef __cplusplus
extern "C" {
#endif

////////////////////
/// Buffer sizes ///
////////////////////

// All sizes are in bytes.
#define NCRYPT_MLKEM768_PUBLIC_KEY_SIZE    1184
#define NCRYPT_MLKEM768_SECRET_KEY_SIZE    2400
#define NCRYPT_MLKEM768_CIPHERTEXT_SIZE    1088
#define NCRYPT_MLKEM768_SHARED_SECRET_SIZE   32
#define NCRYPT_MLKEM768_KEY_SEED_SIZE        64
#define NCRYPT_MLKEM768_ENCAPS_SEED_SIZE     32

#define NCRYPT_MLDSA44_PUBLIC_KEY_SIZE     1312
#define NCRYPT_MLDSA44_SECRET_KEY_SIZE     2560
#define NCRYPT_MLDSA44_SIGNATURE_SIZE      2420
#define NCRYPT_MLDSA44_KEY_SEED_SIZE         32
#define NCRYPT_MLDSA44_RND_SIZE              32
#define NCRYPT_MLDSA44_MAX_CONTEXT_SIZE     255

// Sizes of the hybrid construction. The MAC size is that of Poly1305.
#define NCRYPT_PQC_KEM_CT_SIZE   NCRYPT_MLKEM768_CIPHERTEXT_SIZE
#define NCRYPT_PQC_MAC_SIZE        16
#define NCRYPT_PQC_SEED_SIZE     NCRYPT_MLKEM768_ENCAPS_SEED_SIZE


///////////////////////////////
/// ML-KEM-768 key exchange ///
///////////////////////////////

// Derive an ML-KEM-768 key pair from a 64-byte seed (FIPS 203
// ML-KEM.KeyGen_internal, with seed = d || z). The seed is wiped.
void ncrypt_mlkem768_key_pair(uint8_t secret_key[NCRYPT_MLKEM768_SECRET_KEY_SIZE],
                              uint8_t public_key[NCRYPT_MLKEM768_PUBLIC_KEY_SIZE],
                              uint8_t seed      [NCRYPT_MLKEM768_KEY_SEED_SIZE]);

// Encapsulate a 32-byte shared secret for public_key using a 32-byte
// seed (FIPS 203 ML-KEM.Encaps_internal). The seed is wiped.
// Returns 0 on success and -1 if public_key fails the FIPS 203 modulus
// check; in that case ciphertext and shared_secret are left untouched.
//
// The seed must be unique for every call. Reusing a seed with the same
// public key reproduces the ciphertext and the shared secret.
int ncrypt_mlkem768_encapsulate(uint8_t       ciphertext   [NCRYPT_MLKEM768_CIPHERTEXT_SIZE],
                                uint8_t       shared_secret[NCRYPT_MLKEM768_SHARED_SECRET_SIZE],
                                const uint8_t public_key   [NCRYPT_MLKEM768_PUBLIC_KEY_SIZE],
                                uint8_t       seed         [NCRYPT_MLKEM768_ENCAPS_SEED_SIZE]);

// Decapsulate ciphertext with secret_key (FIPS 203 ML-KEM.Decaps).
// Returns 0 on success and -1 if secret_key fails the FIPS 203 hash
// check, in which case shared_secret is left untouched.
// A malformed or forged ciphertext is never reported. As FIPS 203
// requires, it yields an unrelated pseudorandom shared secret
// (implicit rejection); callers must authenticate whatever they derive
// from the shared secret.
int ncrypt_mlkem768_decapsulate(uint8_t       shared_secret[NCRYPT_MLKEM768_SHARED_SECRET_SIZE],
                                const uint8_t ciphertext   [NCRYPT_MLKEM768_CIPHERTEXT_SIZE],
                                const uint8_t secret_key   [NCRYPT_MLKEM768_SECRET_KEY_SIZE]);


////////////////////////////
/// ML-DSA-44 signatures ///
////////////////////////////

// Derive an ML-DSA-44 key pair from a 32-byte seed (FIPS 204
// ML-DSA.KeyGen_internal). The seed is wiped.
void ncrypt_mldsa44_key_pair(uint8_t secret_key[NCRYPT_MLDSA44_SECRET_KEY_SIZE],
                             uint8_t public_key[NCRYPT_MLDSA44_PUBLIC_KEY_SIZE],
                             uint8_t seed      [NCRYPT_MLDSA44_KEY_SEED_SIZE]);

// Sign a message with hedged ML-DSA-44 (FIPS 204 ML-DSA.Sign). This is
// the default variant of the standard: rnd holds 32 fresh random bytes
// that are mixed into the per-signature secret, which limits the damage
// done by fault attacks and some side channels. rnd is wiped.
//
// context is an optional domain-separation string of at most 255 bytes
// (pass NULL and 0 for none). Returns 0 on success and -1 if
// context_size exceeds NCRYPT_MLDSA44_MAX_CONTEXT_SIZE; in that case
// signature is left untouched but rnd is still wiped.
int ncrypt_mldsa44_sign(uint8_t        signature [NCRYPT_MLDSA44_SIGNATURE_SIZE],
                        const uint8_t  secret_key[NCRYPT_MLDSA44_SECRET_KEY_SIZE],
                        uint8_t        rnd       [NCRYPT_MLDSA44_RND_SIZE],
                        const uint8_t *context, size_t context_size,
                        const uint8_t *message, size_t message_size);

// Deterministic ML-DSA-44 (FIPS 204 with rnd = 32 zero bytes). Same
// message and key always give the same signature. Use it only where
// reproducible signatures are required, for instance in test vectors
// or when no random source is available at signing time.
int ncrypt_mldsa44_sign_deterministic(uint8_t        signature [NCRYPT_MLDSA44_SIGNATURE_SIZE],
                                      const uint8_t  secret_key[NCRYPT_MLDSA44_SECRET_KEY_SIZE],
                                      const uint8_t *context, size_t context_size,
                                      const uint8_t *message, size_t message_size);

// Verify a signature (FIPS 204 ML-DSA.Verify). The context must be the
// one used for signing. Returns 0 if the signature is valid and -1
// otherwise, including when context_size exceeds 255.
int ncrypt_mldsa44_check(const uint8_t  signature [NCRYPT_MLDSA44_SIGNATURE_SIZE],
                         const uint8_t  public_key[NCRYPT_MLDSA44_PUBLIC_KEY_SIZE],
                         const uint8_t *context, size_t context_size,
                         const uint8_t *message, size_t message_size);


//////////////////////
/// High-level API ///
//////////////////////

// The functions below fix the algorithm choices: ML-KEM-768 for
// encryption and hedged ML-DSA-44 with an empty context for signatures.
// Never use one key pair, or one seed, for both purposes.

void ncrypt_pqc_key_pair(uint8_t secret_key[NCRYPT_MLKEM768_SECRET_KEY_SIZE],
                         uint8_t public_key[NCRYPT_MLKEM768_PUBLIC_KEY_SIZE],
                         uint8_t seed      [NCRYPT_MLKEM768_KEY_SEED_SIZE]);

void ncrypt_pqc_sign_key_pair(uint8_t secret_key[NCRYPT_MLDSA44_SECRET_KEY_SIZE],
                              uint8_t public_key[NCRYPT_MLDSA44_PUBLIC_KEY_SIZE],
                              uint8_t seed      [NCRYPT_MLDSA44_KEY_SEED_SIZE]);

// Hybrid public-key encryption. Encapsulates a fresh ML-KEM-768 shared
// secret for their_public_key, derives a one-time XChaCha20-Poly1305
// key and nonce from that secret and from kem_ct, and encrypts
// plain_text. The receiver needs kem_ct, mac, cipher_text, and ad; ad is
// authenticated but not transmitted by this function. The seed is
// wiped. Returns 0 on success and -1 if their_public_key is malformed;
// on failure no output buffer is modified.
//
// The (key, nonce) pair is unique exactly when the encapsulation is,
// so the seed must be fresh for every call. See doc/API.md.
// cipher_text may be the same buffer as plain_text.
int ncrypt_pqc_encrypt(uint8_t       *cipher_text,
                       uint8_t        mac             [NCRYPT_PQC_MAC_SIZE],
                       uint8_t        kem_ct          [NCRYPT_PQC_KEM_CT_SIZE],
                       const uint8_t  their_public_key[NCRYPT_MLKEM768_PUBLIC_KEY_SIZE],
                       uint8_t        seed            [NCRYPT_PQC_SEED_SIZE],
                       const uint8_t *ad,         size_t ad_size,
                       const uint8_t *plain_text, size_t text_size);

// Decrypt a message produced by ncrypt_pqc_encrypt. Returns 0 on
// success and -1 if secret_key is inconsistent or authentication fails
// (wrong key, modified kem_ct, mac, cipher_text, or ad). On failure
// plain_text is left untouched. plain_text may be the same buffer as
// cipher_text.
int ncrypt_pqc_decrypt(uint8_t       *plain_text,
                       const uint8_t  kem_ct     [NCRYPT_PQC_KEM_CT_SIZE],
                       const uint8_t  mac        [NCRYPT_PQC_MAC_SIZE],
                       const uint8_t  secret_key [NCRYPT_MLKEM768_SECRET_KEY_SIZE],
                       const uint8_t *ad,          size_t ad_size,
                       const uint8_t *cipher_text, size_t text_size);

// Detached hedged ML-DSA-44 signatures with an empty context. rnd is
// 32 fresh random bytes and is wiped.
void ncrypt_pqc_sign(uint8_t        signature [NCRYPT_MLDSA44_SIGNATURE_SIZE],
                     const uint8_t  secret_key[NCRYPT_MLDSA44_SECRET_KEY_SIZE],
                     uint8_t        rnd       [NCRYPT_MLDSA44_RND_SIZE],
                     const uint8_t *message, size_t message_size);
int ncrypt_pqc_check(const uint8_t  signature [NCRYPT_MLDSA44_SIGNATURE_SIZE],
                     const uint8_t  public_key[NCRYPT_MLDSA44_PUBLIC_KEY_SIZE],
                     const uint8_t *message, size_t message_size);

#ifdef __cplusplus
}
#endif

#endif // NCRYPT_PQC_H
