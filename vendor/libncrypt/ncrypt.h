// libncrypt -- classical layer interface.
//
// A namespace-renamed port of Monocypher 4.0.3 (https://monocypher.org,
// redistributed under CC0-1.0), with Monocypher's optional Ed25519 /
// SHA-512 / HMAC / HKDF module merged into the same files. libncrypt
// itself is released under the Anonymous Public Domain License 1.0; see
// LICENSE. See doc/PROVENANCE.md for the upstream revision and the list
// of local changes.

#ifndef NCRYPT_H
#define NCRYPT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Version of the library, as a string.  Also reported by the test suite.
#define NCRYPT_VERSION "1.0.0"

// Constant time comparisons
// -------------------------

// Return 0 if a and b are equal, -1 otherwise
int ncrypt_verify16(const uint8_t a[16], const uint8_t b[16]);
int ncrypt_verify32(const uint8_t a[32], const uint8_t b[32]);
int ncrypt_verify64(const uint8_t a[64], const uint8_t b[64]);


// Erase sensitive data
// --------------------
void ncrypt_wipe(void *secret, size_t size);


// Authenticated encryption
// ------------------------
void ncrypt_aead_lock(uint8_t       *cipher_text,
                      uint8_t        mac  [16],
                      const uint8_t  key  [32],
                      const uint8_t  nonce[24],
                      const uint8_t *ad,         size_t ad_size,
                      const uint8_t *plain_text, size_t text_size);
int ncrypt_aead_unlock(uint8_t       *plain_text,
                       const uint8_t  mac  [16],
                       const uint8_t  key  [32],
                       const uint8_t  nonce[24],
                       const uint8_t *ad,          size_t ad_size,
                       const uint8_t *cipher_text, size_t text_size);

// Authenticated stream
// --------------------
typedef struct {
	uint64_t counter;
	uint8_t  key[32];
	uint8_t  nonce[8];
} ncrypt_aead_ctx;

void ncrypt_aead_init_x(ncrypt_aead_ctx *ctx,
                        const uint8_t key[32], const uint8_t nonce[24]);
void ncrypt_aead_init_djb(ncrypt_aead_ctx *ctx,
                          const uint8_t key[32], const uint8_t nonce[8]);
void ncrypt_aead_init_ietf(ncrypt_aead_ctx *ctx,
                           const uint8_t key[32], const uint8_t nonce[12]);

void ncrypt_aead_write(ncrypt_aead_ctx *ctx,
                       uint8_t         *cipher_text,
                       uint8_t          mac[16],
                       const uint8_t   *ad        , size_t ad_size,
                       const uint8_t   *plain_text, size_t text_size);
int ncrypt_aead_read(ncrypt_aead_ctx *ctx,
                     uint8_t         *plain_text,
                     const uint8_t    mac[16],
                     const uint8_t   *ad        , size_t ad_size,
                     const uint8_t   *cipher_text, size_t text_size);


// General purpose hash (BLAKE2b)
// ------------------------------

// Direct interface
void ncrypt_blake2b(uint8_t *hash,          size_t hash_size,
                    const uint8_t *message, size_t message_size);

void ncrypt_blake2b_keyed(uint8_t *hash,          size_t hash_size,
                          const uint8_t *key,     size_t key_size,
                          const uint8_t *message, size_t message_size);

// Incremental interface
typedef struct {
	// Do not rely on the size or contents of this type,
	// for they may change without notice.
	uint64_t hash[8];
	uint64_t input_offset[2];
	uint64_t input[16];
	size_t   input_idx;
	size_t   hash_size;
} ncrypt_blake2b_ctx;

void ncrypt_blake2b_init(ncrypt_blake2b_ctx *ctx, size_t hash_size);
void ncrypt_blake2b_keyed_init(ncrypt_blake2b_ctx *ctx, size_t hash_size,
                               const uint8_t *key, size_t key_size);
void ncrypt_blake2b_update(ncrypt_blake2b_ctx *ctx,
                           const uint8_t *message, size_t message_size);
void ncrypt_blake2b_final(ncrypt_blake2b_ctx *ctx, uint8_t *hash);


// Password key derivation (Argon2)
// --------------------------------
#define NCRYPT_ARGON2_D  0
#define NCRYPT_ARGON2_I  1
#define NCRYPT_ARGON2_ID 2

typedef struct {
	uint32_t algorithm;  // Argon2d, Argon2i, Argon2id
	uint32_t nb_blocks;  // memory hardness, >= 8 * nb_lanes
	uint32_t nb_passes;  // CPU hardness, >= 1 (>= 3 recommended for Argon2i)
	uint32_t nb_lanes;   // parallelism level (single threaded anyway)
} ncrypt_argon2_config;

typedef struct {
	const uint8_t *pass;
	const uint8_t *salt;
	uint32_t pass_size;
	uint32_t salt_size;  // 16 bytes recommended
} ncrypt_argon2_inputs;

typedef struct {
	const uint8_t *key; // may be NULL if no key
	const uint8_t *ad;  // may be NULL if no additional data
	uint32_t key_size;  // 0 if no key (32 bytes recommended otherwise)
	uint32_t ad_size;   // 0 if no additional data
} ncrypt_argon2_extras;

extern const ncrypt_argon2_extras ncrypt_argon2_no_extras;

void ncrypt_argon2(uint8_t *hash, uint32_t hash_size, void *work_area,
                   ncrypt_argon2_config config,
                   ncrypt_argon2_inputs inputs,
                   ncrypt_argon2_extras extras);


// Key exchange (X-25519)
// ----------------------

// Shared secrets are not quite random.
// Hash them to derive an actual shared key.
void ncrypt_x25519_public_key(uint8_t       public_key[32],
                              const uint8_t secret_key[32]);
void ncrypt_x25519(uint8_t       raw_shared_secret[32],
                   const uint8_t your_secret_key  [32],
                   const uint8_t their_public_key [32]);

// Conversion to EdDSA
void ncrypt_x25519_to_eddsa(uint8_t eddsa[32], const uint8_t x25519[32]);

// Converting to hidden points (Elligator 2)
// -----------------------------------------
// "Dirty" public keys do not clear the cofactor, so they leak 3 bits of
// the private key. Use them only as an intermediate value that is then
// hidden with ncrypt_elligator_rev().
void ncrypt_x25519_dirty_fast (uint8_t       public_key[32],
                               const uint8_t secret_key[32]);
void ncrypt_x25519_dirty_small(uint8_t       public_key[32],
                               const uint8_t secret_key[32]);

// Direct map: a 32-byte representative to a curve point (u coordinate).
void ncrypt_elligator_map(uint8_t       curve[32],
                          const uint8_t hidden[32]);

// Inverse map: a curve point to a 32-byte representative. Returns 0 on
// success and -1 if the point has no representative, in which case
// `hidden` is left untouched. `tweak` is a random byte.
int ncrypt_elligator_rev(uint8_t       hidden    [32],
                         const uint8_t public_key[32],
                         uint8_t       tweak);

// Generate a key pair whose public key is a uniform-looking 32-byte
// string. `seed` is a 32-byte seed and is wiped.
void ncrypt_elligator_key_pair(uint8_t hidden    [32],
                               uint8_t secret_key[32],
                               uint8_t seed      [32]);

// scalar "division"
// Used for OPRF.  Be aware that exponential blinding is less secure
// than Diffie-Hellman key exchange.
void ncrypt_x25519_inverse(uint8_t       blind_salt [32],
                           const uint8_t private_key[32],
                           const uint8_t curve_point[32]);

// Signatures
// ----------

// EdDSA with curve25519 + BLAKE2b
void ncrypt_eddsa_key_pair(uint8_t secret_key[64],
                           uint8_t public_key[32],
                           uint8_t seed[32]);
void ncrypt_eddsa_sign(uint8_t        signature [64],
                       const uint8_t  secret_key[64],
                       const uint8_t *message, size_t message_size);
int ncrypt_eddsa_check(const uint8_t  signature [64],
                       const uint8_t  public_key[32],
                       const uint8_t *message, size_t message_size);

// Conversion to X25519
void ncrypt_eddsa_to_x25519(uint8_t x25519[32], const uint8_t eddsa[32]);

// EdDSA building blocks
void ncrypt_eddsa_trim_scalar(uint8_t out[32], const uint8_t in[32]);
void ncrypt_eddsa_reduce(uint8_t reduced[32], const uint8_t expanded[64]);
void ncrypt_eddsa_mul_add(uint8_t r[32],
                          const uint8_t a[32],
                          const uint8_t b[32],
                          const uint8_t c[32]);
void ncrypt_eddsa_scalarbase(uint8_t point[32], const uint8_t scalar[32]);
int ncrypt_eddsa_check_equation(const uint8_t signature[64],
                                const uint8_t public_key[32],
                                const uint8_t h_ram[32]);


// Chacha20
// --------

// Specialised hash.
// Used to hash X25519 shared secrets.
void ncrypt_chacha20_h(uint8_t       out[32],
                       const uint8_t key[32],
                       const uint8_t in [16]);

// Unauthenticated stream cipher.
// Don't forget to add authentication.
uint64_t ncrypt_chacha20_djb(uint8_t       *cipher_text,
                             const uint8_t *plain_text,
                             size_t         text_size,
                             const uint8_t  key[32],
                             const uint8_t  nonce[8],
                             uint64_t       ctr);
uint32_t ncrypt_chacha20_ietf(uint8_t       *cipher_text,
                              const uint8_t *plain_text,
                              size_t         text_size,
                              const uint8_t  key[32],
                              const uint8_t  nonce[12],
                              uint32_t       ctr);
uint64_t ncrypt_chacha20_x(uint8_t       *cipher_text,
                           const uint8_t *plain_text,
                           size_t         text_size,
                           const uint8_t  key[32],
                           const uint8_t  nonce[24],
                           uint64_t       ctr);


// Poly 1305
// ---------

// This is a *one time* authenticator.
// Disclosing the mac reveals the key.
// See ncrypt_lock() on how to use it properly.

// Direct interface
void ncrypt_poly1305(uint8_t        mac[16],
                     const uint8_t *message, size_t message_size,
                     const uint8_t  key[32]);

// Incremental interface
typedef struct {
	// Do not rely on the size or contents of this type,
	// for they may change without notice.
	uint8_t  c[16];  // chunk of the message
	size_t   c_idx;  // How many bytes are there in the chunk.
	uint32_t r  [4]; // constant multiplier (from the secret key)
	uint32_t pad[4]; // random number added at the end (from the secret key)
	uint32_t h  [5]; // accumulated hash
} ncrypt_poly1305_ctx;

void ncrypt_poly1305_init  (ncrypt_poly1305_ctx *ctx, const uint8_t key[32]);
void ncrypt_poly1305_update(ncrypt_poly1305_ctx *ctx,
                            const uint8_t *message, size_t message_size);
void ncrypt_poly1305_final (ncrypt_poly1305_ctx *ctx, uint8_t mac[16]);


// Do not rely on the size or content on any of those types,
// they may change without notice.
typedef struct {
	uint64_t hash[8];
	uint64_t input[16];
	uint64_t input_size[2];
	size_t   input_idx;
} ncrypt_sha512_ctx;

typedef struct {
	uint8_t key[128];
	ncrypt_sha512_ctx ctx;
} ncrypt_sha512_hmac_ctx;


// SHA 512
// -------
void ncrypt_sha512_init  (ncrypt_sha512_ctx *ctx);
void ncrypt_sha512_update(ncrypt_sha512_ctx *ctx,
                          const uint8_t *message, size_t  message_size);
void ncrypt_sha512_final (ncrypt_sha512_ctx *ctx, uint8_t hash[64]);
void ncrypt_sha512(uint8_t hash[64],
                   const uint8_t *message, size_t message_size);

// SHA 512 HMAC
// ------------
void ncrypt_sha512_hmac_init(ncrypt_sha512_hmac_ctx *ctx,
                             const uint8_t *key, size_t key_size);
void ncrypt_sha512_hmac_update(ncrypt_sha512_hmac_ctx *ctx,
                               const uint8_t *message, size_t  message_size);
void ncrypt_sha512_hmac_final(ncrypt_sha512_hmac_ctx *ctx, uint8_t hmac[64]);
void ncrypt_sha512_hmac(uint8_t hmac[64],
                        const uint8_t *key    , size_t key_size,
                        const uint8_t *message, size_t message_size);

// SHA 512 HKDF
// ------------
void ncrypt_sha512_hkdf_expand(uint8_t       *okm,  size_t okm_size,
                               const uint8_t *prk,  size_t prk_size,
                               const uint8_t *info, size_t info_size);
void ncrypt_sha512_hkdf(uint8_t       *okm , size_t okm_size,
                        const uint8_t *ikm , size_t ikm_size,
                        const uint8_t *salt, size_t salt_size,
                        const uint8_t *info, size_t info_size);

// Ed25519
// -------
// Signatures (EdDSA with curve25519 + SHA-512)
// --------------------------------------------
void ncrypt_ed25519_key_pair(uint8_t secret_key[64],
                             uint8_t public_key[32],
                             uint8_t seed[32]);
void ncrypt_ed25519_sign(uint8_t        signature [64],
                         const uint8_t  secret_key[64],
                         const uint8_t *message, size_t message_size);
int ncrypt_ed25519_check(const uint8_t  signature [64],
                         const uint8_t  public_key[32],
                         const uint8_t *message, size_t message_size);

// Pre-hash variants
void ncrypt_ed25519_ph_sign(uint8_t       signature   [64],
                            const uint8_t secret_key  [64],
                            const uint8_t message_hash[64]);
int ncrypt_ed25519_ph_check(const uint8_t signature   [64],
                            const uint8_t public_key  [32],
                            const uint8_t message_hash[64]);

#ifdef __cplusplus
}
#endif

#endif // NCRYPT_H
