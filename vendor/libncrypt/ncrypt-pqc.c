// libncrypt -- post-quantum layer.
//
// The FIPS 202 core follows the public domain Keccak implementation
// used by the CRYSTALS reference code. The ML-KEM-768 and ML-DSA-44
// cores are derived from the pq-crystals/kyber and pq-crystals/dilithium
// reference implementations (see doc/PROVENANCE.md for exact commits).
// Everything except the ncrypt_* entry points is static, so this file
// can be linked next to other copies of Keccak, Kyber, or Dilithium.
//
// Portability: the arithmetic below assumes a two's complement C99
// implementation with 8-bit char, 16-bit int16_t, 32-bit int32_t, and
// arithmetic (sign-extending) right shift on negative signed values.
// Every compiler in practical use satisfies these assumptions, which
// are the same as those of the upstream reference code.
//
// Build this file together with ncrypt.c.

#include "ncrypt-pqc.h"
#include <string.h>

// Parameter sets. The reference cores support the other FIPS 203 and
// FIPS 204 sets as well, but the public API and its size constants are
// fixed to ML-KEM-768 and ML-DSA-44; a static check below rejects any
// other selection.
#define KYBER_K        3   // ML-KEM-768
#define DILITHIUM_MODE 2   // ML-DSA-44

////////////////
/// FIPS 202 ///
////////////////
#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72


typedef struct {
  uint64_t s[25];
  unsigned int pos;
} keccak_state;

static void shake128_init(keccak_state *state);
static void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
static void shake128_finalize(keccak_state *state);
static void shake128_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen);
static void shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state);

static void shake256_init(keccak_state *state);
static void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
static void shake256_finalize(keccak_state *state);
static void shake256_squeeze(uint8_t *out, size_t outlen, keccak_state *state);
static void shake256_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen);
static void shake256_squeezeblocks(uint8_t *out, size_t nblocks,  keccak_state *state);

static void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
static void sha3_256(uint8_t h[32], const uint8_t *in, size_t inlen);
static void sha3_512(uint8_t h[64], const uint8_t *in, size_t inlen);


// Keccak follows the FIPS 202 reference implementation.


#define NROUNDS 24
#define ROL(a, offset) (((a) << (offset)) ^ ((a) >> (64-(offset))))


static uint64_t load64(const uint8_t x[8]) {
  unsigned int i;
  uint64_t r = 0;

  for(i=0;i<8;i++)
    r |= (uint64_t)x[i] << 8*i;

  return r;
}


static void store64(uint8_t x[8], uint64_t u) {
  unsigned int i;

  for(i=0;i<8;i++)
    x[i] = (uint8_t)(u >> 8*i);
}

// Keccak round constants
static const uint64_t KeccakF_RoundConstants[NROUNDS] = {
  (uint64_t)0x0000000000000001ULL,
  (uint64_t)0x0000000000008082ULL,
  (uint64_t)0x800000000000808aULL,
  (uint64_t)0x8000000080008000ULL,
  (uint64_t)0x000000000000808bULL,
  (uint64_t)0x0000000080000001ULL,
  (uint64_t)0x8000000080008081ULL,
  (uint64_t)0x8000000000008009ULL,
  (uint64_t)0x000000000000008aULL,
  (uint64_t)0x0000000000000088ULL,
  (uint64_t)0x0000000080008009ULL,
  (uint64_t)0x000000008000000aULL,
  (uint64_t)0x000000008000808bULL,
  (uint64_t)0x800000000000008bULL,
  (uint64_t)0x8000000000008089ULL,
  (uint64_t)0x8000000000008003ULL,
  (uint64_t)0x8000000000008002ULL,
  (uint64_t)0x8000000000000080ULL,
  (uint64_t)0x000000000000800aULL,
  (uint64_t)0x800000008000000aULL,
  (uint64_t)0x8000000080008081ULL,
  (uint64_t)0x8000000000008080ULL,
  (uint64_t)0x0000000080000001ULL,
  (uint64_t)0x8000000080008008ULL
};


static void KeccakF1600_StatePermute(uint64_t state[25])
{
        int round;

        uint64_t Aba, Abe, Abi, Abo, Abu;
        uint64_t Aga, Age, Agi, Ago, Agu;
        uint64_t Aka, Ake, Aki, Ako, Aku;
        uint64_t Ama, Ame, Ami, Amo, Amu;
        uint64_t Asa, Ase, Asi, Aso, Asu;
        uint64_t BCa, BCe, BCi, BCo, BCu;
        uint64_t Da, De, Di, Do, Du;
        uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
        uint64_t Ega, Ege, Egi, Ego, Egu;
        uint64_t Eka, Eke, Eki, Eko, Eku;
        uint64_t Ema, Eme, Emi, Emo, Emu;
        uint64_t Esa, Ese, Esi, Eso, Esu;

        // Load the state into local variables.
        Aba = state[ 0];
        Abe = state[ 1];
        Abi = state[ 2];
        Abo = state[ 3];
        Abu = state[ 4];
        Aga = state[ 5];
        Age = state[ 6];
        Agi = state[ 7];
        Ago = state[ 8];
        Agu = state[ 9];
        Aka = state[10];
        Ake = state[11];
        Aki = state[12];
        Ako = state[13];
        Aku = state[14];
        Ama = state[15];
        Ame = state[16];
        Ami = state[17];
        Amo = state[18];
        Amu = state[19];
        Asa = state[20];
        Ase = state[21];
        Asi = state[22];
        Aso = state[23];
        Asu = state[24];

        for(round = 0; round < NROUNDS; round += 2) {
            // Compute the column parities for the theta step.
            BCa = Aba^Aga^Aka^Ama^Asa;
            BCe = Abe^Age^Ake^Ame^Ase;
            BCi = Abi^Agi^Aki^Ami^Asi;
            BCo = Abo^Ago^Ako^Amo^Aso;
            BCu = Abu^Agu^Aku^Amu^Asu;

            // Apply theta, rho, pi, chi, and iota to the first round.
            Da = BCu^ROL(BCe, 1);
            De = BCa^ROL(BCi, 1);
            Di = BCe^ROL(BCo, 1);
            Do = BCi^ROL(BCu, 1);
            Du = BCo^ROL(BCa, 1);

            Aba ^= Da;
            BCa = Aba;
            Age ^= De;
            BCe = ROL(Age, 44);
            Aki ^= Di;
            BCi = ROL(Aki, 43);
            Amo ^= Do;
            BCo = ROL(Amo, 21);
            Asu ^= Du;
            BCu = ROL(Asu, 14);
            Eba =   BCa ^((~BCe)&  BCi );
            Eba ^= (uint64_t)KeccakF_RoundConstants[round];
            Ebe =   BCe ^((~BCi)&  BCo );
            Ebi =   BCi ^((~BCo)&  BCu );
            Ebo =   BCo ^((~BCu)&  BCa );
            Ebu =   BCu ^((~BCa)&  BCe );

            Abo ^= Do;
            BCa = ROL(Abo, 28);
            Agu ^= Du;
            BCe = ROL(Agu, 20);
            Aka ^= Da;
            BCi = ROL(Aka,  3);
            Ame ^= De;
            BCo = ROL(Ame, 45);
            Asi ^= Di;
            BCu = ROL(Asi, 61);
            Ega =   BCa ^((~BCe)&  BCi );
            Ege =   BCe ^((~BCi)&  BCo );
            Egi =   BCi ^((~BCo)&  BCu );
            Ego =   BCo ^((~BCu)&  BCa );
            Egu =   BCu ^((~BCa)&  BCe );

            Abe ^= De;
            BCa = ROL(Abe,  1);
            Agi ^= Di;
            BCe = ROL(Agi,  6);
            Ako ^= Do;
            BCi = ROL(Ako, 25);
            Amu ^= Du;
            BCo = ROL(Amu,  8);
            Asa ^= Da;
            BCu = ROL(Asa, 18);
            Eka =   BCa ^((~BCe)&  BCi );
            Eke =   BCe ^((~BCi)&  BCo );
            Eki =   BCi ^((~BCo)&  BCu );
            Eko =   BCo ^((~BCu)&  BCa );
            Eku =   BCu ^((~BCa)&  BCe );

            Abu ^= Du;
            BCa = ROL(Abu, 27);
            Aga ^= Da;
            BCe = ROL(Aga, 36);
            Ake ^= De;
            BCi = ROL(Ake, 10);
            Ami ^= Di;
            BCo = ROL(Ami, 15);
            Aso ^= Do;
            BCu = ROL(Aso, 56);
            Ema =   BCa ^((~BCe)&  BCi );
            Eme =   BCe ^((~BCi)&  BCo );
            Emi =   BCi ^((~BCo)&  BCu );
            Emo =   BCo ^((~BCu)&  BCa );
            Emu =   BCu ^((~BCa)&  BCe );

            Abi ^= Di;
            BCa = ROL(Abi, 62);
            Ago ^= Do;
            BCe = ROL(Ago, 55);
            Aku ^= Du;
            BCi = ROL(Aku, 39);
            Ama ^= Da;
            BCo = ROL(Ama, 41);
            Ase ^= De;
            BCu = ROL(Ase,  2);
            Esa =   BCa ^((~BCe)&  BCi );
            Ese =   BCe ^((~BCi)&  BCo );
            Esi =   BCi ^((~BCo)&  BCu );
            Eso =   BCo ^((~BCu)&  BCa );
            Esu =   BCu ^((~BCa)&  BCe );

            // Compute the column parities for the second theta step.
            BCa = Eba^Ega^Eka^Ema^Esa;
            BCe = Ebe^Ege^Eke^Eme^Ese;
            BCi = Ebi^Egi^Eki^Emi^Esi;
            BCo = Ebo^Ego^Eko^Emo^Eso;
            BCu = Ebu^Egu^Eku^Emu^Esu;

            // Apply theta, rho, pi, chi, and iota to the second round.
            Da = BCu^ROL(BCe, 1);
            De = BCa^ROL(BCi, 1);
            Di = BCe^ROL(BCo, 1);
            Do = BCi^ROL(BCu, 1);
            Du = BCo^ROL(BCa, 1);

            Eba ^= Da;
            BCa = Eba;
            Ege ^= De;
            BCe = ROL(Ege, 44);
            Eki ^= Di;
            BCi = ROL(Eki, 43);
            Emo ^= Do;
            BCo = ROL(Emo, 21);
            Esu ^= Du;
            BCu = ROL(Esu, 14);
            Aba =   BCa ^((~BCe)&  BCi );
            Aba ^= (uint64_t)KeccakF_RoundConstants[round+1];
            Abe =   BCe ^((~BCi)&  BCo );
            Abi =   BCi ^((~BCo)&  BCu );
            Abo =   BCo ^((~BCu)&  BCa );
            Abu =   BCu ^((~BCa)&  BCe );

            Ebo ^= Do;
            BCa = ROL(Ebo, 28);
            Egu ^= Du;
            BCe = ROL(Egu, 20);
            Eka ^= Da;
            BCi = ROL(Eka, 3);
            Eme ^= De;
            BCo = ROL(Eme, 45);
            Esi ^= Di;
            BCu = ROL(Esi, 61);
            Aga =   BCa ^((~BCe)&  BCi );
            Age =   BCe ^((~BCi)&  BCo );
            Agi =   BCi ^((~BCo)&  BCu );
            Ago =   BCo ^((~BCu)&  BCa );
            Agu =   BCu ^((~BCa)&  BCe );

            Ebe ^= De;
            BCa = ROL(Ebe, 1);
            Egi ^= Di;
            BCe = ROL(Egi, 6);
            Eko ^= Do;
            BCi = ROL(Eko, 25);
            Emu ^= Du;
            BCo = ROL(Emu, 8);
            Esa ^= Da;
            BCu = ROL(Esa, 18);
            Aka =   BCa ^((~BCe)&  BCi );
            Ake =   BCe ^((~BCi)&  BCo );
            Aki =   BCi ^((~BCo)&  BCu );
            Ako =   BCo ^((~BCu)&  BCa );
            Aku =   BCu ^((~BCa)&  BCe );

            Ebu ^= Du;
            BCa = ROL(Ebu, 27);
            Ega ^= Da;
            BCe = ROL(Ega, 36);
            Eke ^= De;
            BCi = ROL(Eke, 10);
            Emi ^= Di;
            BCo = ROL(Emi, 15);
            Eso ^= Do;
            BCu = ROL(Eso, 56);
            Ama =   BCa ^((~BCe)&  BCi );
            Ame =   BCe ^((~BCi)&  BCo );
            Ami =   BCi ^((~BCo)&  BCu );
            Amo =   BCo ^((~BCu)&  BCa );
            Amu =   BCu ^((~BCa)&  BCe );

            Ebi ^= Di;
            BCa = ROL(Ebi, 62);
            Ego ^= Do;
            BCe = ROL(Ego, 55);
            Eku ^= Du;
            BCi = ROL(Eku, 39);
            Ema ^= Da;
            BCo = ROL(Ema, 41);
            Ese ^= De;
            BCu = ROL(Ese, 2);
            Asa =   BCa ^((~BCe)&  BCi );
            Ase =   BCe ^((~BCi)&  BCo );
            Asi =   BCi ^((~BCo)&  BCu );
            Aso =   BCo ^((~BCu)&  BCa );
            Asu =   BCu ^((~BCa)&  BCe );
        }

        // Store the permuted state.
        state[ 0] = Aba;
        state[ 1] = Abe;
        state[ 2] = Abi;
        state[ 3] = Abo;
        state[ 4] = Abu;
        state[ 5] = Aga;
        state[ 6] = Age;
        state[ 7] = Agi;
        state[ 8] = Ago;
        state[ 9] = Agu;
        state[10] = Aka;
        state[11] = Ake;
        state[12] = Aki;
        state[13] = Ako;
        state[14] = Aku;
        state[15] = Ama;
        state[16] = Ame;
        state[17] = Ami;
        state[18] = Amo;
        state[19] = Amu;
        state[20] = Asa;
        state[21] = Ase;
        state[22] = Asi;
        state[23] = Aso;
        state[24] = Asu;
}


static void keccak_init(uint64_t s[25])
{
  unsigned int i;
  for(i=0;i<25;i++)
    s[i] = 0;
}


static unsigned int keccak_absorb(uint64_t s[25],
                                  unsigned int pos,
                                  unsigned int r,
                                  const uint8_t *in,
                                  size_t inlen)
{
  unsigned int i;

  while(pos+inlen >= r) {
    for(i=pos;i<r;i++)
      s[i/8] ^= (uint64_t)*in++ << 8*(i%8);
    inlen -= r-pos;
    KeccakF1600_StatePermute(s);
    pos = 0;
  }

  for(i=pos;i<pos+inlen;i++)
    s[i/8] ^= (uint64_t)*in++ << 8*(i%8);

  return i;
}


static void keccak_finalize(uint64_t s[25], unsigned int pos, unsigned int r, uint8_t p)
{
  s[pos/8] ^= (uint64_t)p << 8*(pos%8);
  s[r/8-1] ^= 1ULL << 63;
}


static unsigned int keccak_squeeze(uint8_t *out,
                                   size_t outlen,
                                   uint64_t s[25],
                                   unsigned int pos,
                                   unsigned int r)
{
  unsigned int i;

  while(outlen) {
    if(pos == r) {
      KeccakF1600_StatePermute(s);
      pos = 0;
    }
    for(i=pos;i < r && i < pos+outlen; i++)
      *out++ = (uint8_t)(s[i/8] >> 8*(i%8));
    outlen -= i-pos;
    pos = i;
  }

  return pos;
}


static void keccak_absorb_once(uint64_t s[25],
                               unsigned int r,
                               const uint8_t *in,
                               size_t inlen,
                               uint8_t p)
{
  unsigned int i;

  for(i=0;i<25;i++)
    s[i] = 0;

  while(inlen >= r) {
    for(i=0;i<r/8;i++)
      s[i] ^= load64(in+8*i);
    in += r;
    inlen -= r;
    KeccakF1600_StatePermute(s);
  }

  for(i=0;i<inlen;i++)
    s[i/8] ^= (uint64_t)in[i] << 8*(i%8);

  s[i/8] ^= (uint64_t)p << 8*(i%8);
  s[(r-1)/8] ^= 1ULL << 63;
}


static void keccak_squeezeblocks(uint8_t *out,
                                 size_t nblocks,
                                 uint64_t s[25],
                                 unsigned int r)
{
  unsigned int i;

  while(nblocks) {
    KeccakF1600_StatePermute(s);
    for(i=0;i<r/8;i++)
      store64(out+8*i, s[i]);
    out += r;
    nblocks -= 1;
  }
}


static void shake128_init(keccak_state *state)
{
  keccak_init(state->s);
  state->pos = 0;
}


static void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen)
{
  state->pos = keccak_absorb(state->s, state->pos, SHAKE128_RATE, in, inlen);
}


static void shake128_finalize(keccak_state *state)
{
  keccak_finalize(state->s, state->pos, SHAKE128_RATE, 0x1F);
  state->pos = SHAKE128_RATE;
}


static void shake128_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen)
{
  keccak_absorb_once(state->s, SHAKE128_RATE, in, inlen, 0x1F);
  state->pos = SHAKE128_RATE;
}


static void shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state)
{
  keccak_squeezeblocks(out, nblocks, state->s, SHAKE128_RATE);
}


static void shake256_init(keccak_state *state)
{
  keccak_init(state->s);
  state->pos = 0;
}


static void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen)
{
  state->pos = keccak_absorb(state->s, state->pos, SHAKE256_RATE, in, inlen);
}


static void shake256_finalize(keccak_state *state)
{
  keccak_finalize(state->s, state->pos, SHAKE256_RATE, 0x1F);
  state->pos = SHAKE256_RATE;
}


static void shake256_squeeze(uint8_t *out, size_t outlen, keccak_state *state)
{
  state->pos = keccak_squeeze(out, outlen, state->s, state->pos, SHAKE256_RATE);
}


static void shake256_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen)
{
  keccak_absorb_once(state->s, SHAKE256_RATE, in, inlen, 0x1F);
  state->pos = SHAKE256_RATE;
}


static void shake256_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state)
{
  keccak_squeezeblocks(out, nblocks, state->s, SHAKE256_RATE);
}


static void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
  size_t nblocks;
  keccak_state state;

  shake256_absorb_once(&state, in, inlen);
  nblocks = outlen/SHAKE256_RATE;
  shake256_squeezeblocks(out, nblocks, &state);
  outlen -= nblocks*SHAKE256_RATE;
  out += nblocks*SHAKE256_RATE;
  shake256_squeeze(out, outlen, &state);
}


static void sha3_256(uint8_t h[32], const uint8_t *in, size_t inlen)
{
  unsigned int i;
  uint64_t s[25];

  keccak_absorb_once(s, SHA3_256_RATE, in, inlen, 0x06);
  KeccakF1600_StatePermute(s);
  for(i=0;i<4;i++)
    store64(h+8*i,s[i]);
}


static void sha3_512(uint8_t h[64], const uint8_t *in, size_t inlen)
{
  unsigned int i;
  uint64_t s[25];

  keccak_absorb_once(s, SHA3_512_RATE, in, inlen, 0x06);
  KeccakF1600_StatePermute(s);
  for(i=0;i<8;i++)
    store64(h+8*i,s[i]);
}

//////////////
/// ML-KEM ///
//////////////
// Parameter values below are fixed by the selected parameter set.
#if   (KYBER_K == 2)
#elif (KYBER_K == 3)
#elif (KYBER_K == 4)
#else
#error "KYBER_K must be in {2,3,4}"
#endif

#define KYBER_N 256
#define KYBER_Q 3329

#define KYBER_SYMBYTES 32   // Hash and seed size, in bytes.
#define KYBER_SSBYTES  32   // Shared-secret size, in bytes.

#define KYBER_POLYBYTES		384
#define KYBER_POLYVECBYTES	(KYBER_K * KYBER_POLYBYTES)

#if KYBER_K == 2
#define KYBER_ETA1 3
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 3
#define KYBER_ETA1 2
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 4
#define KYBER_ETA1 2
#define KYBER_POLYCOMPRESSEDBYTES    160
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 352)
#endif

#define KYBER_ETA2 2

#define KYBER_INDCPA_MSGBYTES       (KYBER_SYMBYTES)
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)
#define KYBER_INDCPA_BYTES          (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)

#define KYBER_PUBLICKEYBYTES  (KYBER_INDCPA_PUBLICKEYBYTES)
// Space reserved for H(pk).
#define KYBER_SECRETKEYBYTES  (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES)
#define KYBER_CIPHERTEXTBYTES (KYBER_INDCPA_BYTES)


#define MLKEM_MONT -1044 // Montgomery factor modulo q.
#define MLKEM_QINV -3327 // Negative modular inverse of q.

static int16_t mlkem_montgomery_reduce(int32_t a);

static int16_t mlkem_barrett_reduce(int16_t a);


static void mlkem_ntt(int16_t mlkem_poly[256]);

static void mlkem_invntt(int16_t mlkem_poly[256]);

static void mlkem_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);


// A polynomial is represented by 256 coefficients in Z_q[X]/(X^256 + 1).
typedef struct{
  int16_t coeffs[KYBER_N];
} mlkem_poly;

static void mlkem_poly_compress(uint8_t r[KYBER_POLYCOMPRESSEDBYTES], const mlkem_poly *a);
static void mlkem_poly_decompress(mlkem_poly *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES]);

static void mlkem_poly_tobytes(uint8_t r[KYBER_POLYBYTES], const mlkem_poly *a);
static void mlkem_poly_frombytes(mlkem_poly *r, const uint8_t a[KYBER_POLYBYTES]);

static void mlkem_poly_frommsg(mlkem_poly *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES]);
static void mlkem_poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const mlkem_poly *r);

static void mlkem_poly_getnoise_eta1(mlkem_poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);

static void mlkem_poly_getnoise_eta2(mlkem_poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);

static void mlkem_poly_ntt(mlkem_poly *r);
static void mlkem_poly_invntt_tomont(mlkem_poly *r);
static void mlkem_poly_basemul_montgomery(mlkem_poly *r, const mlkem_poly *a, const mlkem_poly *b);
static void mlkem_poly_tomont(mlkem_poly *r);

static void mlkem_poly_reduce(mlkem_poly *r);

static void mlkem_poly_add(mlkem_poly *r, const mlkem_poly *a, const mlkem_poly *b);
static void mlkem_poly_sub(mlkem_poly *r, const mlkem_poly *a, const mlkem_poly *b);


static void mlkem_poly_cbd_eta1(mlkem_poly *r, const uint8_t buf[KYBER_ETA1*KYBER_N/4]);

static void mlkem_poly_cbd_eta2(mlkem_poly *r, const uint8_t buf[KYBER_ETA2*KYBER_N/4]);


typedef struct{
  mlkem_poly vec[KYBER_K];
} mlkem_polyvec;

static void mlkem_polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES], const mlkem_polyvec *a);
static void mlkem_polyvec_decompress(mlkem_polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES]);

static void mlkem_polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const mlkem_polyvec *a);
static void mlkem_polyvec_frombytes(mlkem_polyvec *r, const uint8_t a[KYBER_POLYVECBYTES]);

static void mlkem_polyvec_ntt(mlkem_polyvec *r);
static void mlkem_polyvec_invntt_tomont(mlkem_polyvec *r);

static void mlkem_polyvec_basemul_acc_montgomery(mlkem_poly *r, const mlkem_polyvec *a, const mlkem_polyvec *b);

static void mlkem_polyvec_reduce(mlkem_polyvec *r);

static void mlkem_polyvec_add(mlkem_polyvec *r, const mlkem_polyvec *a, const mlkem_polyvec *b);


static int mlkem_verify(const uint8_t *a, const uint8_t *b, size_t len);

static void mlkem_cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b);

static void mlkem_cmov_int16(int16_t *r, int16_t v, uint16_t b);


typedef keccak_state mlkem_xof_state;

static void mlkem_shake128_absorb(keccak_state *s,
                           const uint8_t seed[KYBER_SYMBYTES],
                           uint8_t x,
                           uint8_t y);

static void mlkem_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce);

static void mlkem_shake256_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]);

#define XOF_BLOCKBYTES SHAKE128_RATE

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) mlkem_shake128_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) mlkem_shake256_prf(OUT, OUTBYTES, KEY, NONCE)
#define rkprf(OUT, KEY, INPUT) mlkem_shake256_rkprf(OUT, KEY, INPUT)


static void mlkem_gen_matrix(mlkem_polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed);

static void mlkem_indcpa_keypair_derand(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                           uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                           const uint8_t coins[KYBER_SYMBYTES]);

static void mlkem_indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES]);

static void mlkem_indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);


// The public header hard-codes the ML-KEM-768 sizes.
#if KYBER_PUBLICKEYBYTES  != NCRYPT_MLKEM768_PUBLIC_KEY_SIZE || \
    KYBER_SECRETKEYBYTES  != NCRYPT_MLKEM768_SECRET_KEY_SIZE || \
    KYBER_CIPHERTEXTBYTES != NCRYPT_MLKEM768_CIPHERTEXT_SIZE || \
    KYBER_SSBYTES         != NCRYPT_MLKEM768_SHARED_SECRET_SIZE
#error "ML-KEM parameter set does not match ncrypt-pqc.h"
#endif

static int mlkem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);


static int mlkem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);


static int mlkem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);


static int16_t mlkem_montgomery_reduce(int32_t a)
{
  int16_t t;

  t = (int16_t)((int16_t)a*MLKEM_QINV);
  // |a| < q*2^15, so (a - t*q) is a multiple of 2^16 with |.| < 2^31,
  // and the shifted value fits in 16 bits.
  t = (int16_t)((a - (int32_t)t*KYBER_Q) >> 16);
  return t;
}


static int16_t mlkem_barrett_reduce(int16_t a) {
  int16_t t;
  const int16_t v = ((1<<26) + KYBER_Q/2)/KYBER_Q;

  // v*a + 2^25 stays below 2^31 in magnitude for every int16 a, and
  // the result is in {-1, 0, 1, 2}.
  t  = (int16_t)(((int32_t)v*a + (1<<25)) >> 26);
  t *= KYBER_Q;
  return a - t;
}


// The constants below are generated from the ML-KEM root of unity.

static const int16_t mlkem_zetas[128] = {
  -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
   -171,   622,  1577,   182,   962, -1202, -1474,  1468,
    573, -1325,   264,   383,  -829,  1458, -1602,  -130,
   -681,  1017,   732,   608, -1542,   411,  -205, -1571,
   1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
    516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
   -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
   -398,   961, -1508,  -725,   448, -1065,   677, -1275,
  -1103,   430,   555,   843, -1251,   871,  1550,   105,
    422,   587,   177,  -235,  -291,  -460,  1574,  1653,
   -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
  -1590,   644,  -872,   349,   418,   329,  -156,   -75,
    817,  1097,   603,   610,  1322, -1285, -1465,   384,
  -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
  -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
   -108,  -308,   996,   991,   958, -1460,  1522,  1628
};


static int16_t fqmul(int16_t a, int16_t b) {
  return mlkem_montgomery_reduce((int32_t)a*b);
}


static void mlkem_ntt(int16_t r[256]) {
  unsigned int len, start, j, k;
  int16_t t, zeta;

  k = 1;
  for(len = 128; len >= 2; len >>= 1) {
    for(start = 0; start < 256; start = j + len) {
      zeta = mlkem_zetas[k++];
      for(j = start; j < start + len; j++) {
        t = fqmul(zeta, r[j + len]);
        r[j + len] = r[j] - t;
        r[j] = r[j] + t;
      }
    }
  }
}


static void mlkem_invntt(int16_t r[256]) {
  unsigned int start, len, j, k;
  int16_t t, zeta;
  const int16_t f = 1441; // Montgomery factor squared divided by 128.

  k = 127;
  for(len = 2; len <= 128; len <<= 1) {
    for(start = 0; start < 256; start = j + len) {
      zeta = mlkem_zetas[k--];
      for(j = start; j < start + len; j++) {
        t = r[j];
        r[j] = mlkem_barrett_reduce(t + r[j + len]);
        r[j + len] = r[j + len] - t;
        r[j + len] = fqmul(zeta, r[j + len]);
      }
    }
  }

  for(j = 0; j < 256; j++)
    r[j] = fqmul(r[j], f);
}


static void mlkem_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta)
{
  r[0]  = fqmul(a[1], b[1]);
  r[0]  = fqmul(r[0], zeta);
  r[0] += fqmul(a[0], b[0]);
  r[1]  = fqmul(a[0], b[1]);
  r[1] += fqmul(a[1], b[0]);
}


static uint32_t load32_littleendian(const uint8_t x[4])
{
  uint32_t r;
  r  = (uint32_t)x[0];
  r |= (uint32_t)x[1] << 8;
  r |= (uint32_t)x[2] << 16;
  r |= (uint32_t)x[3] << 24;
  return r;
}


#if KYBER_ETA1 == 3
static uint32_t load24_littleendian(const uint8_t x[3])
{
  uint32_t r;
  r  = (uint32_t)x[0];
  r |= (uint32_t)x[1] << 8;
  r |= (uint32_t)x[2] << 16;
  return r;
}
#endif


static void cbd2(mlkem_poly *r, const uint8_t buf[2*KYBER_N/4])
{
  unsigned int i,j;
  uint32_t t,d;
  int16_t a,b;

  for(i=0;i<KYBER_N/8;i++) {
    t  = load32_littleendian(buf+4*i);
    d  = t & 0x55555555;
    d += (t>>1) & 0x55555555;

    for(j=0;j<8;j++) {
      a = (d >> (4*j+0)) & 0x3;
      b = (d >> (4*j+2)) & 0x3;
      r->coeffs[8*i+j] = a - b;
    }
  }
}


#if KYBER_ETA1 == 3
static void cbd3(mlkem_poly *r, const uint8_t buf[3*KYBER_N/4])
{
  unsigned int i,j;
  uint32_t t,d;
  int16_t a,b;

  for(i=0;i<KYBER_N/4;i++) {
    t  = load24_littleendian(buf+3*i);
    d  = t & 0x00249249;
    d += (t>>1) & 0x00249249;
    d += (t>>2) & 0x00249249;

    for(j=0;j<4;j++) {
      a = (d >> (6*j+0)) & 0x7;
      b = (d >> (6*j+3)) & 0x7;
      r->coeffs[4*i+j] = a - b;
    }
  }
}
#endif

static void mlkem_poly_cbd_eta1(mlkem_poly *r, const uint8_t buf[KYBER_ETA1*KYBER_N/4])
{
#if KYBER_ETA1 == 2
  cbd2(r, buf);
#elif KYBER_ETA1 == 3
  cbd3(r, buf);
#else
#error "This implementation requires eta1 in {2,3}"
#endif
}

static void mlkem_poly_cbd_eta2(mlkem_poly *r, const uint8_t buf[KYBER_ETA2*KYBER_N/4])
{
#if KYBER_ETA2 == 2
  cbd2(r, buf);
#else
#error "This implementation requires eta2 = 2"
#endif
}


static void mlkem_poly_compress(uint8_t r[KYBER_POLYCOMPRESSEDBYTES], const mlkem_poly *a)
{
  unsigned int i,j;
  int32_t u;
  uint32_t d0;
  uint8_t t[8];

#if (KYBER_POLYCOMPRESSEDBYTES == 128)

  for(i=0;i<KYBER_N/8;i++) {
    for(j=0;j<8;j++) {
      // Move into the standard representative range.
      u  = a->coeffs[8*i+j];
      u += (u >> 15) & KYBER_Q;

      d0 = (uint32_t)u << 4;
      d0 += 1665;
      d0 *= 80635;
      d0 >>= 28;
      t[j] = (uint8_t)(d0 & 0xf);
    }

    r[0] = (uint8_t)(t[0] | (t[1] << 4));
    r[1] = (uint8_t)(t[2] | (t[3] << 4));
    r[2] = (uint8_t)(t[4] | (t[5] << 4));
    r[3] = (uint8_t)(t[6] | (t[7] << 4));
    r += 4;
  }
#elif (KYBER_POLYCOMPRESSEDBYTES == 160)
  for(i=0;i<KYBER_N/8;i++) {
    for(j=0;j<8;j++) {
      // Move into the standard representative range.
      u  = a->coeffs[8*i+j];
      u += (u >> 15) & KYBER_Q;

      d0 = (uint32_t)u << 5;
      d0 += 1664;
      d0 *= 40318;
      d0 >>= 27;
      t[j] = (uint8_t)(d0 & 0x1f);
    }

    r[0] = (uint8_t)((t[0] >> 0) | (t[1] << 5));
    r[1] = (uint8_t)((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
    r[2] = (uint8_t)((t[3] >> 1) | (t[4] << 4));
    r[3] = (uint8_t)((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
    r[4] = (uint8_t)((t[6] >> 2) | (t[7] << 3));
    r += 5;
  }
#else
#error "KYBER_POLYCOMPRESSEDBYTES needs to be in {128, 160}"
#endif
}


static void mlkem_poly_decompress(mlkem_poly *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES])
{
  unsigned int i;

#if (KYBER_POLYCOMPRESSEDBYTES == 128)
  for(i=0;i<KYBER_N/2;i++) {
    // (15*q + 8) >> 4 < q, so the results fit in int16_t.
    r->coeffs[2*i+0] = (int16_t)((((uint16_t)(a[0] & 15)*KYBER_Q) + 8) >> 4);
    r->coeffs[2*i+1] = (int16_t)((((uint16_t)(a[0] >> 4)*KYBER_Q) + 8) >> 4);
    a += 1;
  }
#elif (KYBER_POLYCOMPRESSEDBYTES == 160)
  unsigned int j;
  uint8_t t[8];
  for(i=0;i<KYBER_N/8;i++) {
    t[0] = (a[0] >> 0);
    t[1] = (a[0] >> 5) | (a[1] << 3);
    t[2] = (a[1] >> 2);
    t[3] = (a[1] >> 7) | (a[2] << 1);
    t[4] = (a[2] >> 4) | (a[3] << 4);
    t[5] = (a[3] >> 1);
    t[6] = (a[3] >> 6) | (a[4] << 2);
    t[7] = (a[4] >> 3);
    a += 5;

    for(j=0;j<8;j++) {
      // Same reasoning as in mlkem_poly_frombytes: mask the value.
      uint32_t c = t[j] & 31;
      r->coeffs[8*i+j] = (int16_t)((c*KYBER_Q + 16) >> 5);
    }
  }
#else
#error "KYBER_POLYCOMPRESSEDBYTES needs to be in {128, 160}"
#endif
}


static void mlkem_poly_tobytes(uint8_t r[KYBER_POLYBYTES], const mlkem_poly *a)
{
  unsigned int i;
  uint16_t t0, t1;

  for(i=0;i<KYBER_N/2;i++) {
    // Move into the standard representative range.
    t0  = (uint16_t)a->coeffs[2*i];
    t0  = (uint16_t)(t0 + (((int16_t)t0 >> 15) & KYBER_Q));
    t1  = (uint16_t)a->coeffs[2*i+1];
    t1  = (uint16_t)(t1 + (((int16_t)t1 >> 15) & KYBER_Q));
    r[3*i+0] = (uint8_t)(t0 >> 0);
    r[3*i+1] = (uint8_t)((t0 >> 8) | (t1 << 4));
    r[3*i+2] = (uint8_t)(t1 >> 4);
  }
}


static void mlkem_poly_frombytes(mlkem_poly *r, const uint8_t a[KYBER_POLYBYTES])
{
  unsigned int i;
  uint16_t t0, t1;
  for(i=0;i<KYBER_N/2;i++) {
    // Mask the decoded values rather than the array index: an index
    // expression of the form `x & 0xFFF` is itself computed from data
    // the compiler may not prove bounded, and it is one of the shapes
    // that has been observed to compile into a value dependent
    // address.  The result is identical.
    t0 = (uint16_t)((a[3*i+0] >> 0) | ((uint16_t)a[3*i+1] << 8));
    t1 = (uint16_t)((a[3*i+1] >> 4) | ((uint16_t)a[3*i+2] << 4));
    r->coeffs[2*i]   = (int16_t)(t0 & 0xFFF);
    r->coeffs[2*i+1] = (int16_t)(t1 & 0xFFF);
  }
}


static void mlkem_poly_frommsg(mlkem_poly *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES])
{
  unsigned int i,j;

#if (KYBER_INDCPA_MSGBYTES != KYBER_N/8)
#error "KYBER_INDCPA_MSGBYTES must be equal to KYBER_N/8 bytes!"
#endif

  for(i=0;i<KYBER_N/8;i++) {
    for(j=0;j<8;j++) {
      r->coeffs[8*i+j] = 0;
      mlkem_cmov_int16(r->coeffs+8*i+j, ((KYBER_Q+1)/2), (msg[i] >> j)&1);
    }
  }
}


static void mlkem_poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const mlkem_poly *a)
{
  unsigned int i,j;
  uint32_t t;

  for(i=0;i<KYBER_N/8;i++) {
    msg[i] = 0;
    for(j=0;j<8;j++) {
      // The coefficient is in [0, q) after mlkem_poly_reduce.
      t  = (uint32_t)a->coeffs[8*i+j];
      t <<= 1;
      t += 1665;
      t *= 80635;
      t >>= 28;
      t &= 1;
      msg[i] = (uint8_t)(msg[i] | (t << j));
    }
  }
}


static void mlkem_poly_getnoise_eta1(mlkem_poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce)
{
  uint8_t buf[KYBER_ETA1*KYBER_N/4];
  prf(buf, sizeof(buf), seed, nonce);
  mlkem_poly_cbd_eta1(r, buf);
}


static void mlkem_poly_getnoise_eta2(mlkem_poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce)
{
  uint8_t buf[KYBER_ETA2*KYBER_N/4];
  prf(buf, sizeof(buf), seed, nonce);
  mlkem_poly_cbd_eta2(r, buf);
}


static void mlkem_poly_ntt(mlkem_poly *r)
{
  mlkem_ntt(r->coeffs);
  mlkem_poly_reduce(r);
}


static void mlkem_poly_invntt_tomont(mlkem_poly *r)
{
  mlkem_invntt(r->coeffs);
}


static void mlkem_poly_basemul_montgomery(mlkem_poly *r, const mlkem_poly *a, const mlkem_poly *b)
{
  unsigned int i;
  for(i=0;i<KYBER_N/4;i++) {
    mlkem_basemul(&r->coeffs[4*i], &a->coeffs[4*i], &b->coeffs[4*i], mlkem_zetas[64+i]);
    mlkem_basemul(&r->coeffs[4*i+2], &a->coeffs[4*i+2], &b->coeffs[4*i+2], -mlkem_zetas[64+i]);
  }
}


static void mlkem_poly_tomont(mlkem_poly *r)
{
  unsigned int i;
  const int16_t f = (1ULL << 32) % KYBER_Q;
  for(i=0;i<KYBER_N;i++)
    r->coeffs[i] = mlkem_montgomery_reduce((int32_t)r->coeffs[i]*f);
}


static void mlkem_poly_reduce(mlkem_poly *r)
{
  unsigned int i;
  for(i=0;i<KYBER_N;i++)
    r->coeffs[i] = mlkem_barrett_reduce(r->coeffs[i]);
}


static void mlkem_poly_add(mlkem_poly *r, const mlkem_poly *a, const mlkem_poly *b)
{
  unsigned int i;
  for(i=0;i<KYBER_N;i++)
    r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}


static void mlkem_poly_sub(mlkem_poly *r, const mlkem_poly *a, const mlkem_poly *b)
{
  unsigned int i;
  for(i=0;i<KYBER_N;i++)
    r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}


static void mlkem_polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES], const mlkem_polyvec *a)
{
  unsigned int i,j,k;
  uint64_t d0;

#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))
  uint16_t t[8];
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/8;j++) {
      for(k=0;k<8;k++) {
        t[k]  = (uint16_t)a->vec[i].coeffs[8*j+k];
        t[k]  = (uint16_t)(t[k] + (((int16_t)t[k] >> 15) & KYBER_Q));

        d0 = t[k];
        d0 <<= 11;
        d0 += 1664;
        d0 *= 645084;
        d0 >>= 31;
        t[k] = (uint16_t)(d0 & 0x7ff);
      }

      r[ 0] = (uint8_t)(t[0] >>  0);
      r[ 1] = (uint8_t)((t[0] >>  8) | (t[1] << 3));
      r[ 2] = (uint8_t)((t[1] >>  5) | (t[2] << 6));
      r[ 3] = (uint8_t)(t[2] >>  2);
      r[ 4] = (uint8_t)((t[2] >> 10) | (t[3] << 1));
      r[ 5] = (uint8_t)((t[3] >>  7) | (t[4] << 4));
      r[ 6] = (uint8_t)((t[4] >>  4) | (t[5] << 7));
      r[ 7] = (uint8_t)(t[5] >>  1);
      r[ 8] = (uint8_t)((t[5] >>  9) | (t[6] << 2));
      r[ 9] = (uint8_t)((t[6] >>  6) | (t[7] << 5));
      r[10] = (uint8_t)(t[7] >>  3);
      r += 11;
    }
  }
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320))
  uint16_t t[4];
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/4;j++) {
      for(k=0;k<4;k++) {
        t[k]  = (uint16_t)a->vec[i].coeffs[4*j+k];
        t[k]  = (uint16_t)(t[k] + (((int16_t)t[k] >> 15) & KYBER_Q));

        d0 = t[k];
        d0 <<= 10;
        d0 += 1665;
        d0 *= 1290167;
        d0 >>= 32;
        t[k] = (uint16_t)(d0 & 0x3ff);
      }

      r[0] = (uint8_t)(t[0] >> 0);
      r[1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
      r[2] = (uint8_t)((t[1] >> 6) | (t[2] << 4));
      r[3] = (uint8_t)((t[2] >> 4) | (t[3] << 6));
      r[4] = (uint8_t)(t[3] >> 2);
      r += 5;
    }
  }
#else
#error "KYBER_POLYVECCOMPRESSEDBYTES needs to be in {320*KYBER_K, 352*KYBER_K}"
#endif
}


static void mlkem_polyvec_decompress(mlkem_polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES])
{
  unsigned int i,j,k;

#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))
  uint16_t t[8];
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/8;j++) {
      t[0] = (a[0] >> 0) | ((uint16_t)a[ 1] << 8);
      t[1] = (a[1] >> 3) | ((uint16_t)a[ 2] << 5);
      t[2] = (a[2] >> 6) | ((uint16_t)a[ 3] << 2) | ((uint16_t)a[4] << 10);
      t[3] = (a[4] >> 1) | ((uint16_t)a[ 5] << 7);
      t[4] = (a[5] >> 4) | ((uint16_t)a[ 6] << 4);
      t[5] = (a[6] >> 7) | ((uint16_t)a[ 7] << 1) | ((uint16_t)a[8] << 9);
      t[6] = (a[8] >> 2) | ((uint16_t)a[ 9] << 6);
      t[7] = (a[9] >> 5) | ((uint16_t)a[10] << 3);
      a += 11;

      for(k=0;k<8;k++) {
        // Mask the value, not the index (see mlkem_poly_frombytes).
        uint32_t c = t[k] & 0x7FF;
        r->vec[i].coeffs[8*j+k] = (int16_t)((c*KYBER_Q + 1024) >> 11);
      }
    }
  }
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320))
  uint16_t t[4];
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/4;j++) {
      // The shifted bytes are promoted to int; the cast keeps the
      // narrowing conversion to uint16_t explicit (see DESIGN.md).
      t[0] = (uint16_t)((a[0] >> 0) | ((uint16_t)a[1] << 8));
      t[1] = (uint16_t)((a[1] >> 2) | ((uint16_t)a[2] << 6));
      t[2] = (uint16_t)((a[2] >> 4) | ((uint16_t)a[3] << 4));
      t[3] = (uint16_t)((a[3] >> 6) | ((uint16_t)a[4] << 2));
      a += 5;

      for(k=0;k<4;k++) {
        // Mask the value, not the index (see mlkem_poly_frombytes).
        uint32_t c = t[k] & 0x3FF;
        r->vec[i].coeffs[4*j+k] = (int16_t)((c*KYBER_Q + 512) >> 10);
      }
    }
  }
#else
#error "KYBER_POLYVECCOMPRESSEDBYTES needs to be in {320*KYBER_K, 352*KYBER_K}"
#endif
}


static void mlkem_polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const mlkem_polyvec *a)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    mlkem_poly_tobytes(r+i*KYBER_POLYBYTES, &a->vec[i]);
}


static void mlkem_polyvec_frombytes(mlkem_polyvec *r, const uint8_t a[KYBER_POLYVECBYTES])
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    mlkem_poly_frombytes(&r->vec[i], a+i*KYBER_POLYBYTES);
}


static void mlkem_polyvec_ntt(mlkem_polyvec *r)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    mlkem_poly_ntt(&r->vec[i]);
}


static void mlkem_polyvec_invntt_tomont(mlkem_polyvec *r)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    mlkem_poly_invntt_tomont(&r->vec[i]);
}


static void mlkem_polyvec_basemul_acc_montgomery(mlkem_poly *r, const mlkem_polyvec *a, const mlkem_polyvec *b)
{
  unsigned int i;
  mlkem_poly t;

  mlkem_poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
  for(i=1;i<KYBER_K;i++) {
    mlkem_poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
    mlkem_poly_add(r, r, &t);
  }

  mlkem_poly_reduce(r);
}


static void mlkem_polyvec_reduce(mlkem_polyvec *r)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    mlkem_poly_reduce(&r->vec[i]);
}


static void mlkem_polyvec_add(mlkem_polyvec *r, const mlkem_polyvec *a, const mlkem_polyvec *b)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    mlkem_poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
}


static int mlkem_verify(const uint8_t *a, const uint8_t *b, size_t len)
{
  size_t i;
  uint8_t r = 0;

  for(i=0;i<len;i++)
    r |= a[i] ^ b[i];

  return (int)((-(uint64_t)r) >> 63);
}


// The asm statement hides b from the optimiser. Otherwise a compiler
// may infer that b is 0 or 1 and turn the mask arithmetic into a
// branch, which would leak the decapsulation result through timing.
static void mlkem_cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b)
{
  size_t i;

#if defined(__GNUC__) || defined(__clang__)
  __asm__("" : "+r"(b) : );
#endif
  b = (uint8_t)-b;
  for(i=0;i<len;i++)
    r[i] = (uint8_t)(r[i] ^ (b & (r[i] ^ x[i])));
}


static void mlkem_cmov_int16(int16_t *r, int16_t v, uint16_t b)
{
#if defined(__GNUC__) || defined(__clang__)
  __asm__("" : "+r"(b) : );
#endif
  b = (uint16_t)-b;
  *r = (int16_t)(*r ^ (b & ((*r) ^ v)));
}


static void mlkem_shake128_absorb(keccak_state *state,
                           const uint8_t seed[KYBER_SYMBYTES],
                           uint8_t x,
                           uint8_t y)
{
  uint8_t extseed[KYBER_SYMBYTES+2];

  memcpy(extseed, seed, KYBER_SYMBYTES);
  extseed[KYBER_SYMBYTES+0] = x;
  extseed[KYBER_SYMBYTES+1] = y;

  shake128_absorb_once(state, extseed, sizeof(extseed));
}


static void mlkem_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce)
{
  uint8_t extkey[KYBER_SYMBYTES+1];

  memcpy(extkey, key, KYBER_SYMBYTES);
  extkey[KYBER_SYMBYTES] = nonce;

  shake256(out, outlen, extkey, sizeof(extkey));
}


static void mlkem_shake256_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES])
{
  keccak_state s;

  shake256_init(&s);
  shake256_absorb(&s, key, KYBER_SYMBYTES);
  shake256_absorb(&s, input, KYBER_CIPHERTEXTBYTES);
  shake256_finalize(&s);
  shake256_squeeze(out, KYBER_SSBYTES, &s);
}


static void pack_pk(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES],
                    mlkem_polyvec *pk,
                    const uint8_t seed[KYBER_SYMBYTES])
{
  mlkem_polyvec_tobytes(r, pk);
  memcpy(r+KYBER_POLYVECBYTES, seed, KYBER_SYMBYTES);
}


static void unpack_pk(mlkem_polyvec *pk,
                      uint8_t seed[KYBER_SYMBYTES],
                      const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES])
{
  mlkem_polyvec_frombytes(pk, packedpk);
  memcpy(seed, packedpk+KYBER_POLYVECBYTES, KYBER_SYMBYTES);
}


static void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], mlkem_polyvec *sk)
{
  mlkem_polyvec_tobytes(r, sk);
}


static void unpack_sk(mlkem_polyvec *sk, const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES])
{
  mlkem_polyvec_frombytes(sk, packedsk);
}


static void pack_ciphertext(uint8_t r[KYBER_INDCPA_BYTES], mlkem_polyvec *b, mlkem_poly *v)
{
  mlkem_polyvec_compress(r, b);
  mlkem_poly_compress(r+KYBER_POLYVECCOMPRESSEDBYTES, v);
}


static void unpack_ciphertext(mlkem_polyvec *b, mlkem_poly *v, const uint8_t c[KYBER_INDCPA_BYTES])
{
  mlkem_polyvec_decompress(b, c);
  mlkem_poly_decompress(v, c+KYBER_POLYVECCOMPRESSEDBYTES);
}


static unsigned int mlkem_rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen)
{
  unsigned int ctr, pos;
  uint16_t val0, val1;

  ctr = pos = 0;
  while(ctr < len && pos + 3 <= buflen) {
    val0 = ((buf[pos+0] >> 0) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
    val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
    pos += 3;

    if(val0 < KYBER_Q)
      r[ctr++] = (int16_t)val0;
    if(ctr < len && val1 < KYBER_Q)
      r[ctr++] = (int16_t)val1;
  }

  return ctr;
}

#define gen_a(A,B)  mlkem_gen_matrix(A,B,0)
#define gen_at(A,B) mlkem_gen_matrix(A,B,1)


#if(XOF_BLOCKBYTES % 3)
#error "Implementation of mlkem_gen_matrix assumes that XOF_BLOCKBYTES is a multiple of 3"
#endif

#define GEN_MATRIX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)
// Matrix generation is private to this translation unit.
static void mlkem_gen_matrix(mlkem_polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed)
{
  unsigned int ctr, i, j;
  unsigned int buflen;
  uint8_t buf[GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES];
  mlkem_xof_state state;

  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_K;j++) {
      if(transposed)
        xof_absorb(&state, seed, (uint8_t)i, (uint8_t)j);
      else
        xof_absorb(&state, seed, (uint8_t)j, (uint8_t)i);

      xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
      buflen = GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES;
      ctr = mlkem_rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, buflen);

      while(ctr < KYBER_N) {
        xof_squeezeblocks(buf, 1, &state);
        buflen = XOF_BLOCKBYTES;
        ctr += mlkem_rej_uniform(a[i].vec[j].coeffs + ctr, KYBER_N - ctr, buf, buflen);
      }
    }
  }
}


static void mlkem_indcpa_keypair_derand(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                           uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                           const uint8_t coins[KYBER_SYMBYTES])
{
  unsigned int i;
  uint8_t buf[2*KYBER_SYMBYTES];
  const uint8_t *publicseed = buf;
  const uint8_t *noiseseed = buf+KYBER_SYMBYTES;
  uint8_t nonce = 0;
  mlkem_polyvec a[KYBER_K], e, pkpv, skpv;

  memcpy(buf, coins, KYBER_SYMBYTES);
  buf[KYBER_SYMBYTES] = KYBER_K;
  hash_g(buf, buf, KYBER_SYMBYTES+1);

  gen_a(a, publicseed);

  for(i=0;i<KYBER_K;i++)
    mlkem_poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);
  for(i=0;i<KYBER_K;i++)
    mlkem_poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);

  mlkem_polyvec_ntt(&skpv);
  mlkem_polyvec_ntt(&e);

  // Compute the matrix-vector product.
  for(i=0;i<KYBER_K;i++) {
    mlkem_polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
    mlkem_poly_tomont(&pkpv.vec[i]);
  }

  mlkem_polyvec_add(&pkpv, &pkpv, &e);
  mlkem_polyvec_reduce(&pkpv);

  pack_sk(sk, &skpv);
  pack_pk(pk, &pkpv, publicseed);

  ncrypt_wipe(buf,   sizeof buf);
  ncrypt_wipe(&skpv, sizeof skpv);
  ncrypt_wipe(&e,    sizeof e);
}


static void mlkem_indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES])
{
  unsigned int i;
  uint8_t seed[KYBER_SYMBYTES];
  uint8_t nonce = 0;
  mlkem_polyvec sp, pkpv, ep, at[KYBER_K], b;
  mlkem_poly v, k, epp;

  unpack_pk(&pkpv, seed, pk);
  mlkem_poly_frommsg(&k, m);
  gen_at(at, seed);

  for(i=0;i<KYBER_K;i++)
    mlkem_poly_getnoise_eta1(sp.vec+i, coins, nonce++);
  for(i=0;i<KYBER_K;i++)
    mlkem_poly_getnoise_eta2(ep.vec+i, coins, nonce++);
  mlkem_poly_getnoise_eta2(&epp, coins, nonce++);

  mlkem_polyvec_ntt(&sp);

  // Compute the matrix-vector product.
  for(i=0;i<KYBER_K;i++)
    mlkem_polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);

  mlkem_polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);

  mlkem_polyvec_invntt_tomont(&b);
  mlkem_poly_invntt_tomont(&v);

  mlkem_polyvec_add(&b, &b, &ep);
  mlkem_poly_add(&v, &v, &epp);
  mlkem_poly_add(&v, &v, &k);
  mlkem_polyvec_reduce(&b);
  mlkem_poly_reduce(&v);

  pack_ciphertext(c, &b, &v);

  ncrypt_wipe(&sp,  sizeof sp);
  ncrypt_wipe(&ep,  sizeof ep);
  ncrypt_wipe(&epp, sizeof epp);
  ncrypt_wipe(&k,   sizeof k);
  ncrypt_wipe(&v,   sizeof v);
}


static void mlkem_indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES])
{
  mlkem_polyvec b, skpv;
  mlkem_poly v, mp;

  unpack_ciphertext(&b, &v, c);
  unpack_sk(&skpv, sk);

  mlkem_polyvec_ntt(&b);
  mlkem_polyvec_basemul_acc_montgomery(&mp, &skpv, &b);
  mlkem_poly_invntt_tomont(&mp);

  mlkem_poly_sub(&mp, &v, &mp);
  mlkem_poly_reduce(&mp);

  mlkem_poly_tomsg(m, &mp);

  ncrypt_wipe(&skpv, sizeof skpv);
  ncrypt_wipe(&mp,   sizeof mp);
  ncrypt_wipe(&v,    sizeof v);
}


static int mlkem_keypair_derand(uint8_t *pk,
                              uint8_t *sk,
                              const uint8_t *coins)
{
  mlkem_indcpa_keypair_derand(pk, sk, coins);
  memcpy(sk+KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_PUBLICKEYBYTES);
  hash_h(sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  // Rejection value from the key.
  memcpy(sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, coins+KYBER_SYMBYTES, KYBER_SYMBYTES);
  return 0;
}


static int mlkem_enc_derand(uint8_t *ct,
                          uint8_t *ss,
                          const uint8_t *pk,
                          const uint8_t *coins)
{
  uint8_t buf[2*KYBER_SYMBYTES];
  // Buffer for the shared key and coins.
  uint8_t kr[2*KYBER_SYMBYTES];

  memcpy(buf, coins, KYBER_SYMBYTES);

  // Bind the coins to the public key.
  hash_h(buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  // The coins follow the first 32 bytes of kr.
  mlkem_indcpa_enc(ct, buf, pk, kr+KYBER_SYMBYTES);

  memcpy(ss,kr,KYBER_SYMBYTES);
  ncrypt_wipe(buf, sizeof buf);
  ncrypt_wipe(kr,  sizeof kr);
  return 0;
}


static int mlkem_dec(uint8_t *ss,
                   const uint8_t *ct,
                   const uint8_t *sk)
{
  int fail;
  uint8_t buf[2*KYBER_SYMBYTES];
  // Buffer for the shared key and coins.
  uint8_t kr[2*KYBER_SYMBYTES];
  uint8_t cmp[KYBER_CIPHERTEXTBYTES];
  const uint8_t *pk = sk+KYBER_INDCPA_SECRETKEYBYTES;

  mlkem_indcpa_dec(buf, ct, sk);

  // Bind the coins to the public key.
  memcpy(buf+KYBER_SYMBYTES, sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, KYBER_SYMBYTES);
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  // The coins follow the first 32 bytes of kr.
  mlkem_indcpa_enc(cmp, buf, pk, kr+KYBER_SYMBYTES);

  fail = mlkem_verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

  // Derive the rejection key.
  rkprf(ss,sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES,ct);

  // Select the valid or rejection key.
  mlkem_cmov(ss,kr,KYBER_SYMBYTES,!fail);

  ncrypt_wipe(buf, sizeof buf);
  ncrypt_wipe(kr,  sizeof kr);
  ncrypt_wipe(cmp, sizeof cmp);
  return 0;
}

//////////////
/// ML-DSA ///
//////////////
#define MLDSA_SEEDBYTES 32
#define MLDSA_CRHBYTES 64
#define MLDSA_TRBYTES 64
#define MLDSA_RNDBYTES 32
#define MLDSA_N 256
#define MLDSA_Q 8380417
#define MLDSA_D 13
#define MLDSA_ROOT_OF_UNITY 1753

#if DILITHIUM_MODE == 2
#define MLDSA_K 4
#define MLDSA_L 4
#define MLDSA_ETA 2
#define MLDSA_TAU 39
#define MLDSA_BETA 78
#define MLDSA_GAMMA1 (1 << 17)
#define MLDSA_GAMMA2 ((MLDSA_Q-1)/88)
#define MLDSA_OMEGA 80
#define MLDSA_CTILDEBYTES 32

#elif DILITHIUM_MODE == 3
#define MLDSA_K 6
#define MLDSA_L 5
#define MLDSA_ETA 4
#define MLDSA_TAU 49
#define MLDSA_BETA 196
#define MLDSA_GAMMA1 (1 << 19)
#define MLDSA_GAMMA2 ((MLDSA_Q-1)/32)
#define MLDSA_OMEGA 55
#define MLDSA_CTILDEBYTES 48

#elif DILITHIUM_MODE == 5
#define MLDSA_K 8
#define MLDSA_L 7
#define MLDSA_ETA 2
#define MLDSA_TAU 60
#define MLDSA_BETA 120
#define MLDSA_GAMMA1 (1 << 19)
#define MLDSA_GAMMA2 ((MLDSA_Q-1)/32)
#define MLDSA_OMEGA 75
#define MLDSA_CTILDEBYTES 64

#endif

#define MLDSA_POLYT1_PACKEDBYTES  320
#define MLDSA_POLYT0_PACKEDBYTES  416
#define MLDSA_POLYVECH_PACKEDBYTES (MLDSA_OMEGA + MLDSA_K)

#if MLDSA_GAMMA1 == (1 << 17)
#define MLDSA_POLYZ_PACKEDBYTES   576
#elif MLDSA_GAMMA1 == (1 << 19)
#define MLDSA_POLYZ_PACKEDBYTES   640
#endif

#if MLDSA_GAMMA2 == (MLDSA_Q-1)/88
#define MLDSA_POLYW1_PACKEDBYTES  192
#elif MLDSA_GAMMA2 == (MLDSA_Q-1)/32
#define MLDSA_POLYW1_PACKEDBYTES  128
#endif

#if MLDSA_ETA == 2
#define MLDSA_POLYETA_PACKEDBYTES  96
#elif MLDSA_ETA == 4
#define MLDSA_POLYETA_PACKEDBYTES 128
#endif

#define MLDSA_CRYPTO_PUBLICKEYBYTES (MLDSA_SEEDBYTES + MLDSA_K*MLDSA_POLYT1_PACKEDBYTES)
#define MLDSA_CRYPTO_SECRETKEYBYTES (2*MLDSA_SEEDBYTES + MLDSA_TRBYTES + MLDSA_L*MLDSA_POLYETA_PACKEDBYTES + MLDSA_K*MLDSA_POLYETA_PACKEDBYTES + MLDSA_K*MLDSA_POLYT0_PACKEDBYTES)
#define MLDSA_CRYPTO_BYTES (MLDSA_CTILDEBYTES + MLDSA_L*MLDSA_POLYZ_PACKEDBYTES + MLDSA_POLYVECH_PACKEDBYTES)

// The public header hard-codes the ML-DSA-44 sizes.
#if MLDSA_CRYPTO_PUBLICKEYBYTES != NCRYPT_MLDSA44_PUBLIC_KEY_SIZE || \
    MLDSA_CRYPTO_SECRETKEYBYTES != NCRYPT_MLDSA44_SECRET_KEY_SIZE || \
    MLDSA_CRYPTO_BYTES          != NCRYPT_MLDSA44_SIGNATURE_SIZE  || \
    MLDSA_SEEDBYTES             != NCRYPT_MLDSA44_KEY_SEED_SIZE   || \
    MLDSA_RNDBYTES              != NCRYPT_MLDSA44_RND_SIZE
#error "ML-DSA parameter set does not match ncrypt-pqc.h"
#endif


#define MLDSA_MONT -4186625 // Montgomery factor modulo q.
#define MLDSA_QINV 58728449 // Negative modular inverse of q.

static int32_t mldsa_montgomery_reduce(int64_t a);

static int32_t mldsa_reduce32(int32_t a);

static int32_t mldsa_caddq(int32_t a);


static int32_t mldsa_power2round(int32_t *a0, int32_t a);

static int32_t mldsa_decompose(int32_t *a0, int32_t a);

static unsigned int mldsa_make_hint(int32_t a0, int32_t a1);

static int32_t mldsa_use_hint(int32_t a, unsigned int hint);


static void mldsa_ntt(int32_t a[MLDSA_N]);

static void mldsa_invntt_tomont(int32_t a[MLDSA_N]);


typedef struct {
  int32_t coeffs[MLDSA_N];
} mldsa_poly;

static void mldsa_poly_reduce(mldsa_poly *a);
static void mldsa_poly_caddq(mldsa_poly *a);

static void mldsa_poly_add(mldsa_poly *c, const mldsa_poly *a, const mldsa_poly *b);
static void mldsa_poly_sub(mldsa_poly *c, const mldsa_poly *a, const mldsa_poly *b);
static void mldsa_poly_shiftl(mldsa_poly *a);

static void mldsa_poly_ntt(mldsa_poly *a);
static void mldsa_poly_invntt_tomont(mldsa_poly *a);
static void mldsa_poly_pointwise_montgomery(mldsa_poly *c, const mldsa_poly *a, const mldsa_poly *b);

static void mldsa_poly_power2round(mldsa_poly *a1, mldsa_poly *a0, const mldsa_poly *a);
static void mldsa_poly_decompose(mldsa_poly *a1, mldsa_poly *a0, const mldsa_poly *a);
static unsigned int mldsa_poly_make_hint(mldsa_poly *h, const mldsa_poly *a0, const mldsa_poly *a1);
static void mldsa_poly_use_hint(mldsa_poly *b, const mldsa_poly *a, const mldsa_poly *h);

static int mldsa_poly_chknorm(const mldsa_poly *a, int32_t B);
static void mldsa_poly_uniform(mldsa_poly *a,
                  const uint8_t seed[MLDSA_SEEDBYTES],
                  uint16_t nonce);
static void mldsa_poly_uniform_eta(mldsa_poly *a,
                      const uint8_t seed[MLDSA_CRHBYTES],
                      uint16_t nonce);
static void mldsa_poly_uniform_gamma1(mldsa_poly *a,
                         const uint8_t seed[MLDSA_CRHBYTES],
                         uint16_t nonce);
static void mldsa_poly_challenge(mldsa_poly *c, const uint8_t seed[MLDSA_CTILDEBYTES]);

static void mldsa_polyeta_pack(uint8_t *r, const mldsa_poly *a);
static void mldsa_polyeta_unpack(mldsa_poly *r, const uint8_t *a);

static void mldsa_polyt1_pack(uint8_t *r, const mldsa_poly *a);
static void mldsa_polyt1_unpack(mldsa_poly *r, const uint8_t *a);

static void mldsa_polyt0_pack(uint8_t *r, const mldsa_poly *a);
static void mldsa_polyt0_unpack(mldsa_poly *r, const uint8_t *a);

static void mldsa_polyz_pack(uint8_t *r, const mldsa_poly *a);
static void mldsa_polyz_unpack(mldsa_poly *r, const uint8_t *a);

static void mldsa_polyw1_pack(uint8_t *r, const mldsa_poly *a);


// Vector of MLDSA_L polynomials.
typedef struct {
  mldsa_poly vec[MLDSA_L];
} mldsa_polyvecl;

static void mldsa_polyvecl_uniform_eta(mldsa_polyvecl *v, const uint8_t seed[MLDSA_CRHBYTES], uint16_t nonce);

static void mldsa_polyvecl_uniform_gamma1(mldsa_polyvecl *v, const uint8_t seed[MLDSA_CRHBYTES], uint16_t nonce);

static void mldsa_polyvecl_reduce(mldsa_polyvecl *v);

static void mldsa_polyvecl_add(mldsa_polyvecl *w, const mldsa_polyvecl *u, const mldsa_polyvecl *v);

static void mldsa_polyvecl_ntt(mldsa_polyvecl *v);
static void mldsa_polyvecl_invntt_tomont(mldsa_polyvecl *v);
static void mldsa_polyvecl_pointwise_poly_montgomery(mldsa_polyvecl *r, const mldsa_poly *a, const mldsa_polyvecl *v);
static void mldsa_polyvecl_pointwise_acc_montgomery(mldsa_poly *w,
                                       const mldsa_polyvecl *u,
                                       const mldsa_polyvecl *v);


static int mldsa_polyvecl_chknorm(const mldsa_polyvecl *v, int32_t B);


// Vector of MLDSA_K polynomials.
typedef struct {
  mldsa_poly vec[MLDSA_K];
} mldsa_polyveck;

static void mldsa_polyveck_uniform_eta(mldsa_polyveck *v, const uint8_t seed[MLDSA_CRHBYTES], uint16_t nonce);

static void mldsa_polyveck_reduce(mldsa_polyveck *v);
static void mldsa_polyveck_caddq(mldsa_polyveck *v);

static void mldsa_polyveck_add(mldsa_polyveck *w, const mldsa_polyveck *u, const mldsa_polyveck *v);
static void mldsa_polyveck_sub(mldsa_polyveck *w, const mldsa_polyveck *u, const mldsa_polyveck *v);
static void mldsa_polyveck_shiftl(mldsa_polyveck *v);

static void mldsa_polyveck_ntt(mldsa_polyveck *v);
static void mldsa_polyveck_invntt_tomont(mldsa_polyveck *v);
static void mldsa_polyveck_pointwise_poly_montgomery(mldsa_polyveck *r, const mldsa_poly *a, const mldsa_polyveck *v);

static int mldsa_polyveck_chknorm(const mldsa_polyveck *v, int32_t B);

static void mldsa_polyveck_power2round(mldsa_polyveck *v1, mldsa_polyveck *v0, const mldsa_polyveck *v);
static void mldsa_polyveck_decompose(mldsa_polyveck *v1, mldsa_polyveck *v0, const mldsa_polyveck *v);
static unsigned int mldsa_polyveck_make_hint(mldsa_polyveck *h,
                                const mldsa_polyveck *v0,
                                const mldsa_polyveck *v1);
static void mldsa_polyveck_use_hint(mldsa_polyveck *w, const mldsa_polyveck *v, const mldsa_polyveck *h);

static void mldsa_polyveck_pack_w1(uint8_t r[MLDSA_K*MLDSA_POLYW1_PACKEDBYTES], const mldsa_polyveck *w1);

static void mldsa_polyvec_matrix_expand(mldsa_polyvecl mat[MLDSA_K], const uint8_t rho[MLDSA_SEEDBYTES]);

static void mldsa_polyvec_matrix_pointwise_montgomery(mldsa_polyveck *t, const mldsa_polyvecl mat[MLDSA_K], const mldsa_polyvecl *v);


static void mldsa_pack_pk(uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES], const uint8_t rho[MLDSA_SEEDBYTES], const mldsa_polyveck *t1);

static void mldsa_pack_sk(uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
             const uint8_t rho[MLDSA_SEEDBYTES],
             const uint8_t tr[MLDSA_TRBYTES],
             const uint8_t key[MLDSA_SEEDBYTES],
             const mldsa_polyveck *t0,
             const mldsa_polyvecl *s1,
             const mldsa_polyveck *s2);

static void mldsa_pack_sig(uint8_t sig[MLDSA_CRYPTO_BYTES], const uint8_t c[MLDSA_CTILDEBYTES], const mldsa_polyvecl *z, const mldsa_polyveck *h);

static void mldsa_unpack_pk(uint8_t rho[MLDSA_SEEDBYTES], mldsa_polyveck *t1, const uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES]);

static void mldsa_unpack_sk(uint8_t rho[MLDSA_SEEDBYTES],
               uint8_t tr[MLDSA_TRBYTES],
               uint8_t key[MLDSA_SEEDBYTES],
               mldsa_polyveck *t0,
               mldsa_polyvecl *s1,
               mldsa_polyveck *s2,
               const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES]);

static int mldsa_unpack_sig(uint8_t c[MLDSA_CTILDEBYTES], mldsa_polyvecl *z, mldsa_polyveck *h, const uint8_t sig[MLDSA_CRYPTO_BYTES]);


typedef keccak_state mldsa_stream128_state;
typedef keccak_state mldsa_stream256_state;

static void mldsa_shake128_stream_init(keccak_state *state,
                                    const uint8_t seed[MLDSA_SEEDBYTES],
                                    uint16_t nonce);

static void mldsa_shake256_stream_init(keccak_state *state,
                                    const uint8_t seed[MLDSA_CRHBYTES],
                                    uint16_t nonce);

#define STREAM128_BLOCKBYTES SHAKE128_RATE
#define STREAM256_BLOCKBYTES SHAKE256_RATE

#define stream128_init(STATE, SEED, NONCE) mldsa_shake128_stream_init(STATE, SEED, NONCE)
#define stream128_squeezeblocks(OUT, OUTBLOCKS, STATE) shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define stream256_init(STATE, SEED, NONCE) mldsa_shake256_stream_init(STATE, SEED, NONCE)
#define stream256_squeezeblocks(OUT, OUTBLOCKS, STATE) shake256_squeezeblocks(OUT, OUTBLOCKS, STATE)


static int mldsa_keypair_derand(uint8_t *pk, uint8_t *sk,
                               const uint8_t seed[MLDSA_SEEDBYTES]);

static void mldsa_signature_internal(uint8_t *sig,
                                    const uint8_t *m,
                                    size_t mlen,
                                    const uint8_t *pre,
                                    size_t prelen,
                                    const uint8_t rnd[MLDSA_RNDBYTES],
                                    const uint8_t *sk);

static int mldsa_signature(uint8_t *sig,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *ctx, size_t ctxlen,
                          const uint8_t rnd[MLDSA_RNDBYTES],
                          const uint8_t *sk);

static int mldsa_verify_internal(const uint8_t *sig,
                                const uint8_t *m,
                                size_t mlen,
                                const uint8_t *pre,
                                size_t prelen,
                                const uint8_t *pk);

static int mldsa_verify(const uint8_t *sig,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *ctx, size_t ctxlen,
                       const uint8_t *pk);


static int32_t mldsa_montgomery_reduce(int64_t a) {
  int32_t t;

  t = (int32_t)((int64_t)(int32_t)a*MLDSA_QINV);
  // |a| < q*2^31, so (a - t*q) is a multiple of 2^32 whose magnitude is
  // below 2^63, and the shifted value fits in 32 bits.
  t = (int32_t)((a - (int64_t)t*MLDSA_Q) >> 32);
  return t;
}


static int32_t mldsa_reduce32(int32_t a) {
  int32_t t;

  t = (a + (1 << 22)) >> 23;
  t = a - t*MLDSA_Q;
  return t;
}


static int32_t mldsa_caddq(int32_t a) {
  a += (a >> 31) & MLDSA_Q;
  return a;
}


static int32_t mldsa_power2round(int32_t *a0, int32_t a)  {
  int32_t a1;

  a1 = (a + (1 << (MLDSA_D-1)) - 1) >> MLDSA_D;
  *a0 = a - (a1 << MLDSA_D);
  return a1;
}


static int32_t mldsa_decompose(int32_t *a0, int32_t a) {
  int32_t a1;

  a1  = (a + 127) >> 7;
#if MLDSA_GAMMA2 == (MLDSA_Q-1)/32
  a1  = (a1*1025 + (1 << 21)) >> 22;
  a1 &= 15;
#elif MLDSA_GAMMA2 == (MLDSA_Q-1)/88
  a1  = (a1*11275 + (1 << 23)) >> 24;
  a1 ^= ((43 - a1) >> 31) & a1;
#endif

  *a0  = a - a1*2*MLDSA_GAMMA2;
  *a0 -= (((MLDSA_Q-1)/2 - *a0) >> 31) & MLDSA_Q;
  return a1;
}


static unsigned int mldsa_make_hint(int32_t a0, int32_t a1) {
  if(a0 > MLDSA_GAMMA2 || a0 < -MLDSA_GAMMA2 || (a0 == -MLDSA_GAMMA2 && a1 != 0))
    return 1;

  return 0;
}


static int32_t mldsa_use_hint(int32_t a, unsigned int hint) {
  int32_t a0, a1;

  a1 = mldsa_decompose(&a0, a);
  if(hint == 0)
    return a1;

#if MLDSA_GAMMA2 == (MLDSA_Q-1)/32
  if(a0 > 0)
    return (a1 + 1) & 15;
  else
    return (a1 - 1) & 15;
#elif MLDSA_GAMMA2 == (MLDSA_Q-1)/88
  if(a0 > 0)
    return (a1 == 43) ?  0 : a1 + 1;
  else
    return (a1 ==  0) ? 43 : a1 - 1;
#endif
}


static const int32_t zetas[MLDSA_N] = {
         0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
   1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
   2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
  -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
   2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
  -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
  -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
  -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
   3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
   -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
  -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
  -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
   1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
   2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
   -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
   2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
  -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
  -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
  -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
   -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
  -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
  -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
  -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
   -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
  -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
   -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782
};


static void mldsa_ntt(int32_t a[MLDSA_N]) {
  unsigned int len, start, j, k;
  int32_t zeta, t;

  k = 0;
  for(len = 128; len > 0; len >>= 1) {
    for(start = 0; start < MLDSA_N; start = j + len) {
      zeta = zetas[++k];
      for(j = start; j < start + len; ++j) {
        t = mldsa_montgomery_reduce((int64_t)zeta * a[j + len]);
        a[j + len] = a[j] - t;
        a[j] = a[j] + t;
      }
    }
  }
}


static void mldsa_invntt_tomont(int32_t a[MLDSA_N]) {
  unsigned int start, len, j, k;
  int32_t t, zeta;
  const int32_t f = 41978; // Montgomery factor squared divided by 256.

  k = 256;
  for(len = 1; len < MLDSA_N; len <<= 1) {
    for(start = 0; start < MLDSA_N; start = j + len) {
      zeta = -zetas[--k];
      for(j = start; j < start + len; ++j) {
        t = a[j];
        a[j] = t + a[j + len];
        a[j + len] = t - a[j + len];
        a[j + len] = mldsa_montgomery_reduce((int64_t)zeta * a[j + len]);
      }
    }
  }

  for(j = 0; j < MLDSA_N; ++j) {
    a[j] = mldsa_montgomery_reduce((int64_t)f * a[j]);
  }
}


static void mldsa_poly_reduce(mldsa_poly *a) {
  unsigned int i;

  for(i = 0; i < MLDSA_N; ++i)
    a->coeffs[i] = mldsa_reduce32(a->coeffs[i]);

}


static void mldsa_poly_caddq(mldsa_poly *a) {
  unsigned int i;

  for(i = 0; i < MLDSA_N; ++i)
    a->coeffs[i] = mldsa_caddq(a->coeffs[i]);

}


static void mldsa_poly_add(mldsa_poly *c, const mldsa_poly *a, const mldsa_poly *b)  {
  unsigned int i;

  for(i = 0; i < MLDSA_N; ++i)
    c->coeffs[i] = a->coeffs[i] + b->coeffs[i];

}


static void mldsa_poly_sub(mldsa_poly *c, const mldsa_poly *a, const mldsa_poly *b) {
  unsigned int i;

  for(i = 0; i < MLDSA_N; ++i)
    c->coeffs[i] = a->coeffs[i] - b->coeffs[i];

}


static void mldsa_poly_shiftl(mldsa_poly *a) {
  unsigned int i;

  for(i = 0; i < MLDSA_N; ++i)
    a->coeffs[i] <<= MLDSA_D;

}


static void mldsa_poly_ntt(mldsa_poly *a) {

  mldsa_ntt(a->coeffs);

}


static void mldsa_poly_invntt_tomont(mldsa_poly *a) {

  mldsa_invntt_tomont(a->coeffs);

}


static void mldsa_poly_pointwise_montgomery(mldsa_poly *c, const mldsa_poly *a, const mldsa_poly *b) {
  unsigned int i;

  for(i = 0; i < MLDSA_N; ++i)
    c->coeffs[i] = mldsa_montgomery_reduce((int64_t)a->coeffs[i] * b->coeffs[i]);

}


static void mldsa_poly_power2round(mldsa_poly *a1, mldsa_poly *a0, const mldsa_poly *a) {
  unsigned int i;

  for(i = 0; i < MLDSA_N; ++i)
    a1->coeffs[i] = mldsa_power2round(&a0->coeffs[i], a->coeffs[i]);

}


static void mldsa_poly_decompose(mldsa_poly *a1, mldsa_poly *a0, const mldsa_poly *a) {
  unsigned int i;

  for(i = 0; i < MLDSA_N; ++i)
    a1->coeffs[i] = mldsa_decompose(&a0->coeffs[i], a->coeffs[i]);

}


static unsigned int mldsa_poly_make_hint(mldsa_poly *h, const mldsa_poly *a0, const mldsa_poly *a1) {
  unsigned int i, s = 0;

  for(i = 0; i < MLDSA_N; ++i) {
    h->coeffs[i] = (int32_t)mldsa_make_hint(a0->coeffs[i], a1->coeffs[i]);
    s += (unsigned int)h->coeffs[i];
  }

  return s;
}


static void mldsa_poly_use_hint(mldsa_poly *b, const mldsa_poly *a, const mldsa_poly *h) {
  unsigned int i;

  for(i = 0; i < MLDSA_N; ++i)
    b->coeffs[i] = mldsa_use_hint(a->coeffs[i], (unsigned int)h->coeffs[i]);

}


static int mldsa_poly_chknorm(const mldsa_poly *a, int32_t B) {
  unsigned int i;
  int32_t t;

  if(B > (MLDSA_Q-1)/8)
    return 1;

  // The violating index may be public, but the sign must remain hidden.
  for(i = 0; i < MLDSA_N; ++i) {
    // Take the absolute value.
    t = a->coeffs[i] >> 31;
    t = a->coeffs[i] - (t & 2*a->coeffs[i]);

    if(t >= B) {
      return 1;
    }
  }

  return 0;
}


static unsigned int mldsa_rej_uniform(int32_t *a,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen)
{
  unsigned int ctr, pos;
  uint32_t t;

  ctr = pos = 0;
  while(ctr < len && pos + 3 <= buflen) {
    t  = buf[pos++];
    t |= (uint32_t)buf[pos++] << 8;
    t |= (uint32_t)buf[pos++] << 16;
    t &= 0x7FFFFF;

    if(t < MLDSA_Q)
      a[ctr++] = (int32_t)t;
  }

  return ctr;
}


#define POLY_UNIFORM_NBLOCKS ((768 + STREAM128_BLOCKBYTES - 1)/STREAM128_BLOCKBYTES)
static void mldsa_poly_uniform(mldsa_poly *a,
                  const uint8_t seed[MLDSA_SEEDBYTES],
                  uint16_t nonce)
{
  unsigned int i, ctr, off;
  unsigned int buflen = POLY_UNIFORM_NBLOCKS*STREAM128_BLOCKBYTES;
  uint8_t buf[POLY_UNIFORM_NBLOCKS*STREAM128_BLOCKBYTES + 2];
  mldsa_stream128_state state;

  stream128_init(&state, seed, nonce);
  stream128_squeezeblocks(buf, POLY_UNIFORM_NBLOCKS, &state);

  ctr = mldsa_rej_uniform(a->coeffs, MLDSA_N, buf, buflen);

  while(ctr < MLDSA_N) {
    off = buflen % 3;
    for(i = 0; i < off; ++i)
      buf[i] = buf[buflen - off + i];

    stream128_squeezeblocks(buf + off, 1, &state);
    buflen = STREAM128_BLOCKBYTES + off;
    ctr += mldsa_rej_uniform(a->coeffs + ctr, MLDSA_N - ctr, buf, buflen);
  }
}


static unsigned int rej_eta(int32_t *a,
                            unsigned int len,
                            const uint8_t *buf,
                            unsigned int buflen)
{
  unsigned int ctr, pos;
  uint32_t t0, t1;

  ctr = pos = 0;
  while(ctr < len && pos < buflen) {
    t0 = buf[pos] & 0x0F;
    t1 = buf[pos++] >> 4;

#if MLDSA_ETA == 2
    if(t0 < 15) {
      t0 = t0 - (205*t0 >> 10)*5;
      a[ctr++] = 2 - (int32_t)t0;
    }
    if(t1 < 15 && ctr < len) {
      t1 = t1 - (205*t1 >> 10)*5;
      a[ctr++] = 2 - (int32_t)t1;
    }
#elif MLDSA_ETA == 4
    if(t0 < 9)
      a[ctr++] = 4 - (int32_t)t0;
    if(t1 < 9 && ctr < len)
      a[ctr++] = 4 - (int32_t)t1;
#endif
  }

  return ctr;
}


#if MLDSA_ETA == 2
#define POLY_UNIFORM_ETA_NBLOCKS ((136 + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES)
#elif MLDSA_ETA == 4
#define POLY_UNIFORM_ETA_NBLOCKS ((227 + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES)
#endif
static void mldsa_poly_uniform_eta(mldsa_poly *a,
                      const uint8_t seed[MLDSA_CRHBYTES],
                      uint16_t nonce)
{
  unsigned int ctr;
  unsigned int buflen = POLY_UNIFORM_ETA_NBLOCKS*STREAM256_BLOCKBYTES;
  uint8_t buf[POLY_UNIFORM_ETA_NBLOCKS*STREAM256_BLOCKBYTES];
  mldsa_stream256_state state;

  stream256_init(&state, seed, nonce);
  stream256_squeezeblocks(buf, POLY_UNIFORM_ETA_NBLOCKS, &state);

  ctr = rej_eta(a->coeffs, MLDSA_N, buf, buflen);

  while(ctr < MLDSA_N) {
    stream256_squeezeblocks(buf, 1, &state);
    ctr += rej_eta(a->coeffs + ctr, MLDSA_N - ctr, buf, STREAM256_BLOCKBYTES);
  }
}


#define POLY_UNIFORM_GAMMA1_NBLOCKS ((MLDSA_POLYZ_PACKEDBYTES + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES)
static void mldsa_poly_uniform_gamma1(mldsa_poly *a,
                         const uint8_t seed[MLDSA_CRHBYTES],
                         uint16_t nonce)
{
  uint8_t buf[POLY_UNIFORM_GAMMA1_NBLOCKS*STREAM256_BLOCKBYTES];
  mldsa_stream256_state state;

  stream256_init(&state, seed, nonce);
  stream256_squeezeblocks(buf, POLY_UNIFORM_GAMMA1_NBLOCKS, &state);
  mldsa_polyz_unpack(a, buf);
}


static void mldsa_poly_challenge(mldsa_poly *c, const uint8_t seed[MLDSA_CTILDEBYTES]) {
  unsigned int i, b, pos;
  uint64_t signs;
  uint8_t buf[SHAKE256_RATE];
  keccak_state state;

  shake256_init(&state);
  shake256_absorb(&state, seed, MLDSA_CTILDEBYTES);
  shake256_finalize(&state);
  shake256_squeezeblocks(buf, 1, &state);

  signs = 0;
  for(i = 0; i < 8; ++i)
    signs |= (uint64_t)buf[i] << 8*i;
  pos = 8;

  for(i = 0; i < MLDSA_N; ++i)
    c->coeffs[i] = 0;
  for(i = MLDSA_N-MLDSA_TAU; i < MLDSA_N; ++i) {
    do {
      if(pos >= SHAKE256_RATE) {
        shake256_squeezeblocks(buf, 1, &state);
        pos = 0;
      }

      b = buf[pos++];
    } while(b > i);

    c->coeffs[i] = c->coeffs[b];
    c->coeffs[b] = 1 - 2*(int32_t)(signs & 1);
    signs >>= 1;
  }
}


static void mldsa_polyeta_pack(uint8_t *r, const mldsa_poly *a) {
  unsigned int i;
  uint8_t t[8];

#if MLDSA_ETA == 2
  for(i = 0; i < MLDSA_N/8; ++i) {
    t[0] = (uint8_t)(MLDSA_ETA - a->coeffs[8*i+0]);
    t[1] = (uint8_t)(MLDSA_ETA - a->coeffs[8*i+1]);
    t[2] = (uint8_t)(MLDSA_ETA - a->coeffs[8*i+2]);
    t[3] = (uint8_t)(MLDSA_ETA - a->coeffs[8*i+3]);
    t[4] = (uint8_t)(MLDSA_ETA - a->coeffs[8*i+4]);
    t[5] = (uint8_t)(MLDSA_ETA - a->coeffs[8*i+5]);
    t[6] = (uint8_t)(MLDSA_ETA - a->coeffs[8*i+6]);
    t[7] = (uint8_t)(MLDSA_ETA - a->coeffs[8*i+7]);

    r[3*i+0] = (uint8_t)((t[0] >> 0) | (t[1] << 3) | (t[2] << 6));
    r[3*i+1] = (uint8_t)((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7));
    r[3*i+2] = (uint8_t)((t[5] >> 1) | (t[6] << 2) | (t[7] << 5));
  }
#elif MLDSA_ETA == 4
  for(i = 0; i < MLDSA_N/2; ++i) {
    t[0] = (uint8_t)(MLDSA_ETA - a->coeffs[2*i+0]);
    t[1] = (uint8_t)(MLDSA_ETA - a->coeffs[2*i+1]);
    r[i] = (uint8_t)(t[0] | (t[1] << 4));
  }
#endif

}


static void mldsa_polyeta_unpack(mldsa_poly *r, const uint8_t *a) {
  unsigned int i;

#if MLDSA_ETA == 2
  for(i = 0; i < MLDSA_N/8; ++i) {
    r->coeffs[8*i+0] =  (a[3*i+0] >> 0) & 7;
    r->coeffs[8*i+1] =  (a[3*i+0] >> 3) & 7;
    r->coeffs[8*i+2] = ((a[3*i+0] >> 6) | (a[3*i+1] << 2)) & 7;
    r->coeffs[8*i+3] =  (a[3*i+1] >> 1) & 7;
    r->coeffs[8*i+4] =  (a[3*i+1] >> 4) & 7;
    r->coeffs[8*i+5] = ((a[3*i+1] >> 7) | (a[3*i+2] << 1)) & 7;
    r->coeffs[8*i+6] =  (a[3*i+2] >> 2) & 7;
    r->coeffs[8*i+7] =  (a[3*i+2] >> 5) & 7;

    r->coeffs[8*i+0] = MLDSA_ETA - r->coeffs[8*i+0];
    r->coeffs[8*i+1] = MLDSA_ETA - r->coeffs[8*i+1];
    r->coeffs[8*i+2] = MLDSA_ETA - r->coeffs[8*i+2];
    r->coeffs[8*i+3] = MLDSA_ETA - r->coeffs[8*i+3];
    r->coeffs[8*i+4] = MLDSA_ETA - r->coeffs[8*i+4];
    r->coeffs[8*i+5] = MLDSA_ETA - r->coeffs[8*i+5];
    r->coeffs[8*i+6] = MLDSA_ETA - r->coeffs[8*i+6];
    r->coeffs[8*i+7] = MLDSA_ETA - r->coeffs[8*i+7];
  }
#elif MLDSA_ETA == 4
  for(i = 0; i < MLDSA_N/2; ++i) {
    r->coeffs[2*i+0] = a[i] & 0x0F;
    r->coeffs[2*i+1] = a[i] >> 4;
    r->coeffs[2*i+0] = MLDSA_ETA - r->coeffs[2*i+0];
    r->coeffs[2*i+1] = MLDSA_ETA - r->coeffs[2*i+1];
  }
#endif

}


static void mldsa_polyt1_pack(uint8_t *r, const mldsa_poly *a) {
  unsigned int i;

  for(i = 0; i < MLDSA_N/4; ++i) {
    r[5*i+0] = (uint8_t)((a->coeffs[4*i+0] >> 0));
    r[5*i+1] = (uint8_t)((a->coeffs[4*i+0] >> 8) | (a->coeffs[4*i+1] << 2));
    r[5*i+2] = (uint8_t)((a->coeffs[4*i+1] >> 6) | (a->coeffs[4*i+2] << 4));
    r[5*i+3] = (uint8_t)((a->coeffs[4*i+2] >> 4) | (a->coeffs[4*i+3] << 6));
    r[5*i+4] = (uint8_t)((a->coeffs[4*i+3] >> 2));
  }

}


static void mldsa_polyt1_unpack(mldsa_poly *r, const uint8_t *a) {
  unsigned int i;

  for(i = 0; i < MLDSA_N/4; ++i) {
    r->coeffs[4*i+0] = (int32_t)(((a[5*i+0] >> 0) | ((uint32_t)a[5*i+1] << 8)) & 0x3FF);
    r->coeffs[4*i+1] = (int32_t)(((a[5*i+1] >> 2) | ((uint32_t)a[5*i+2] << 6)) & 0x3FF);
    r->coeffs[4*i+2] = (int32_t)(((a[5*i+2] >> 4) | ((uint32_t)a[5*i+3] << 4)) & 0x3FF);
    r->coeffs[4*i+3] = (int32_t)(((a[5*i+3] >> 6) | ((uint32_t)a[5*i+4] << 2)) & 0x3FF);
  }

}


static void mldsa_polyt0_pack(uint8_t *r, const mldsa_poly *a) {
  unsigned int i;
  uint32_t t[8];

  for(i = 0; i < MLDSA_N/8; ++i) {
    t[0] = (uint32_t)((1 << (MLDSA_D-1)) - a->coeffs[8*i+0]);
    t[1] = (uint32_t)((1 << (MLDSA_D-1)) - a->coeffs[8*i+1]);
    t[2] = (uint32_t)((1 << (MLDSA_D-1)) - a->coeffs[8*i+2]);
    t[3] = (uint32_t)((1 << (MLDSA_D-1)) - a->coeffs[8*i+3]);
    t[4] = (uint32_t)((1 << (MLDSA_D-1)) - a->coeffs[8*i+4]);
    t[5] = (uint32_t)((1 << (MLDSA_D-1)) - a->coeffs[8*i+5]);
    t[6] = (uint32_t)((1 << (MLDSA_D-1)) - a->coeffs[8*i+6]);
    t[7] = (uint32_t)((1 << (MLDSA_D-1)) - a->coeffs[8*i+7]);

    r[13*i+ 0] = (uint8_t)(t[0]);
    r[13*i+ 1] = (uint8_t)(t[0] >>  8);
    r[13*i+ 1] = (uint8_t)(r[13*i+ 1] | (t[1] <<  5));
    r[13*i+ 2] = (uint8_t)(t[1] >>  3);
    r[13*i+ 3] = (uint8_t)(t[1] >> 11);
    r[13*i+ 3] = (uint8_t)(r[13*i+ 3] | (t[2] <<  2));
    r[13*i+ 4] = (uint8_t)(t[2] >>  6);
    r[13*i+ 4] = (uint8_t)(r[13*i+ 4] | (t[3] <<  7));
    r[13*i+ 5] = (uint8_t)(t[3] >>  1);
    r[13*i+ 6] = (uint8_t)(t[3] >>  9);
    r[13*i+ 6] = (uint8_t)(r[13*i+ 6] | (t[4] <<  4));
    r[13*i+ 7] = (uint8_t)(t[4] >>  4);
    r[13*i+ 8] = (uint8_t)(t[4] >> 12);
    r[13*i+ 8] = (uint8_t)(r[13*i+ 8] | (t[5] <<  1));
    r[13*i+ 9] = (uint8_t)(t[5] >>  7);
    r[13*i+ 9] = (uint8_t)(r[13*i+ 9] | (t[6] <<  6));
    r[13*i+10] = (uint8_t)(t[6] >>  2);
    r[13*i+11] = (uint8_t)(t[6] >> 10);
    r[13*i+11] = (uint8_t)(r[13*i+11] | (t[7] <<  3));
    r[13*i+12] = (uint8_t)(t[7] >>  5);
  }

}


static void mldsa_polyt0_unpack(mldsa_poly *r, const uint8_t *a) {
  unsigned int i;
  uint32_t t[8];

  for(i = 0; i < MLDSA_N/8; ++i) {
    t[0]  = a[13*i+0];
    t[0] |= (uint32_t)a[13*i+1] << 8;
    t[0] &= 0x1FFF;

    t[1]  = a[13*i+1] >> 5;
    t[1] |= (uint32_t)a[13*i+2] << 3;
    t[1] |= (uint32_t)a[13*i+3] << 11;
    t[1] &= 0x1FFF;

    t[2]  = a[13*i+3] >> 2;
    t[2] |= (uint32_t)a[13*i+4] << 6;
    t[2] &= 0x1FFF;

    t[3]  = a[13*i+4] >> 7;
    t[3] |= (uint32_t)a[13*i+5] << 1;
    t[3] |= (uint32_t)a[13*i+6] << 9;
    t[3] &= 0x1FFF;

    t[4]  = a[13*i+6] >> 4;
    t[4] |= (uint32_t)a[13*i+7] << 4;
    t[4] |= (uint32_t)a[13*i+8] << 12;
    t[4] &= 0x1FFF;

    t[5]  = a[13*i+8] >> 1;
    t[5] |= (uint32_t)a[13*i+9] << 7;
    t[5] &= 0x1FFF;

    t[6]  = a[13*i+9] >> 6;
    t[6] |= (uint32_t)a[13*i+10] << 2;
    t[6] |= (uint32_t)a[13*i+11] << 10;
    t[6] &= 0x1FFF;

    t[7]  = a[13*i+11] >> 3;
    t[7] |= (uint32_t)a[13*i+12] << 5;
    t[7] &= 0x1FFF;

    r->coeffs[8*i+0] = (1 << (MLDSA_D-1)) - (int32_t)t[0];
    r->coeffs[8*i+1] = (1 << (MLDSA_D-1)) - (int32_t)t[1];
    r->coeffs[8*i+2] = (1 << (MLDSA_D-1)) - (int32_t)t[2];
    r->coeffs[8*i+3] = (1 << (MLDSA_D-1)) - (int32_t)t[3];
    r->coeffs[8*i+4] = (1 << (MLDSA_D-1)) - (int32_t)t[4];
    r->coeffs[8*i+5] = (1 << (MLDSA_D-1)) - (int32_t)t[5];
    r->coeffs[8*i+6] = (1 << (MLDSA_D-1)) - (int32_t)t[6];
    r->coeffs[8*i+7] = (1 << (MLDSA_D-1)) - (int32_t)t[7];
  }

}


static void mldsa_polyz_pack(uint8_t *r, const mldsa_poly *a) {
  unsigned int i;
  uint32_t t[4];

#if MLDSA_GAMMA1 == (1 << 17)
  for(i = 0; i < MLDSA_N/4; ++i) {
    t[0] = (uint32_t)(MLDSA_GAMMA1 - a->coeffs[4*i+0]);
    t[1] = (uint32_t)(MLDSA_GAMMA1 - a->coeffs[4*i+1]);
    t[2] = (uint32_t)(MLDSA_GAMMA1 - a->coeffs[4*i+2]);
    t[3] = (uint32_t)(MLDSA_GAMMA1 - a->coeffs[4*i+3]);

    r[9*i+0] = (uint8_t)(t[0]);
    r[9*i+1] = (uint8_t)(t[0] >> 8);
    r[9*i+2] = (uint8_t)(t[0] >> 16);
    r[9*i+2] = (uint8_t)(r[9*i+2] | (t[1] << 2));
    r[9*i+3] = (uint8_t)(t[1] >> 6);
    r[9*i+4] = (uint8_t)(t[1] >> 14);
    r[9*i+4] = (uint8_t)(r[9*i+4] | (t[2] << 4));
    r[9*i+5] = (uint8_t)(t[2] >> 4);
    r[9*i+6] = (uint8_t)(t[2] >> 12);
    r[9*i+6] = (uint8_t)(r[9*i+6] | (t[3] << 6));
    r[9*i+7] = (uint8_t)(t[3] >> 2);
    r[9*i+8] = (uint8_t)(t[3] >> 10);
  }
#elif MLDSA_GAMMA1 == (1 << 19)
  for(i = 0; i < MLDSA_N/2; ++i) {
    t[0] = (uint32_t)(MLDSA_GAMMA1 - a->coeffs[2*i+0]);
    t[1] = (uint32_t)(MLDSA_GAMMA1 - a->coeffs[2*i+1]);

    r[5*i+0] = (uint8_t)(t[0]);
    r[5*i+1] = (uint8_t)(t[0] >> 8);
    r[5*i+2] = (uint8_t)(t[0] >> 16);
    r[5*i+2] = (uint8_t)(r[5*i+2] | (t[1] << 4));
    r[5*i+3] = (uint8_t)(t[1] >> 4);
    r[5*i+4] = (uint8_t)(t[1] >> 12);
  }
#endif

}


static void mldsa_polyz_unpack(mldsa_poly *r, const uint8_t *a) {
  unsigned int i;
  uint32_t t[4];

#if MLDSA_GAMMA1 == (1 << 17)
  for(i = 0; i < MLDSA_N/4; ++i) {
    t[0]  = a[9*i+0];
    t[0] |= (uint32_t)a[9*i+1] << 8;
    t[0] |= (uint32_t)a[9*i+2] << 16;
    t[0] &= 0x3FFFF;

    t[1]  = a[9*i+2] >> 2;
    t[1] |= (uint32_t)a[9*i+3] << 6;
    t[1] |= (uint32_t)a[9*i+4] << 14;
    t[1] &= 0x3FFFF;

    t[2]  = a[9*i+4] >> 4;
    t[2] |= (uint32_t)a[9*i+5] << 4;
    t[2] |= (uint32_t)a[9*i+6] << 12;
    t[2] &= 0x3FFFF;

    t[3]  = a[9*i+6] >> 6;
    t[3] |= (uint32_t)a[9*i+7] << 2;
    t[3] |= (uint32_t)a[9*i+8] << 10;
    t[3] &= 0x3FFFF;

    r->coeffs[4*i+0] = MLDSA_GAMMA1 - (int32_t)t[0];
    r->coeffs[4*i+1] = MLDSA_GAMMA1 - (int32_t)t[1];
    r->coeffs[4*i+2] = MLDSA_GAMMA1 - (int32_t)t[2];
    r->coeffs[4*i+3] = MLDSA_GAMMA1 - (int32_t)t[3];
  }
#elif MLDSA_GAMMA1 == (1 << 19)
  for(i = 0; i < MLDSA_N/2; ++i) {
    t[0]  = a[5*i+0];
    t[0] |= (uint32_t)a[5*i+1] << 8;
    t[0] |= (uint32_t)a[5*i+2] << 16;
    t[0] &= 0xFFFFF;

    t[1]  = a[5*i+2] >> 4;
    t[1] |= (uint32_t)a[5*i+3] << 4;
    t[1] |= (uint32_t)a[5*i+4] << 12;

    r->coeffs[2*i+0] = MLDSA_GAMMA1 - (int32_t)t[0];
    r->coeffs[2*i+1] = MLDSA_GAMMA1 - (int32_t)t[1];
  }
#endif

}


static void mldsa_polyw1_pack(uint8_t *r, const mldsa_poly *a) {
  unsigned int i;

#if MLDSA_GAMMA2 == (MLDSA_Q-1)/88
  for(i = 0; i < MLDSA_N/4; ++i) {
    r[3*i+0] = (uint8_t)(a->coeffs[4*i+0]);
    r[3*i+0] = (uint8_t)(r[3*i+0] | (a->coeffs[4*i+1] << 6));
    r[3*i+1] = (uint8_t)(a->coeffs[4*i+1] >> 2);
    r[3*i+1] = (uint8_t)(r[3*i+1] | (a->coeffs[4*i+2] << 4));
    r[3*i+2] = (uint8_t)(a->coeffs[4*i+2] >> 4);
    r[3*i+2] = (uint8_t)(r[3*i+2] | (a->coeffs[4*i+3] << 2));
  }
#elif MLDSA_GAMMA2 == (MLDSA_Q-1)/32
  for(i = 0; i < MLDSA_N/2; ++i)
    r[i] = (uint8_t)(a->coeffs[2*i+0] | (a->coeffs[2*i+1] << 4));
#endif

}


static void mldsa_polyvec_matrix_expand(mldsa_polyvecl mat[MLDSA_K], const uint8_t rho[MLDSA_SEEDBYTES]) {
  unsigned int i, j;

  for(i = 0; i < MLDSA_K; ++i)
    for(j = 0; j < MLDSA_L; ++j)
      mldsa_poly_uniform(&mat[i].vec[j], rho, (uint16_t)((i << 8) + j));
}

static void mldsa_polyvec_matrix_pointwise_montgomery(mldsa_polyveck *t, const mldsa_polyvecl mat[MLDSA_K], const mldsa_polyvecl *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v);
}


// Vector operations for MLDSA_L polynomials.


static void mldsa_polyvecl_uniform_eta(mldsa_polyvecl *v, const uint8_t seed[MLDSA_CRHBYTES], uint16_t nonce) {
  unsigned int i;

  for(i = 0; i < MLDSA_L; ++i)
    mldsa_poly_uniform_eta(&v->vec[i], seed, nonce++);
}

static void mldsa_polyvecl_uniform_gamma1(mldsa_polyvecl *v, const uint8_t seed[MLDSA_CRHBYTES], uint16_t nonce) {
  unsigned int i;

  for(i = 0; i < MLDSA_L; ++i)
    mldsa_poly_uniform_gamma1(&v->vec[i], seed, (uint16_t)(MLDSA_L*nonce + i));
}

static void mldsa_polyvecl_reduce(mldsa_polyvecl *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_L; ++i)
    mldsa_poly_reduce(&v->vec[i]);
}


static void mldsa_polyvecl_add(mldsa_polyvecl *w, const mldsa_polyvecl *u, const mldsa_polyvecl *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_L; ++i)
    mldsa_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}


static void mldsa_polyvecl_ntt(mldsa_polyvecl *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_L; ++i)
    mldsa_poly_ntt(&v->vec[i]);
}

static void mldsa_polyvecl_invntt_tomont(mldsa_polyvecl *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_L; ++i)
    mldsa_poly_invntt_tomont(&v->vec[i]);
}

static void mldsa_polyvecl_pointwise_poly_montgomery(mldsa_polyvecl *r, const mldsa_poly *a, const mldsa_polyvecl *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_L; ++i)
    mldsa_poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}


static void mldsa_polyvecl_pointwise_acc_montgomery(mldsa_poly *w,
                                       const mldsa_polyvecl *u,
                                       const mldsa_polyvecl *v)
{
  unsigned int i;
  mldsa_poly t;

  mldsa_poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
  for(i = 1; i < MLDSA_L; ++i) {
    mldsa_poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
    mldsa_poly_add(w, w, &t);
  }
}


static int mldsa_polyvecl_chknorm(const mldsa_polyvecl *v, int32_t bound)  {
  unsigned int i;

  for(i = 0; i < MLDSA_L; ++i)
    if(mldsa_poly_chknorm(&v->vec[i], bound))
      return 1;

  return 0;
}


// Vector operations for MLDSA_K polynomials.


static void mldsa_polyveck_uniform_eta(mldsa_polyveck *v, const uint8_t seed[MLDSA_CRHBYTES], uint16_t nonce) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_poly_uniform_eta(&v->vec[i], seed, nonce++);
}


static void mldsa_polyveck_reduce(mldsa_polyveck *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_poly_reduce(&v->vec[i]);
}


static void mldsa_polyveck_caddq(mldsa_polyveck *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_poly_caddq(&v->vec[i]);
}


static void mldsa_polyveck_add(mldsa_polyveck *w, const mldsa_polyveck *u, const mldsa_polyveck *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}


static void mldsa_polyveck_sub(mldsa_polyveck *w, const mldsa_polyveck *u, const mldsa_polyveck *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
}


static void mldsa_polyveck_shiftl(mldsa_polyveck *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_poly_shiftl(&v->vec[i]);
}


static void mldsa_polyveck_ntt(mldsa_polyveck *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_poly_ntt(&v->vec[i]);
}


static void mldsa_polyveck_invntt_tomont(mldsa_polyveck *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_poly_invntt_tomont(&v->vec[i]);
}

static void mldsa_polyveck_pointwise_poly_montgomery(mldsa_polyveck *r, const mldsa_poly *a, const mldsa_polyveck *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}


static int mldsa_polyveck_chknorm(const mldsa_polyveck *v, int32_t bound) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    if(mldsa_poly_chknorm(&v->vec[i], bound))
      return 1;

  return 0;
}


static void mldsa_polyveck_power2round(mldsa_polyveck *v1, mldsa_polyveck *v0, const mldsa_polyveck *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}


static void mldsa_polyveck_decompose(mldsa_polyveck *v1, mldsa_polyveck *v0, const mldsa_polyveck *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}


static unsigned int mldsa_polyveck_make_hint(mldsa_polyveck *h,
                                const mldsa_polyveck *v0,
                                const mldsa_polyveck *v1)
{
  unsigned int i, s = 0;

  for(i = 0; i < MLDSA_K; ++i)
    s += mldsa_poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);

  return s;
}


static void mldsa_polyveck_use_hint(mldsa_polyveck *w, const mldsa_polyveck *u, const mldsa_polyveck *h) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_poly_use_hint(&w->vec[i], &u->vec[i], &h->vec[i]);
}

static void mldsa_polyveck_pack_w1(uint8_t r[MLDSA_K*MLDSA_POLYW1_PACKEDBYTES], const mldsa_polyveck *w1) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_polyw1_pack(&r[i*MLDSA_POLYW1_PACKEDBYTES], &w1->vec[i]);
}


static void mldsa_pack_pk(uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
             const uint8_t rho[MLDSA_SEEDBYTES],
             const mldsa_polyveck *t1)
{
  unsigned int i;

  for(i = 0; i < MLDSA_SEEDBYTES; ++i)
    pk[i] = rho[i];
  pk += MLDSA_SEEDBYTES;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_polyt1_pack(pk + i*MLDSA_POLYT1_PACKEDBYTES, &t1->vec[i]);
}


static void mldsa_unpack_pk(uint8_t rho[MLDSA_SEEDBYTES],
               mldsa_polyveck *t1,
               const uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES])
{
  unsigned int i;

  for(i = 0; i < MLDSA_SEEDBYTES; ++i)
    rho[i] = pk[i];
  pk += MLDSA_SEEDBYTES;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_polyt1_unpack(&t1->vec[i], pk + i*MLDSA_POLYT1_PACKEDBYTES);
}


static void mldsa_pack_sk(uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
             const uint8_t rho[MLDSA_SEEDBYTES],
             const uint8_t tr[MLDSA_TRBYTES],
             const uint8_t key[MLDSA_SEEDBYTES],
             const mldsa_polyveck *t0,
             const mldsa_polyvecl *s1,
             const mldsa_polyveck *s2)
{
  unsigned int i;

  for(i = 0; i < MLDSA_SEEDBYTES; ++i)
    sk[i] = rho[i];
  sk += MLDSA_SEEDBYTES;

  for(i = 0; i < MLDSA_SEEDBYTES; ++i)
    sk[i] = key[i];
  sk += MLDSA_SEEDBYTES;

  for(i = 0; i < MLDSA_TRBYTES; ++i)
    sk[i] = tr[i];
  sk += MLDSA_TRBYTES;

  for(i = 0; i < MLDSA_L; ++i)
    mldsa_polyeta_pack(sk + i*MLDSA_POLYETA_PACKEDBYTES, &s1->vec[i]);
  sk += MLDSA_L*MLDSA_POLYETA_PACKEDBYTES;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_polyeta_pack(sk + i*MLDSA_POLYETA_PACKEDBYTES, &s2->vec[i]);
  sk += MLDSA_K*MLDSA_POLYETA_PACKEDBYTES;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_polyt0_pack(sk + i*MLDSA_POLYT0_PACKEDBYTES, &t0->vec[i]);
}


static void mldsa_unpack_sk(uint8_t rho[MLDSA_SEEDBYTES],
               uint8_t tr[MLDSA_TRBYTES],
               uint8_t key[MLDSA_SEEDBYTES],
               mldsa_polyveck *t0,
               mldsa_polyvecl *s1,
               mldsa_polyveck *s2,
               const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES])
{
  unsigned int i;

  for(i = 0; i < MLDSA_SEEDBYTES; ++i)
    rho[i] = sk[i];
  sk += MLDSA_SEEDBYTES;

  for(i = 0; i < MLDSA_SEEDBYTES; ++i)
    key[i] = sk[i];
  sk += MLDSA_SEEDBYTES;

  for(i = 0; i < MLDSA_TRBYTES; ++i)
    tr[i] = sk[i];
  sk += MLDSA_TRBYTES;

  for(i=0; i < MLDSA_L; ++i)
    mldsa_polyeta_unpack(&s1->vec[i], sk + i*MLDSA_POLYETA_PACKEDBYTES);
  sk += MLDSA_L*MLDSA_POLYETA_PACKEDBYTES;

  for(i=0; i < MLDSA_K; ++i)
    mldsa_polyeta_unpack(&s2->vec[i], sk + i*MLDSA_POLYETA_PACKEDBYTES);
  sk += MLDSA_K*MLDSA_POLYETA_PACKEDBYTES;

  for(i=0; i < MLDSA_K; ++i)
    mldsa_polyt0_unpack(&t0->vec[i], sk + i*MLDSA_POLYT0_PACKEDBYTES);
}


static void mldsa_pack_sig(uint8_t sig[MLDSA_CRYPTO_BYTES],
              const uint8_t c[MLDSA_CTILDEBYTES],
              const mldsa_polyvecl *z,
              const mldsa_polyveck *h)
{
  unsigned int i, j, k;

  for(i=0; i < MLDSA_CTILDEBYTES; ++i)
    sig[i] = c[i];
  sig += MLDSA_CTILDEBYTES;

  for(i = 0; i < MLDSA_L; ++i)
    mldsa_polyz_pack(sig + i*MLDSA_POLYZ_PACKEDBYTES, &z->vec[i]);
  sig += MLDSA_L*MLDSA_POLYZ_PACKEDBYTES;

  // Encode the hint vector.
  for(i = 0; i < MLDSA_OMEGA + MLDSA_K; ++i)
    sig[i] = 0;

  k = 0;
  for(i = 0; i < MLDSA_K; ++i) {
    for(j = 0; j < MLDSA_N; ++j)
      if(h->vec[i].coeffs[j] != 0)
        sig[k++] = (uint8_t)j;

    sig[MLDSA_OMEGA + i] = (uint8_t)k;
  }
}


static int mldsa_unpack_sig(uint8_t c[MLDSA_CTILDEBYTES],
               mldsa_polyvecl *z,
               mldsa_polyveck *h,
               const uint8_t sig[MLDSA_CRYPTO_BYTES])
{
  unsigned int i, j, k;

  for(i = 0; i < MLDSA_CTILDEBYTES; ++i)
    c[i] = sig[i];
  sig += MLDSA_CTILDEBYTES;

  for(i = 0; i < MLDSA_L; ++i)
    mldsa_polyz_unpack(&z->vec[i], sig + i*MLDSA_POLYZ_PACKEDBYTES);
  sig += MLDSA_L*MLDSA_POLYZ_PACKEDBYTES;

  // Decode the hint vector.
  k = 0;
  for(i = 0; i < MLDSA_K; ++i) {
    for(j = 0; j < MLDSA_N; ++j)
      h->vec[i].coeffs[j] = 0;

    if(sig[MLDSA_OMEGA + i] < k || sig[MLDSA_OMEGA + i] > MLDSA_OMEGA)
      return 1;

    for(j = k; j < sig[MLDSA_OMEGA + i]; ++j) {
      // Keep the coefficient order required for strong unforgeability.
      if(j > k && sig[j] <= sig[j-1]) return 1;
      h->vec[i].coeffs[sig[j]] = 1;
    }

    k = sig[MLDSA_OMEGA + i];
  }

  // Set unused hint indices to zero.
  for(j = k; j < MLDSA_OMEGA; ++j)
    if(sig[j])
      return 1;

  return 0;
}


static void mldsa_shake128_stream_init(keccak_state *state, const uint8_t seed[MLDSA_SEEDBYTES], uint16_t nonce)
{
  uint8_t t[2];
  t[0] = (uint8_t)nonce;
  t[1] = (uint8_t)(nonce >> 8);

  shake128_init(state);
  shake128_absorb(state, seed, MLDSA_SEEDBYTES);
  shake128_absorb(state, t, 2);
  shake128_finalize(state);
}

static void mldsa_shake256_stream_init(keccak_state *state, const uint8_t seed[MLDSA_CRHBYTES], uint16_t nonce)
{
  uint8_t t[2];
  t[0] = (uint8_t)nonce;
  t[1] = (uint8_t)(nonce >> 8);

  shake256_init(state);
  shake256_absorb(state, seed, MLDSA_CRHBYTES);
  shake256_absorb(state, t, 2);
  shake256_finalize(state);
}


static int mldsa_keypair_derand(uint8_t *pk, uint8_t *sk,
                               const uint8_t seed[MLDSA_SEEDBYTES]) {
  uint8_t seedbuf[2*MLDSA_SEEDBYTES + MLDSA_CRHBYTES];
  uint8_t tr[MLDSA_TRBYTES];
  const uint8_t *rho, *rhoprime, *key;
  mldsa_polyvecl mat[MLDSA_K];
  mldsa_polyvecl s1, s1hat;
  mldsa_polyveck s2, t1, t0;

  // Expand the key-generation seed.
  memcpy(seedbuf, seed, MLDSA_SEEDBYTES);
  seedbuf[MLDSA_SEEDBYTES+0] = MLDSA_K;
  seedbuf[MLDSA_SEEDBYTES+1] = MLDSA_L;
  shake256(seedbuf, 2*MLDSA_SEEDBYTES + MLDSA_CRHBYTES, seedbuf, MLDSA_SEEDBYTES+2);
  rho = seedbuf;
  rhoprime = rho + MLDSA_SEEDBYTES;
  key = rhoprime + MLDSA_CRHBYTES;

  // Expand the public matrix.
  mldsa_polyvec_matrix_expand(mat, rho);

  // Sample the secret vectors.
  mldsa_polyvecl_uniform_eta(&s1, rhoprime, 0);
  mldsa_polyveck_uniform_eta(&s2, rhoprime, MLDSA_L);

  // Compute the matrix-vector product.
  s1hat = s1;
  mldsa_polyvecl_ntt(&s1hat);
  mldsa_polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
  mldsa_polyveck_reduce(&t1);
  mldsa_polyveck_invntt_tomont(&t1);

  // Add the second secret vector.
  mldsa_polyveck_add(&t1, &t1, &s2);

  // Round t and serialize t1.
  mldsa_polyveck_caddq(&t1);
  mldsa_polyveck_power2round(&t1, &t0, &t1);
  mldsa_pack_pk(pk, rho, &t1);

  // Store the public-key hash and secret key.
  shake256(tr, MLDSA_TRBYTES, pk, MLDSA_CRYPTO_PUBLICKEYBYTES);
  mldsa_pack_sk(sk, rho, tr, key, &t0, &s1, &s2);

  ncrypt_wipe(seedbuf, sizeof seedbuf);
  ncrypt_wipe(&s1,    sizeof s1);
  ncrypt_wipe(&s1hat, sizeof s1hat);
  ncrypt_wipe(&s2,    sizeof s2);
  ncrypt_wipe(&t0,    sizeof t0);
  return 0;
}


static void mldsa_signature_internal(uint8_t *sig,
                                    const uint8_t *m,
                                    size_t mlen,
                                    const uint8_t *pre,
                                    size_t prelen,
                                    const uint8_t rnd[MLDSA_RNDBYTES],
                                    const uint8_t *sk)
{
  unsigned int n;
  uint8_t seedbuf[2*MLDSA_SEEDBYTES + MLDSA_TRBYTES + 2*MLDSA_CRHBYTES];
  uint8_t *rho, *tr, *key, *mu, *rhoprime;
  uint16_t nonce = 0;
  mldsa_polyvecl mat[MLDSA_K], s1, y, z;
  mldsa_polyveck t0, s2, w1, w0, h;
  mldsa_poly cp;
  keccak_state state;

  rho = seedbuf;
  tr = rho + MLDSA_SEEDBYTES;
  key = tr + MLDSA_TRBYTES;
  mu = key + MLDSA_SEEDBYTES;
  rhoprime = mu + MLDSA_CRHBYTES;
  mldsa_unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

  // Compute the message representative mu.
  shake256_init(&state);
  shake256_absorb(&state, tr, MLDSA_TRBYTES);
  shake256_absorb(&state, pre, prelen);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, MLDSA_CRHBYTES, &state);

  // Derive the per-signature seed.
  shake256_init(&state);
  shake256_absorb(&state, key, MLDSA_SEEDBYTES);
  shake256_absorb(&state, rnd, MLDSA_RNDBYTES);
  shake256_absorb(&state, mu, MLDSA_CRHBYTES);
  shake256_finalize(&state);
  shake256_squeeze(rhoprime, MLDSA_CRHBYTES, &state);

  // Expand the matrix and transform the secret vectors.
  mldsa_polyvec_matrix_expand(mat, rho);
  mldsa_polyvecl_ntt(&s1);
  mldsa_polyveck_ntt(&s2);
  mldsa_polyveck_ntt(&t0);

rej:
  // Sample the masking vector.
  mldsa_polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

  // Compute the matrix-vector product.
  z = y;
  mldsa_polyvecl_ntt(&z);
  mldsa_polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
  mldsa_polyveck_reduce(&w1);
  mldsa_polyveck_invntt_tomont(&w1);

  // Decompose w and derive the challenge.
  mldsa_polyveck_caddq(&w1);
  mldsa_polyveck_decompose(&w1, &w0, &w1);
  mldsa_polyveck_pack_w1(sig, &w1);

  shake256_init(&state);
  shake256_absorb(&state, mu, MLDSA_CRHBYTES);
  shake256_absorb(&state, sig, MLDSA_K*MLDSA_POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(sig, MLDSA_CTILDEBYTES, &state);
  mldsa_poly_challenge(&cp, sig);
  mldsa_poly_ntt(&cp);

  // Compute z and reject if it is too large.
  mldsa_polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
  mldsa_polyvecl_invntt_tomont(&z);
  mldsa_polyvecl_add(&z, &z, &y);
  mldsa_polyvecl_reduce(&z);
  if(mldsa_polyvecl_chknorm(&z, MLDSA_GAMMA1 - MLDSA_BETA))
    goto rej;

  // Check the low bits before computing hints.
  mldsa_polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
  mldsa_polyveck_invntt_tomont(&h);
  mldsa_polyveck_sub(&w0, &w0, &h);
  mldsa_polyveck_reduce(&w0);
  if(mldsa_polyveck_chknorm(&w0, MLDSA_GAMMA2 - MLDSA_BETA))
    goto rej;

  // Compute the hint vector.
  mldsa_polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
  mldsa_polyveck_invntt_tomont(&h);
  mldsa_polyveck_reduce(&h);
  if(mldsa_polyveck_chknorm(&h, MLDSA_GAMMA2))
    goto rej;

  mldsa_polyveck_add(&w0, &w0, &h);
  n = mldsa_polyveck_make_hint(&h, &w0, &w1);
  if(n > MLDSA_OMEGA)
    goto rej;

  // Serialize the signature.
  mldsa_pack_sig(sig, sig, &z, &h);

  // Wipe every local that held a secret or secret-derived value.
  // The final z, w1, h, and cp are public, but the same storage held
  // the values of rejected iterations, which are not. mat is public
  // and is wiped for uniformity; the cost is negligible.
  ncrypt_wipe(seedbuf, sizeof seedbuf);
  ncrypt_wipe(mat, sizeof mat);
  ncrypt_wipe(&s1, sizeof s1);
  ncrypt_wipe(&s2, sizeof s2);
  ncrypt_wipe(&t0, sizeof t0);
  ncrypt_wipe(&y,  sizeof y);
  ncrypt_wipe(&z,  sizeof z);
  ncrypt_wipe(&w0, sizeof w0);
  ncrypt_wipe(&w1, sizeof w1);
  ncrypt_wipe(&h,  sizeof h);
  ncrypt_wipe(&cp, sizeof cp);
  ncrypt_wipe(&state, sizeof state);
}


// Build the FIPS 204 domain separator (0 || |ctx| || ctx) and sign.
// Returns -1 if the context is too long, in which case nothing is
// written to sig.
static int mldsa_signature(uint8_t *sig,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *ctx, size_t ctxlen,
                          const uint8_t rnd[MLDSA_RNDBYTES],
                          const uint8_t *sk)
{
  size_t i;
  uint8_t pre[257];

  if(ctxlen > 255)
    return -1;

  pre[0] = 0;
  pre[1] = (uint8_t)ctxlen;
  for(i = 0; i < ctxlen; i++)
    pre[2 + i] = ctx[i];

  mldsa_signature_internal(sig, m, mlen, pre, 2+ctxlen, rnd, sk);
  return 0;
}


static int mldsa_verify_internal(const uint8_t *sig,
                                const uint8_t *m,
                                size_t mlen,
                                const uint8_t *pre,
                                size_t prelen,
                                const uint8_t *pk)
{
  unsigned int i;
  uint8_t buf[MLDSA_K*MLDSA_POLYW1_PACKEDBYTES];
  uint8_t rho[MLDSA_SEEDBYTES];
  uint8_t mu[MLDSA_CRHBYTES];
  uint8_t c[MLDSA_CTILDEBYTES];
  uint8_t c2[MLDSA_CTILDEBYTES];
  uint8_t diff;
  mldsa_poly cp;
  mldsa_polyvecl mat[MLDSA_K], z;
  mldsa_polyveck t1, w1, h;
  keccak_state state;

  mldsa_unpack_pk(rho, &t1, pk);
  if(mldsa_unpack_sig(c, &z, &h, sig))
    return -1;
  if(mldsa_polyvecl_chknorm(&z, MLDSA_GAMMA1 - MLDSA_BETA))
    return -1;

  // Derive the expected challenge.
  shake256(mu, MLDSA_TRBYTES, pk, MLDSA_CRYPTO_PUBLICKEYBYTES);
  shake256_init(&state);
  shake256_absorb(&state, mu, MLDSA_TRBYTES);
  shake256_absorb(&state, pre, prelen);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, MLDSA_CRHBYTES, &state);

  // Compute Az - c * 2^d * t1.
  mldsa_poly_challenge(&cp, c);
  mldsa_polyvec_matrix_expand(mat, rho);

  mldsa_polyvecl_ntt(&z);
  mldsa_polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

  mldsa_poly_ntt(&cp);
  mldsa_polyveck_shiftl(&t1);
  mldsa_polyveck_ntt(&t1);
  mldsa_polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

  mldsa_polyveck_sub(&w1, &w1, &t1);
  mldsa_polyveck_reduce(&w1);
  mldsa_polyveck_invntt_tomont(&w1);

  // Reconstruct the high bits of w.
  mldsa_polyveck_caddq(&w1);
  mldsa_polyveck_use_hint(&w1, &w1, &h);
  mldsa_polyveck_pack_w1(buf, &w1);

  // Recompute and compare the challenge. Both values are public; the
  // comparison is branch-free only to keep the code uniform.
  shake256_init(&state);
  shake256_absorb(&state, mu, MLDSA_CRHBYTES);
  shake256_absorb(&state, buf, MLDSA_K*MLDSA_POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(c2, MLDSA_CTILDEBYTES, &state);
  diff = 0;
  for(i = 0; i < MLDSA_CTILDEBYTES; ++i)
    diff |= (uint8_t)(c[i] ^ c2[i]);

  // Branch-free "diff == 0 ? 0 : -1".  The challenge is public, so a
  // branch would be harmless; keeping the code uniform makes the
  // constant-time harness (make ct) quiet and easier to review.
  return (int)(((uint64_t)diff - 1) >> 63) - 1;
}


static int mldsa_verify(const uint8_t *sig,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *ctx, size_t ctxlen,
                       const uint8_t *pk)
{
  size_t i;
  uint8_t pre[257];

  if(ctxlen > 255)
    return -1;

  pre[0] = 0;
  pre[1] = (uint8_t)ctxlen;
  for(i = 0; i < ctxlen; i++)
    pre[2 + i] = ctx[i];

  return mldsa_verify_internal(sig, m, mlen, pre, 2+ctxlen, pk);
}

////////////////////////////
/// Verdict normalisation ///
////////////////////////////

// Map any non-zero verifier result to exactly -1, without branching.
//
// The internal verifiers return -1 today, but they are a chain of early
// returns from static functions, and the documented contract of the
// public API is "0 on success, -1 on failure". Relying on the internal
// value made the public contract depend on an implementation detail: an
// internal verifier that ever returned, say, -2, or a compiler that
// folded the constant, would have silently widened it. Callers that
// compare against -1 (the documented idiom) would then treat a rejected
// signature as valid.
//
// For x == 0 the result is 0; for any non-zero 32-bit value with the
// sign bit set it is -1. Both branches of the expression stay in
// unsigned arithmetic, so there is no overflow and no branch.
static int mldsa_verdict(int x)
{
	uint32_t u = (uint32_t)x;
	return -(int)((u | (0u - u)) >> 31);
}

////////////////////////////
/// Public API (ML-KEM)  ///
////////////////////////////

void ncrypt_mlkem768_key_pair(uint8_t secret_key[NCRYPT_MLKEM768_SECRET_KEY_SIZE],
                              uint8_t public_key[NCRYPT_MLKEM768_PUBLIC_KEY_SIZE],
                              uint8_t seed      [NCRYPT_MLKEM768_KEY_SEED_SIZE])
{
	(void)mlkem_keypair_derand(public_key, secret_key, seed);
	ncrypt_wipe(seed, NCRYPT_MLKEM768_KEY_SEED_SIZE);
}

int ncrypt_mlkem768_encapsulate(uint8_t       ciphertext   [NCRYPT_MLKEM768_CIPHERTEXT_SIZE],
                                uint8_t       shared_secret[NCRYPT_MLKEM768_SHARED_SECRET_SIZE],
                                const uint8_t public_key   [NCRYPT_MLKEM768_PUBLIC_KEY_SIZE],
                                uint8_t       seed         [NCRYPT_MLKEM768_ENCAPS_SEED_SIZE])
{
	// FIPS 203 section 7.2 (encapsulation key check): every 12-bit
	// coefficient must be below q. The decoder keeps the raw values,
	// so a range check on the decoded vector is equivalent to the
	// re-encoding comparison given in the standard.
	mlkem_polyvec t;
	size_t i, j;
	uint16_t bad = 0;
	mlkem_polyvec_frombytes(&t, public_key);
	for (i = 0; i < KYBER_K; i++) {
		for (j = 0; j < KYBER_N; j++) {
			bad |= (uint16_t)((uint16_t)t.vec[i].coeffs[j] >= KYBER_Q);
		}
	}
	if (bad) {
		ncrypt_wipe(seed, NCRYPT_MLKEM768_ENCAPS_SEED_SIZE);
		return -1;
	}

	(void)mlkem_enc_derand(ciphertext, shared_secret, public_key, seed);
	ncrypt_wipe(seed, NCRYPT_MLKEM768_ENCAPS_SEED_SIZE);
	return 0;
}

int ncrypt_mlkem768_decapsulate(uint8_t       shared_secret[NCRYPT_MLKEM768_SHARED_SECRET_SIZE],
                                const uint8_t ciphertext   [NCRYPT_MLKEM768_CIPHERTEXT_SIZE],
                                const uint8_t secret_key   [NCRYPT_MLKEM768_SECRET_KEY_SIZE])
{
	// FIPS 203 section 7.3, decapsulation key hash check. A forged
	// ciphertext is handled by implicit rejection inside mlkem_dec.
	uint8_t h[32];
	sha3_256(h, secret_key + KYBER_INDCPA_SECRETKEYBYTES,
	         KYBER_PUBLICKEYBYTES);
	if (ncrypt_verify32(h, secret_key + KYBER_SECRETKEYBYTES
	                       - 2*KYBER_SYMBYTES) != 0) {
		return -1;
	}
	(void)mlkem_dec(shared_secret, ciphertext, secret_key);
	return 0;
}


////////////////////////////
/// Public API (ML-DSA)  ///
////////////////////////////

void ncrypt_mldsa44_key_pair(uint8_t secret_key[NCRYPT_MLDSA44_SECRET_KEY_SIZE],
                             uint8_t public_key[NCRYPT_MLDSA44_PUBLIC_KEY_SIZE],
                             uint8_t seed      [NCRYPT_MLDSA44_KEY_SEED_SIZE])
{
	(void)mldsa_keypair_derand(public_key, secret_key, seed);
	ncrypt_wipe(seed, NCRYPT_MLDSA44_KEY_SEED_SIZE);
}

int ncrypt_mldsa44_sign(uint8_t        signature [NCRYPT_MLDSA44_SIGNATURE_SIZE],
                        const uint8_t  secret_key[NCRYPT_MLDSA44_SECRET_KEY_SIZE],
                        uint8_t        rnd       [NCRYPT_MLDSA44_RND_SIZE],
                        const uint8_t *context, size_t context_size,
                        const uint8_t *message, size_t message_size)
{
	int status = mldsa_signature(signature, message, message_size,
	                             context, context_size, rnd, secret_key);
	ncrypt_wipe(rnd, NCRYPT_MLDSA44_RND_SIZE);
	return status;
}

int ncrypt_mldsa44_sign_deterministic(uint8_t        signature [NCRYPT_MLDSA44_SIGNATURE_SIZE],
                                      const uint8_t  secret_key[NCRYPT_MLDSA44_SECRET_KEY_SIZE],
                                      const uint8_t *context, size_t context_size,
                                      const uint8_t *message, size_t message_size)
{
	// FIPS 204 algorithm 2, step 6: the deterministic variant uses a
	// rnd of 32 zero bytes.
	static const uint8_t zero_rnd[NCRYPT_MLDSA44_RND_SIZE] = {0};
	return mldsa_signature(signature, message, message_size,
	                       context, context_size, zero_rnd, secret_key);
}

int ncrypt_mldsa44_check(const uint8_t  signature [NCRYPT_MLDSA44_SIGNATURE_SIZE],
                         const uint8_t  public_key[NCRYPT_MLDSA44_PUBLIC_KEY_SIZE],
                         const uint8_t *context, size_t context_size,
                         const uint8_t *message, size_t message_size)
{
	return mldsa_verdict(mldsa_verify(signature, message, message_size,
	                                  context, context_size, public_key));
}


///////////////////////////
/// High-level wrappers ///
///////////////////////////

void ncrypt_pqc_key_pair(uint8_t secret_key[NCRYPT_MLKEM768_SECRET_KEY_SIZE],
                         uint8_t public_key[NCRYPT_MLKEM768_PUBLIC_KEY_SIZE],
                         uint8_t seed      [NCRYPT_MLKEM768_KEY_SEED_SIZE])
{
	ncrypt_mlkem768_key_pair(secret_key, public_key, seed);
}

void ncrypt_pqc_sign_key_pair(uint8_t secret_key[NCRYPT_MLDSA44_SECRET_KEY_SIZE],
                              uint8_t public_key[NCRYPT_MLDSA44_PUBLIC_KEY_SIZE],
                              uint8_t seed      [NCRYPT_MLDSA44_KEY_SEED_SIZE])
{
	ncrypt_mldsa44_key_pair(secret_key, public_key, seed);
}

// Derive the one-time AEAD key and nonce for the hybrid construction:
//
//     key || nonce = BLAKE2b-56(key = shared_secret,
//                               msg = "ncrypt-pqc-v1" || kem_ct)
//
// The shared secret already depends on the recipient public key and
// on the encapsulation seed, and kem_ct is hashed in as well so that
// the record is bound to the ciphertext the receiver actually got.
// Since both key and nonce are derived from the encapsulation, they
// are unique whenever the encapsulation is; that is, whenever the seed
// is fresh. The label separates this derivation from any other use of
// the same shared secret.
static const uint8_t pqc_kdf_label[13] = "ncrypt-pqc-v1";

static void pqc_message_key(uint8_t key[32], uint8_t nonce[24],
                            const uint8_t shared[NCRYPT_MLKEM768_SHARED_SECRET_SIZE],
                            const uint8_t kem_ct[NCRYPT_PQC_KEM_CT_SIZE])
{
	uint8_t okm[56];
	ncrypt_blake2b_ctx ctx;
	ncrypt_blake2b_keyed_init(&ctx, sizeof okm,
	                          shared, NCRYPT_MLKEM768_SHARED_SECRET_SIZE);
	ncrypt_blake2b_update(&ctx, pqc_kdf_label, sizeof pqc_kdf_label);
	ncrypt_blake2b_update(&ctx, kem_ct, NCRYPT_PQC_KEM_CT_SIZE);
	ncrypt_blake2b_final(&ctx, okm);
	memcpy(key,   okm,      32);
	memcpy(nonce, okm + 32, 24);
	ncrypt_wipe(okm, sizeof okm);
	ncrypt_wipe(&ctx, sizeof ctx);
}

int ncrypt_pqc_encrypt(uint8_t       *cipher_text,
                       uint8_t        mac             [NCRYPT_PQC_MAC_SIZE],
                       uint8_t        kem_ct          [NCRYPT_PQC_KEM_CT_SIZE],
                       const uint8_t  their_public_key[NCRYPT_MLKEM768_PUBLIC_KEY_SIZE],
                       uint8_t        seed            [NCRYPT_PQC_SEED_SIZE],
                       const uint8_t *ad,         size_t ad_size,
                       const uint8_t *plain_text, size_t text_size)
{
	uint8_t shared[NCRYPT_MLKEM768_SHARED_SECRET_SIZE];
	uint8_t key   [32];
	uint8_t nonce [24];

	if (ncrypt_mlkem768_encapsulate(kem_ct, shared,
	                                their_public_key, seed) != 0) {
		return -1;
	}
	pqc_message_key(key, nonce, shared, kem_ct);
	ncrypt_aead_lock(cipher_text, mac, key, nonce,
	                 ad, ad_size, plain_text, text_size);
	ncrypt_wipe(shared, sizeof shared);
	ncrypt_wipe(key,    sizeof key);
	ncrypt_wipe(nonce,  sizeof nonce);
	return 0;
}

int ncrypt_pqc_decrypt(uint8_t       *plain_text,
                       const uint8_t  kem_ct     [NCRYPT_PQC_KEM_CT_SIZE],
                       const uint8_t  mac        [NCRYPT_PQC_MAC_SIZE],
                       const uint8_t  secret_key [NCRYPT_MLKEM768_SECRET_KEY_SIZE],
                       const uint8_t *ad,          size_t ad_size,
                       const uint8_t *cipher_text, size_t text_size)
{
	uint8_t shared[NCRYPT_MLKEM768_SHARED_SECRET_SIZE];
	uint8_t key   [32];
	uint8_t nonce [24];
	int mismatch;

	if (ncrypt_mlkem768_decapsulate(shared, kem_ct, secret_key) != 0) {
		return -1;
	}
	pqc_message_key(key, nonce, shared, kem_ct);
	mismatch = ncrypt_aead_unlock(plain_text, mac, key, nonce,
	                              ad, ad_size, cipher_text, text_size);
	// Wipe unconditionally, and normalise the verdict, before returning:
	// the failure path must leave no copy of the message key behind and
	// must report exactly -1, as documented.
	ncrypt_wipe(shared, sizeof shared);
	ncrypt_wipe(key,    sizeof key);
	ncrypt_wipe(nonce,  sizeof nonce);
	return mldsa_verdict(mismatch);
}

void ncrypt_pqc_sign(uint8_t        signature [NCRYPT_MLDSA44_SIGNATURE_SIZE],
                     const uint8_t  secret_key[NCRYPT_MLDSA44_SECRET_KEY_SIZE],
                     uint8_t        rnd       [NCRYPT_MLDSA44_RND_SIZE],
                     const uint8_t *message, size_t message_size)
{
	// The empty context can never make this call fail.
	(void)ncrypt_mldsa44_sign(signature, secret_key, rnd, 0, 0,
	                          message, message_size);
}

int ncrypt_pqc_check(const uint8_t  signature [NCRYPT_MLDSA44_SIGNATURE_SIZE],
                     const uint8_t  public_key[NCRYPT_MLDSA44_PUBLIC_KEY_SIZE],
                     const uint8_t *message, size_t message_size)
{
	return ncrypt_mldsa44_check(signature, public_key, 0, 0,
	                            message, message_size);
}
