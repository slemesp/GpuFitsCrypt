/*
 * aes_gcm_kernel.cu – Fused AES-CTR + GHASH GPU kernel for AES-GCM.
 *
 * Overview
 * --------
 * This kernel fuses the two data-parallel phases of AES-GCM into a single
 * pass over the plaintext / ciphertext to maximise throughput and minimise
 * global-memory traffic:
 *
 *   Phase A – AES-CTR encryption/decryption  (data-parallel, one thread per block)
 *       C_i = P_i XOR AES_K(J0 + i)
 *
 *   Phase B – GHASH partial-product computation  (see ghash_kernel.cu)
 *       partial[i] = C_i * H^(m - i)
 *
 * The XOR tree reduction (Phase 3 of GHASH) and the final tag computation
 *     T = AES_K(J0) XOR GHASH_result
 * are performed in separate passes after this kernel completes.
 *
 * AES Implementation
 * ------------------
 * AES is implemented using the byte-substitution / shift-rows / mix-columns
 * structure described in NIST FIPS 197, with the S-box stored in __constant__
 * memory for warp-broadcast efficiency.
 *
 * TODO (future optimisation): On Volta and later architectures the S-box
 * table lookups below could be replaced with AES-NI-equivalent `__aes_*`
 * PTX intrinsics to reduce register pressure and improve throughput.
 *
 * The AES S-box is stored in __constant__ memory so it is broadcast across
 * warp reads with a single cache line.
 *
 * Thread / Block Dimensions
 * -------------------------
 * Each thread processes one 16-byte AES block.  Threads within a block
 * cooperate on the GHASH reduction in shared memory.
 *
 *     Grid:  ceil(num_blocks / BLOCK_SIZE) × 1 × 1
 *     Block: BLOCK_SIZE × 1 × 1
 *
 * Compilation
 * -----------
 *     nvcc -O3 -arch=sm_80 -c aes_gcm_kernel.cu -o aes_gcm_kernel.o
 */

#include <stdint.h>
#include <cuda_runtime.h>

#define BLOCK_SIZE  256
#define AES_BLOCK   16

/* AES forward S-box in __constant__ memory for warp-broadcast reads. */
__device__ __constant__ uint8_t AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* Round constants for AES key schedule. */
__device__ __constant__ uint8_t AES_RCON[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

/* GF(2^128) element (hi = bits 127..64, lo = bits 63..0, MSB-first). */
typedef struct { uint64_t hi; uint64_t lo; } gf128_t;
__device__ __constant__ gf128_t GCM_R_AES = { 0xE100000000000000ULL, 0ULL };

/* -------------------------------------------------------------------------
 * Device: GF(2^128) multiply – same algorithm as in ghash_kernel.cu.
 * ------------------------------------------------------------------------- */
__device__ gf128_t gf128_mul_aes(gf128_t x, gf128_t y)
{
    gf128_t z = {0, 0}, v = x;
    for (int i = 0; i < 128; ++i) {
        int bit = 127 - i;
        uint64_t ybit = (bit >= 64) ? ((y.hi >> (bit - 64)) & 1ULL)
                                    : ((y.lo >>  bit       ) & 1ULL);
        if (ybit) { z.hi ^= v.hi; z.lo ^= v.lo; }
        int lsb = (int)(v.lo & 1ULL);
        v.lo = (v.lo >> 1) | (v.hi << 63);
        v.hi >>= 1;
        if (lsb) { v.hi ^= GCM_R_AES.hi; v.lo ^= GCM_R_AES.lo; }
    }
    return z;
}

/* -------------------------------------------------------------------------
 * Device: increment the low-order 32 bits of a 128-bit counter.
 * Counter is stored as four uint32 words in big-endian order: [w0,w1,w2,w3].
 * ------------------------------------------------------------------------- */
__device__ void inc32(uint32_t *ctr)
{
    uint32_t low = __byte_perm(ctr[3], 0, 0x0123);  /* big-endian load */
    low += 1;
    ctr[3] = __byte_perm(low, 0, 0x0123);            /* big-endian store */
}

/* -------------------------------------------------------------------------
 * Device: AES-128 block encryption using the pre-expanded key schedule.
 *
 * `key_schedule` points to 11 round keys × 16 bytes each, packed as
 * uint32 words in big-endian column-major order (standard FIPS 197 layout).
 *
 * Output is written to `out[0..15]`.
 * ------------------------------------------------------------------------- */
__device__ void aes128_encrypt_block(
    const uint32_t *key_schedule, /* 44 uint32 words */
    const uint8_t  *in,
    uint8_t        *out)
{
    uint8_t state[16];
    #pragma unroll
    for (int i = 0; i < 16; ++i)
        state[i] = in[i] ^ ((const uint8_t *)key_schedule)[i];

    /* Rounds 1–9 (SubBytes + ShiftRows + MixColumns + AddRoundKey). */
    for (int r = 1; r <= 9; ++r) {
        uint8_t tmp[16];
        /* SubBytes + ShiftRows combined using S-box with row offsets. */
        tmp[ 0] = AES_SBOX[state[ 0]]; tmp[ 1] = AES_SBOX[state[ 5]];
        tmp[ 2] = AES_SBOX[state[10]]; tmp[ 3] = AES_SBOX[state[15]];
        tmp[ 4] = AES_SBOX[state[ 4]]; tmp[ 5] = AES_SBOX[state[ 9]];
        tmp[ 6] = AES_SBOX[state[14]]; tmp[ 7] = AES_SBOX[state[ 3]];
        tmp[ 8] = AES_SBOX[state[ 8]]; tmp[ 9] = AES_SBOX[state[13]];
        tmp[10] = AES_SBOX[state[ 2]]; tmp[11] = AES_SBOX[state[ 7]];
        tmp[12] = AES_SBOX[state[12]]; tmp[13] = AES_SBOX[state[ 1]];
        tmp[14] = AES_SBOX[state[ 6]]; tmp[15] = AES_SBOX[state[11]];
        /* MixColumns. */
        #define xtime(a) ((uint8_t)(((a) << 1) ^ (((a) >> 7) & 1) * 0x1b))
        for (int c = 0; c < 4; ++c) {
            uint8_t s0 = tmp[c*4], s1 = tmp[c*4+1],
                    s2 = tmp[c*4+2], s3 = tmp[c*4+3];
            state[c*4  ] = xtime(s0)^xtime(s1)^s1^s2^s3;
            state[c*4+1] = s0^xtime(s1)^xtime(s2)^s2^s3;
            state[c*4+2] = s0^s1^xtime(s2)^xtime(s3)^s3;
            state[c*4+3] = xtime(s0)^s0^s1^s2^xtime(s3);
        }
        #undef xtime
        /* AddRoundKey. */
        const uint8_t *rk = (const uint8_t *)(key_schedule + r * 4);
        for (int i = 0; i < 16; ++i) state[i] ^= rk[i];
    }

    /* Final round (no MixColumns). */
    {
        const uint8_t *rk = (const uint8_t *)(key_schedule + 40);
        out[ 0] = AES_SBOX[state[ 0]] ^ rk[ 0]; out[ 1] = AES_SBOX[state[ 5]] ^ rk[ 1];
        out[ 2] = AES_SBOX[state[10]] ^ rk[ 2]; out[ 3] = AES_SBOX[state[15]] ^ rk[ 3];
        out[ 4] = AES_SBOX[state[ 4]] ^ rk[ 4]; out[ 5] = AES_SBOX[state[ 9]] ^ rk[ 5];
        out[ 6] = AES_SBOX[state[14]] ^ rk[ 6]; out[ 7] = AES_SBOX[state[ 3]] ^ rk[ 7];
        out[ 8] = AES_SBOX[state[ 8]] ^ rk[ 8]; out[ 9] = AES_SBOX[state[13]] ^ rk[ 9];
        out[10] = AES_SBOX[state[ 2]] ^ rk[10]; out[11] = AES_SBOX[state[ 7]] ^ rk[11];
        out[12] = AES_SBOX[state[12]] ^ rk[12]; out[13] = AES_SBOX[state[ 1]] ^ rk[13];
        out[14] = AES_SBOX[state[ 6]] ^ rk[14]; out[15] = AES_SBOX[state[11]] ^ rk[15];
    }
}

/* -------------------------------------------------------------------------
 * Main fused AES-CTR + GHASH partial-products kernel.
 *
 * Each thread i:
 *   1. Constructs counter_i = inc32(J0, i+1) as a 128-bit block.
 *   2. Encrypts counter_i to get keystream_i = AES_K(counter_i).
 *   3. XORs keystream_i with the plaintext/ciphertext block to produce
 *      ciphertext/plaintext output.
 *   4. Computes the GHASH partial product:
 *          partial[i] = ciphertext_block[i] * H_powers[m - i]
 *
 * Parameters:
 *   d_input       – plaintext (encrypt) or ciphertext (decrypt), padded to
 *                   a multiple of 16 bytes.
 *   d_output      – output buffer (same size as d_input).
 *   d_partial     – GHASH partial products output (m elements).
 *   d_key_sched   – AES key schedule (44 or 60 uint32 for AES-128/192/256).
 *   d_h_powers    – H^1 … H^m on-device.
 *   j0            – J0 counter as a 128-bit big-endian byte array.
 *   m             – number of 16-byte blocks.
 * ------------------------------------------------------------------------- */
__global__ void aes_gcm_ctr_ghash(
    const uint8_t  * __restrict__ d_input,
    uint8_t        * __restrict__ d_output,
    gf128_t        * __restrict__ d_partial,
    const uint32_t * __restrict__ d_key_sched,
    const gf128_t  * __restrict__ d_h_powers,
    const uint8_t                 j0[16],
    int m)
{
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= m) return;

    /* Step 1: build counter block = inc32(J0, i+1). */
    uint8_t ctr[16];
    #pragma unroll
    for (int b = 0; b < 16; ++b) ctr[b] = j0[b];
    /* Increment the low-order 32-bit word (bytes 12-15) by (i+1). */
    uint32_t ctr32 = ((uint32_t)ctr[12] << 24) | ((uint32_t)ctr[13] << 16)
                   | ((uint32_t)ctr[14] <<  8) |  (uint32_t)ctr[15];
    ctr32 += (uint32_t)(i + 1);
    ctr[12] = (uint8_t)(ctr32 >> 24); ctr[13] = (uint8_t)(ctr32 >> 16);
    ctr[14] = (uint8_t)(ctr32 >>  8); ctr[15] = (uint8_t)(ctr32      );

    /* Step 2: AES-encrypt the counter block to get the keystream block. */
    uint8_t ks[16];
    aes128_encrypt_block(d_key_sched, ctr, ks);

    /* Step 3: XOR with input (encrypt or decrypt – CTR mode is symmetric). */
    uint8_t ct_block[16];
    const uint8_t *in_block = d_input + (size_t)i * 16;
    uint8_t       *out_ptr  = d_output + (size_t)i * 16;
    #pragma unroll
    for (int b = 0; b < 16; ++b) {
        ct_block[b] = in_block[b] ^ ks[b];
        out_ptr[b]  = ct_block[b];
    }

    /* Step 4: GHASH partial product  partial[i] = ciphertext_block[i] * H^(m-i). */
    gf128_t ct_gf;
    ct_gf.hi  = ((uint64_t)ct_block[ 0] << 56) | ((uint64_t)ct_block[ 1] << 48)
              | ((uint64_t)ct_block[ 2] << 40) | ((uint64_t)ct_block[ 3] << 32)
              | ((uint64_t)ct_block[ 4] << 24) | ((uint64_t)ct_block[ 5] << 16)
              | ((uint64_t)ct_block[ 6] <<  8) |  (uint64_t)ct_block[ 7];
    ct_gf.lo  = ((uint64_t)ct_block[ 8] << 56) | ((uint64_t)ct_block[ 9] << 48)
              | ((uint64_t)ct_block[10] << 40) | ((uint64_t)ct_block[11] << 32)
              | ((uint64_t)ct_block[12] << 24) | ((uint64_t)ct_block[13] << 16)
              | ((uint64_t)ct_block[14] <<  8) |  (uint64_t)ct_block[15];

    d_partial[i] = gf128_mul_aes(ct_gf, d_h_powers[m - 1 - i]);
}
