/*
 *   Apache License 2.0
 *
 *   Copyright (c) 2024, Mattias Aabmets
 *
 *   The contents of this file are subject to the terms and conditions defined in the License.
 *   You may not use, modify, or distribute this file except in compliance with the License.
 *
 *   SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include "ttable_aes.h"
#include "aes_sbox.h"

/*
 * Precomputed T‐tables for AES encryption.  Te0..Te3 combine SubBytes,
 * ShiftRows, and MixColumns; Te4 is used for the final round’s SubBytes
 * + ShiftRows (no MixColumns).
 */
static uint32_t Te0[256];
static uint32_t Te1[256];
static uint32_t Te2[256];
static uint32_t Te3[256];
static uint32_t Te4[256];

static int tables_ready = 0;


void add_round_key(uint8_t state[16],
                   const uint8_t round_keys[][16],
                   const uint8_t round) {
#ifdef AES_USE_64BIT_WORDS
    uint64_t *s64 = (uint64_t *)state;
    const uint64_t *rk64 = (const uint64_t *)round_keys[round];
    s64[0] ^= rk64[0];  // XOR bytes [0..7]
    s64[1] ^= rk64[1];  // XOR bytes [8..15]
#else
    uint32_t *s32 = (uint32_t *)state;
    const uint32_t *rk32 = (const uint32_t *)round_keys[round];
    s32[0] ^= rk32[0];  // XOR bytes [0..3]
    s32[1] ^= rk32[1];  // XOR bytes [4..7]
    s32[2] ^= rk32[2];  // XOR bytes [8..11]
    s32[3] ^= rk32[3];  // XOR bytes [12..15]
#endif
}


/*
 * Multiply a byte by {02} in GF(2^8), for table generation.
 */
uint8_t xtime(const uint8_t a) {
    const uint8_t x = (uint8_t)(a << 1);
    const uint8_t y = (uint8_t)(a >> 7);
    return x ^ (uint8_t)(y * 0x1B);
}

/*
 * Generate Te0..Te3 and Te4 using the AES S‐box.  Te0..Te3 encode
 * (SubBytes ◦ ShiftRows ◦ MixColumns) for each possible byte; Te4[x]
 * is simply S‐box[x], for use in the final round (SubBytes+ShiftRows).
 */
static void generate_tables(void) {
    if (tables_ready) {
        return;
    }

    for (int i = 0; i < 256; i++) {
        uint8_t s = aes_sbox[i];
        uint8_t s2 = xtime(s);
        uint8_t s3 = (uint8_t)(s2 ^ s);

        /* Te0[x] = {02}·S[x] <<24 | S[x] <<16 | S[x] <<8 | {03}·S[x] */
        Te0[i] = ((uint32_t)s2 << 24)
               | ((uint32_t)s  << 16)
               | ((uint32_t)s  <<  8)
               | ((uint32_t)s3);

        /* Te1[x] = {03}·S[x] <<24 | {02}·S[x] <<16 | S[x] <<8 | S[x] */
        Te1[i] = ((uint32_t)s3 << 24)
               | ((uint32_t)s2 << 16)
               | ((uint32_t)s  <<  8)
               | ((uint32_t)s);

        /* Te2[x] = S[x] <<24 | {03}·S[x] <<16 | {02}·S[x] <<8 | S[x] */
        Te2[i] = ((uint32_t)s  << 24)
               | ((uint32_t)s3 << 16)
               | ((uint32_t)s2 <<  8)
               | ((uint32_t)s);

        /* Te3[x] = S[x] <<24 | S[x] <<16 | {03}·S[x] <<8 | {02}·S[x] */
        Te3[i] = ((uint32_t)s  << 24)
               | ((uint32_t)s  << 16)
               | ((uint32_t)s3 <<  8)
               | ((uint32_t)s2);

        /* Te4[x] = S[x] (only low byte used; we shift it in final round) */
        Te4[i] = (uint32_t)s;
    }

    tables_ready = 1;
}

/*
 * AES‐128 (or AES‐192/256) encryption of a single 16‐byte block, using
 * precomputed T‐tables.  The full data buffer (potentially multiple blocks)
 * is 'data'; we pick out the 16 bytes at index 'block_index'.  The
 * round keys for every block are concatenated in 'round_keys', with
 * 'key_count' rounds per block.  If tables are not yet generated, we
 * build them at first call.
//
//   data[]:         pointer to a contiguous buffer of (block_count * 16) bytes
//   round_keys[][]: flattened array of size (block_count * key_count) × 16 bytes
//   key_count:      number of round keys per block (e.g. 11 for AES‐128)
//   block_count:    total number of 16‐byte blocks in data[]
//   block_index:    index of the block to encrypt (0 ≤ block_index < block_count)
//   callback:       invoked at the start of each round (for yielding/thumbsup)
//
// This implementation follows the same callback placement as 'clean_aes_encrypt':
//   callback(...) is called just before each non‐final round’s table‐based transform.
*/
void ttable_aes_encrypt(
    uint8_t data[],
    const uint8_t round_keys[][16],
    uint8_t key_count,
    uint8_t block_count,
    uint8_t block_index,
    AES_YieldCallback callback
) {
    generate_tables();

    const uint8_t n_rounds = key_count - 1;
    uint8_t *state = data + (size_t)block_index * 16;
    const uint8_t (*keys)[16] = &round_keys[block_index * key_count];

    uint32_t *state_words = (uint32_t *)state;
    uint32_t s0 = __builtin_bswap32(state_words[0]);
    uint32_t s1 = __builtin_bswap32(state_words[1]);
    uint32_t s2 = __builtin_bswap32(state_words[2]);
    uint32_t s3 = __builtin_bswap32(state_words[3]);

    {
        const uint32_t *rkey = (uint32_t *)keys[0];
        s0 ^= __builtin_bswap32(rkey[0]);
        s1 ^= __builtin_bswap32(rkey[1]);
        s2 ^= __builtin_bswap32(rkey[2]);
        s3 ^= __builtin_bswap32(rkey[3]);
    }

    for (uint8_t round = 1; round < n_rounds; round++) {
        callback(
            data,
            round_keys,
            key_count,
            block_count,
            block_index + 1
        );

        const uint32_t *rkey = (uint32_t *)keys[round];

        uint32_t t0 = Te0[(uint8_t)(s0 >> 24)]
                    ^ Te1[(uint8_t)(s1 >> 16)]
                    ^ Te2[(uint8_t)(s2 >>  8)]
                    ^ Te3[(uint8_t)s3]
                    ^ __builtin_bswap32(rkey[0]);

        uint32_t t1 = Te0[(uint8_t)(s1 >> 24)]
                    ^ Te1[(uint8_t)(s2 >> 16)]
                    ^ Te2[(uint8_t)(s3 >>  8)]
                    ^ Te3[(uint8_t)s0]
                    ^ __builtin_bswap32(rkey[1]);

        uint32_t t2 = Te0[(uint8_t)(s2 >> 24)]
                    ^ Te1[(uint8_t)(s3 >> 16)]
                    ^ Te2[(uint8_t)(s0 >>  8)]
                    ^ Te3[(uint8_t)s1]
                    ^ __builtin_bswap32(rkey[2]);

        uint32_t t3 = Te0[(uint8_t)(s3 >> 24)]
                    ^ Te1[(uint8_t)(s0 >> 16)]
                    ^ Te2[(uint8_t)(s1 >>  8)]
                    ^ Te3[(uint8_t)s2]
                    ^ __builtin_bswap32(rkey[3]);

        /* Prepare for the next round */
        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
    }

    /* Final round (round = n_rounds): SubBytes + ShiftRows + AddRoundKey (no MixColumns) */
    {
        const uint32_t *rkey = (uint32_t *)keys[n_rounds];

        uint32_t out0 = Te4[(uint8_t)(s0 >> 24)] << 24
                      ^ Te4[(uint8_t)(s1 >> 16)] << 16
                      ^ Te4[(uint8_t)(s2 >>  8)] <<  8
                      ^ Te4[(uint8_t)s3]
                      ^ __builtin_bswap32(rkey[0]);

        uint32_t out1 = Te4[(uint8_t)(s1 >> 24)] << 24
                      ^ Te4[(uint8_t)(s2 >> 16)] << 16
                      ^ Te4[(uint8_t)(s3 >>  8)] <<  8
                      ^ Te4[(uint8_t)s0]
                      ^ __builtin_bswap32(rkey[1]);

        uint32_t out2 = Te4[(uint8_t)(s2 >> 24)] << 24
                      ^ Te4[(uint8_t)(s3 >> 16)] << 16
                      ^ Te4[(uint8_t)(s0 >>  8)] <<  8
                      ^ Te4[(uint8_t)s1]
                      ^ __builtin_bswap32(rkey[2]);

        uint32_t out3 = Te4[(uint8_t)(s3 >> 24)] << 24
                      ^ Te4[(uint8_t)(s0 >> 16)] << 16
                      ^ Te4[(uint8_t)(s1 >>  8)] <<  8
                      ^ Te4[(uint8_t)s2]
                      ^ __builtin_bswap32(rkey[3]);

        state_words[0] = __builtin_bswap32(out0);
        state_words[1] = __builtin_bswap32(out1);
        state_words[2] = __builtin_bswap32(out2);
        state_words[3] = __builtin_bswap32(out3);
    }
}

// ====================================================================================================================
// DECRYPTION
// ====================================================================================================================


void sub_bytes(uint8_t state[16], const uint8_t sbox[256]) {
    state[0]  = sbox[state[0]];
    state[1]  = sbox[state[1]];
    state[2]  = sbox[state[2]];
    state[3]  = sbox[state[3]];
    state[4]  = sbox[state[4]];
    state[5]  = sbox[state[5]];
    state[6]  = sbox[state[6]];
    state[7]  = sbox[state[7]];
    state[8]  = sbox[state[8]];
    state[9]  = sbox[state[9]];
    state[10] = sbox[state[10]];
    state[11] = sbox[state[11]];
    state[12] = sbox[state[12]];
    state[13] = sbox[state[13]];
    state[14] = sbox[state[14]];
    state[15] = sbox[state[15]];
}





void inv_shift_rows(uint8_t state[16]) {
    // Row 1 (indices 1,5,9,13): right rotate by 1 (equiv. left rotate by 3)
    uint8_t tmp = state[13];
    state[13]   = state[9];
    state[9]    = state[5];
    state[5]    = state[1];
    state[1]    = tmp;

    // Row 2 (indices 2,6,10,14): right rotate by 2
    tmp       = state[2];
    state[2]  = state[10];
    state[10] = tmp;
    tmp       = state[6];
    state[6]  = state[14];
    state[14] = tmp;

    // Row 3 (indices 3,7,11,15): right rotate by 3 (equiv. left rotate by 1)
    tmp       = state[3];
    state[3]  = state[7];
    state[7]  = state[11];
    state[11] = state[15];
    state[15] = tmp;
}


void mix_single_column(uint8_t state[16], const uint8_t i) {
    const uint8_t a = i;
    const uint8_t b = i + 1;
    const uint8_t c = i + 2;
    const uint8_t d = i + 3;

    const uint8_t x = (uint8_t)(state[a] ^ state[b] ^ state[c] ^ state[d]);
    const uint8_t y = state[a];

    state[a] = (uint8_t)(state[a] ^ x ^ xtime((uint8_t)(state[a] ^ state[b])));
    state[b] = (uint8_t)(state[b] ^ x ^ xtime((uint8_t)(state[b] ^ state[c])));
    state[c] = (uint8_t)(state[c] ^ x ^ xtime((uint8_t)(state[c] ^ state[d])));
    state[d] = (uint8_t)(state[d] ^ x ^ xtime((uint8_t)(state[d] ^ y)));
}


void inv_mix_single_column(uint8_t state[16], const uint8_t i) {
    const uint8_t a = i;
    const uint8_t b = i + 1;
    const uint8_t c = i + 2;
    const uint8_t d = i + 3;

    const uint8_t m = (uint8_t)(state[a] ^ state[c]);
    const uint8_t n = (uint8_t)(state[b] ^ state[d]);
    const uint8_t x = xtime(xtime(m));
    const uint8_t y = xtime(xtime(n));

    state[a] = (uint8_t)(state[a] ^ x);
    state[b] = (uint8_t)(state[b] ^ y);
    state[c] = (uint8_t)(state[c] ^ x);
    state[d] = (uint8_t)(state[d] ^ y);
}


void mix_columns(uint8_t state[16]) {
    mix_single_column(state, 0);
    mix_single_column(state, 4);
    mix_single_column(state, 8);
    mix_single_column(state, 12);
}


void inv_mix_columns(uint8_t state[16]) {
    inv_mix_single_column(state, 0);
    inv_mix_single_column(state, 4);
    inv_mix_single_column(state, 8);
    inv_mix_single_column(state, 12);
    mix_columns(state);
}


void ttable_aes_decrypt(
        uint8_t data[],
        const uint8_t round_keys[][16],
        const uint8_t key_count,
        const uint8_t block_count,
        const uint8_t block_index,
        const AES_YieldCallback callback
) {
    const uint8_t n_rounds = key_count - 1;
    uint8_t *state = data + (size_t)block_index * 16;
    const uint8_t (*keys)[16] = &round_keys[block_index * key_count];

    add_round_key(state, keys, n_rounds);
    inv_shift_rows(state);
    sub_bytes(state, aes_inv_sbox);

    for (uint8_t round = n_rounds - 1; round > 0; round--) {
        add_round_key(state, keys, round);
        inv_mix_columns(state);
        inv_shift_rows(state);
        sub_bytes(state, aes_inv_sbox);
        callback(
            data,
            round_keys,
            key_count,
            block_count,
            block_index + 1
        );
    }

    add_round_key(state, keys, 0);
}