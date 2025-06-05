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
#include "aes_sbox.h"
#include "aes.h"


/*
 * Applies the SubBytes transformation to the 16-byte AES state in-place.
 */
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


/*
 * Single AddRoundKey function that uses preprocessor directives
 * to choose between a 32-bit variant (default) and a 64-bit variant.
 *
 * To compile with 64-bit XORs, define AES_USE_64BIT_WORDS (e.g., via -DAES_USE_64BIT_WORDS).
 * Otherwise, the 32-bit version is used by default.
 */
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
 * Applies the AES ShiftRows transformation in-place on a 16-byte state.
 */
void shift_rows(uint8_t state[16]) {
    // Row 1 (indices 1,5,9,13): rotate left by 1
    uint8_t tmp = state[1];
    state[1]    = state[5];
    state[5]    = state[9];
    state[9]    = state[13];
    state[13]   = tmp;

    // Row 2 (indices 2,6,10,14): rotate left by 2
    tmp       = state[2];
    state[2]  = state[10];
    state[10] = tmp;
    tmp       = state[6];
    state[6]  = state[14];
    state[14] = tmp;

    // Row 3 (indices 3,7,11,15): rotate left by 3 (equiv. rotate right by 1)
    tmp       = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7]  = state[3];
    state[3]  = tmp;
}


/*
 * Applies the AES InvShiftRows transformation in-place on a 16-byte state.
 */
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


/*
 * Multiplies a byte by {02} in GF(2^8)
 */
uint8_t xtime(const uint8_t a) {
    const uint8_t x = (uint8_t)(a << 1);
    const uint8_t y = (uint8_t)(a >> 7);
    return x ^ (uint8_t)(y * 0x1B);
}


/**
 * Applies the AES MixColumns transformation to one 4-byte column.
 */
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


/**
 * Apply the AES InvMixColumns transformation to one 4-byte column.
 */
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


/**
 * Applies the AES MixColumns transformation to the entire state.
 */
void mix_columns(uint8_t state[16]) {
    mix_single_column(state, 0);
    mix_single_column(state, 4);
    mix_single_column(state, 8);
    mix_single_column(state, 12);
}


/**
 * Applies the AES InvMixColumns transformation to the entire state.
 */
void inv_mix_columns(uint8_t state[16]) {
    inv_mix_single_column(state, 0);
    inv_mix_single_column(state, 4);
    inv_mix_single_column(state, 8);
    inv_mix_single_column(state, 12);
    mix_columns(state);
}


/**
 * Encrypts a single 16‐byte block in place, chosen by block_index.
 */
void aes_encrypt(uint8_t data[],
                 const uint8_t round_keys[][16],
                 const uint8_t key_count,
                 const uint8_t block_count,
                 const uint8_t block_index,
                 const AES_YieldCallback callback) {
    const uint8_t n_rounds = key_count - 1;
    uint8_t *state = data + (size_t)block_index * 16;
    const uint8_t (*keys)[16] = &round_keys[block_index * key_count];

    add_round_key(state, keys, 0);
    for (uint8_t round = 1; round < n_rounds; round++) {
        callback(
            data,
            round_keys,
            key_count,
            block_count,
            block_index + 1
        );
        sub_bytes(state, aes_sbox);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, keys, round);
    }
    sub_bytes(state, aes_sbox);
    shift_rows(state);
    add_round_key(state, keys, n_rounds);
}


/**
 * Decrypts a single 16‐byte block in place, chosen by block_index.
 */
void aes_decrypt(uint8_t data[],
                 const uint8_t round_keys[][16],
                 const uint8_t key_count,
                 const uint8_t block_count,
                 const uint8_t block_index,
                 const AES_YieldCallback callback) {
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
