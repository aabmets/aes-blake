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
#include "clean_aes.h"
#include "aes_utils.h"


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
    uint32_t *ptr = (uint32_t*)state;
    const uint32_t buf0 = ptr[0];
    const uint32_t buf1 = ptr[1];
    const uint32_t buf2 = ptr[2];
    const uint32_t buf3 = ptr[3];

    ptr[0] = buf0 & 0x000000FF
           | buf1 & 0x0000FF00
           | buf2 & 0x00FF0000
           | buf3 & 0xFF000000;

    ptr[1] = buf1 & 0x000000FF
           | buf2 & 0x0000FF00
           | buf3 & 0x00FF0000
           | buf0 & 0xFF000000;

    ptr[2] = buf2 & 0x000000FF
           | buf3 & 0x0000FF00
           | buf0 & 0x00FF0000
           | buf1 & 0xFF000000;

    ptr[3] = buf3 & 0x000000FF
           | buf0 & 0x0000FF00
           | buf1 & 0x00FF0000
           | buf2 & 0xFF000000;
}


/*
 * Applies the AES InvShiftRows transformation in-place on a 16-byte state.
 */
void inv_shift_rows(uint8_t state[16]) {
    uint32_t *ptr = (uint32_t*)state;
    const uint32_t buf0 = ptr[0];
    const uint32_t buf1 = ptr[1];
    const uint32_t buf2 = ptr[2];
    const uint32_t buf3 = ptr[3];

    ptr[0] = buf0 & 0x000000FF
           | buf3 & 0x0000FF00
           | buf2 & 0x00FF0000
           | buf1 & 0xFF000000;

    ptr[1] = buf1 & 0x000000FF
           | buf0 & 0x0000FF00
           | buf3 & 0x00FF0000
           | buf2 & 0xFF000000;

    ptr[2] = buf2 & 0x000000FF
           | buf1 & 0x0000FF00
           | buf0 & 0x00FF0000
           | buf3 & 0xFF000000;

    ptr[3] = buf3 & 0x000000FF
           | buf2 & 0x0000FF00
           | buf1 & 0x00FF0000
           | buf0 & 0xFF000000;
}


/**
 * Applies the AES MixColumns transformation to one 4-byte column.
 */
void mix_single_column(uint8_t state[16], const uint8_t i) {
    const uint8_t a = state[i    ];
    const uint8_t b = state[i + 1];
    const uint8_t c = state[i + 2];
    const uint8_t d = state[i + 3];
    const uint8_t x = a ^ b ^ c ^ d;

    state[i    ] = a ^ x ^ xtime(a ^ b);
    state[i + 1] = b ^ x ^ xtime(b ^ c);
    state[i + 2] = c ^ x ^ xtime(c ^ d);
    state[i + 3] = d ^ x ^ xtime(d ^ a);
}


/**
 * Apply the AES InvMixColumns transformation to one 4-byte column.
 */
void inv_mix_single_column(uint8_t state[16], const uint8_t i) {
    const uint8_t a = state[i    ];
    const uint8_t b = state[i + 1];
    const uint8_t c = state[i + 2];
    const uint8_t d = state[i + 3];

    state[i    ] = a ^ xtime(xtime(a ^ c));
    state[i + 1] = b ^ xtime(xtime(b ^ d));
    state[i + 2] = c ^ xtime(xtime(a ^ c));
    state[i + 3] = d ^ xtime(xtime(b ^ d));
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
void clean_aes_encrypt(
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
void clean_aes_decrypt(
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
