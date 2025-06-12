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


/*
 * Applies the SubBytes transformation to the 16-byte AES state in-place.
 */
void sub_bytes(uint8_t state[16]) {
    state[0]  = aes_sbox[state[0]];
    state[1]  = aes_sbox[state[1]];
    state[2]  = aes_sbox[state[2]];
    state[3]  = aes_sbox[state[3]];
    state[4]  = aes_sbox[state[4]];
    state[5]  = aes_sbox[state[5]];
    state[6]  = aes_sbox[state[6]];
    state[7]  = aes_sbox[state[7]];
    state[8]  = aes_sbox[state[8]];
    state[9]  = aes_sbox[state[9]];
    state[10] = aes_sbox[state[10]];
    state[11] = aes_sbox[state[11]];
    state[12] = aes_sbox[state[12]];
    state[13] = aes_sbox[state[13]];
    state[14] = aes_sbox[state[14]];
    state[15] = aes_sbox[state[15]];
}


/*
 * Applies the InvSubBytes transformation to the 16-byte AES state in-place.
 */
void inv_sub_bytes(uint8_t state[16]) {
    state[0]  = aes_inv_sbox[state[0]];
    state[1]  = aes_inv_sbox[state[1]];
    state[2]  = aes_inv_sbox[state[2]];
    state[3]  = aes_inv_sbox[state[3]];
    state[4]  = aes_inv_sbox[state[4]];
    state[5]  = aes_inv_sbox[state[5]];
    state[6]  = aes_inv_sbox[state[6]];
    state[7]  = aes_inv_sbox[state[7]];
    state[8]  = aes_inv_sbox[state[8]];
    state[9]  = aes_inv_sbox[state[9]];
    state[10] = aes_inv_sbox[state[10]];
    state[11] = aes_inv_sbox[state[11]];
    state[12] = aes_inv_sbox[state[12]];
    state[13] = aes_inv_sbox[state[13]];
    state[14] = aes_inv_sbox[state[14]];
    state[15] = aes_inv_sbox[state[15]];
}


/*
 * Single AddRoundKey function that uses preprocessor directives
 * to choose between a 32-bit variant (default) and a 64-bit variant.
 *
 * To compile with 64-bit XORs, define AES_USE_64BIT_WORDS (e.g., via -DAES_USE_64BIT_WORDS).
 * Otherwise, the 32-bit version is used by default.
 */
void add_round_key(uint8_t state[16], const uint8_t round_keys[][16], const uint8_t round) {
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
