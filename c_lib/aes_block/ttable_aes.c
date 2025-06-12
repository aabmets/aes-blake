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
#include "aes_tables.h"
#include "aes_shared.h"
#include "aes_types.h"


static void shift_rows_sub_bytes(uint32_t state[4], const uint8_t b[16]) {
    const uint32_t t0 = aes_sbox[b[ 0]]
                      | aes_sbox[b[ 5]] <<  8
                      | aes_sbox[b[10]] << 16
                      | aes_sbox[b[15]] << 24;

    const uint32_t t1 = aes_sbox[b[ 4]]
                      | aes_sbox[b[ 9]] <<  8
                      | aes_sbox[b[14]] << 16
                      | aes_sbox[b[ 3]] << 24;

    const uint32_t t2 = aes_sbox[b[ 8]]
                      | aes_sbox[b[13]] <<  8
                      | aes_sbox[b[ 2]] << 16
                      | aes_sbox[b[ 7]] << 24;

    const uint32_t t3 = aes_sbox[b[12]]
                      | aes_sbox[b[ 1]] <<  8
                      | aes_sbox[b[ 6]] << 16
                      | aes_sbox[b[11]] << 24;

    state[0] = t0;
    state[1] = t1;
    state[2] = t2;
    state[3] = t3;
}


static void inv_shift_rows_inv_sub_bytes(uint32_t state[4], const uint8_t b[16]) {
    const uint32_t t0 = aes_inv_sbox[b[ 0]]
                      | aes_inv_sbox[b[13]] <<  8
                      | aes_inv_sbox[b[10]] << 16
                      | aes_inv_sbox[b[ 7]] << 24;

    const uint32_t t1 = aes_inv_sbox[b[ 4]]
                      | aes_inv_sbox[b[ 1]] <<  8
                      | aes_inv_sbox[b[14]] << 16
                      | aes_inv_sbox[b[11]] << 24;

    const uint32_t t2 = aes_inv_sbox[b[ 8]]
                      | aes_inv_sbox[b[ 5]] <<  8
                      | aes_inv_sbox[b[ 2]] << 16
                      | aes_inv_sbox[b[15]] << 24;

    const uint32_t t3 = aes_inv_sbox[b[12]]
                      | aes_inv_sbox[b[ 9]] <<  8
                      | aes_inv_sbox[b[ 6]] << 16
                      | aes_inv_sbox[b[ 3]] << 24;

    state[0] = t0;
    state[1] = t1;
    state[2] = t2;
    state[3] = t3;
}


void ttable_aes_encrypt(
        uint8_t data[],
        const uint8_t round_keys[][16],
        const uint8_t key_count,
        const uint8_t block_count,
        const uint8_t block_index,
        const AES_YieldCallback callback
) {
    uint32_t *state = (uint32_t *)(data + block_index * 16);
    uint8_t *b = data + block_index * 16;

    const uint8_t (*keys)[16] = &round_keys[block_index * key_count];
    const uint8_t n_rounds = key_count - 1;

    // First round
    add_round_key(b, keys, 0);

    // Middle rounds
    for (uint8_t round = 1; round < n_rounds; round++) {
        callback(
            data,
            round_keys,
            key_count,
            block_count,
            block_index + 1
        );

        // SubBytes -> ShiftRows -> MixColumns
        const uint32_t t0 = Te0[b[0]] ^ Te1[b[5]] ^ Te2[b[10]] ^ Te3[b[15]];
        const uint32_t t1 = Te0[b[4]] ^ Te1[b[9]] ^ Te2[b[14]] ^ Te3[b[3]];
        const uint32_t t2 = Te0[b[8]] ^ Te1[b[13]] ^ Te2[b[2]] ^ Te3[b[7]];
        const uint32_t t3 = Te0[b[12]] ^ Te1[b[1]] ^ Te2[b[6]] ^ Te3[b[11]];
        state[0] = t0;
        state[1] = t1;
        state[2] = t2;
        state[3] = t3;

        add_round_key(b, keys, round);
    }

    // Final round
    shift_rows_sub_bytes(state, b);
    add_round_key(b, keys, n_rounds);
}


void ttable_aes_decrypt(
        uint8_t data[],
        const uint8_t round_keys[][16],
        const uint8_t key_count,
        const uint8_t block_count,
        const uint8_t block_index,
        const AES_YieldCallback callback
) {
    uint32_t *state = (uint32_t *)(data + block_index * 16);
    uint8_t *b = data + block_index * 16;

    const uint8_t (*keys)[16] = &round_keys[block_index * key_count];
    const uint8_t n_rounds = key_count - 1;

    // First round
    add_round_key(b, keys, n_rounds);
    inv_shift_rows_inv_sub_bytes(state, b);

    // Middle rounds
    for (uint8_t round = n_rounds - 1; round > 0; round--) {
        add_round_key(b, keys, round);

        // InvMixColumns
        const uint32_t t0 = IMC0[b[0]] ^ IMC1[b[1]] ^ IMC2[b[2]] ^ IMC3[b[3]];
        const uint32_t t1 = IMC0[b[4]] ^ IMC1[b[5]] ^ IMC2[b[6]] ^ IMC3[b[7]];
        const uint32_t t2 = IMC0[b[8]] ^ IMC1[b[9]] ^ IMC2[b[10]] ^ IMC3[b[11]];
        const uint32_t t3 = IMC0[b[12]] ^ IMC1[b[13]] ^ IMC2[b[14]] ^ IMC3[b[15]];
        state[0] = t0;
        state[1] = t1;
        state[2] = t2;
        state[3] = t3;

        inv_shift_rows_inv_sub_bytes(state, b);

        callback(
            data,
            round_keys,
            key_count,
            block_count,
            block_index + 1
        );
    }

    // Final round
    add_round_key(b, keys, 0);
}