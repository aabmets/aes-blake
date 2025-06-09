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
#include "ttable_aes.h"
#include "aes_sbox.h"
#include "aes_tables.h"


void ttable_aes_encrypt(
        uint8_t data[],
        const uint8_t round_keys[][16],
        const uint8_t key_count,
        const uint8_t block_count,
        const uint8_t block_index,
        const AES_YieldCallback callback
) {
    uint32_t *state = (uint32_t *)(data + block_index * 16);
    const uint8_t *b = data + block_index * 16;

    const uint8_t (*keys)[16] = &round_keys[block_index * key_count];
    const uint8_t n_rounds = key_count - 1;

    // First round
    {
        const uint32_t *rkey = (uint32_t *)keys[0];

        state[0] ^= rkey[0];
        state[1] ^= rkey[1];
        state[2] ^= rkey[2];
        state[3] ^= rkey[3];
    }

    // Middle rounds
    for (uint8_t round = 1; round < n_rounds; round++) {
        callback(
            data,
            round_keys,
            key_count,
            block_count,
            block_index + 1
        );
        const uint32_t *rkey = (uint32_t *)keys[round];

        const uint32_t t0 = Te0[b[0]] ^ Te1[b[5]] ^ Te2[b[10]] ^ Te3[b[15]];
        const uint32_t t1 = Te0[b[4]] ^ Te1[b[9]] ^ Te2[b[14]] ^ Te3[b[3]];
        const uint32_t t2 = Te0[b[8]] ^ Te1[b[13]] ^ Te2[b[2]] ^ Te3[b[7]];
        const uint32_t t3 = Te0[b[12]] ^ Te1[b[1]] ^ Te2[b[6]] ^ Te3[b[11]];

        state[0] = t0 ^ rkey[0];
        state[1] = t1 ^ rkey[1];
        state[2] = t2 ^ rkey[2];
        state[3] = t3 ^ rkey[3];
    }

    // Final round
    {
        const uint32_t* rkey = (uint32_t*)keys[n_rounds];

        const uint32_t t0 = aes_sbox[b[0]]
                          | aes_sbox[b[5]] << 8
                          | aes_sbox[b[10]] << 16
                          | aes_sbox[b[15]] << 24;

        const uint32_t t1 = aes_sbox[b[4]]
                          | aes_sbox[b[9]] << 8
                          | aes_sbox[b[14]] << 16
                          | aes_sbox[b[3]] << 24;

        const uint32_t t2 = aes_sbox[b[8]]
                          | aes_sbox[b[13]] << 8
                          | aes_sbox[b[2]] << 16
                          | aes_sbox[b[7]] << 24;

        const uint32_t t3 = aes_sbox[b[12]]
                          | aes_sbox[b[1]] << 8
                          | aes_sbox[b[6]] << 16
                          | aes_sbox[b[11]] << 24;

        state[0] = t0 ^ rkey[0];
        state[1] = t1 ^ rkey[1];
        state[2] = t2 ^ rkey[2];
        state[3] = t3 ^ rkey[3];
    }
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
    const uint8_t *b = data + block_index * 16;

    const uint8_t (*keys)[16] = &round_keys[block_index * key_count];
    const uint8_t n_rounds = key_count - 1;

    // First round
    {
        const uint32_t *rkey = (uint32_t *)keys[n_rounds];

        state[0] ^= rkey[0];
        state[1] ^= rkey[1];
        state[2] ^= rkey[2];
        state[3] ^= rkey[3];

        const uint32_t t0 = aes_inv_sbox[b[0]]
                          | aes_inv_sbox[b[13]] << 8
                          | aes_inv_sbox[b[10]] << 16
                          | aes_inv_sbox[b[7]] << 24;

        const uint32_t t1 = aes_inv_sbox[b[4]]
                          | aes_inv_sbox[b[1]] << 8
                          | aes_inv_sbox[b[14]] << 16
                          | aes_inv_sbox[b[11]] << 24;

        const uint32_t t2 = aes_inv_sbox[b[8]]
                          | aes_inv_sbox[b[5]] << 8
                          | aes_inv_sbox[b[2]] << 16
                          | aes_inv_sbox[b[15]] << 24;

        const uint32_t t3 = aes_inv_sbox[b[12]]
                          | aes_inv_sbox[b[9]] << 8
                          | aes_inv_sbox[b[6]] << 16
                          | aes_inv_sbox[b[3]] << 24;

        state[0] = t0;
        state[1] = t1;
        state[2] = t2;
        state[3] = t3;
    }

    // Middle round
    uint8_t *state8 = data + block_index * 16;
    for (uint8_t round = n_rounds - 1; round > 0; round--) {
        const uint32_t *rkey = (uint32_t *)keys[round];

        state[0] ^= rkey[0];
        state[1] ^= rkey[1];
        state[2] ^= rkey[2];
        state[3] ^= rkey[3];

        // add_round_key(state8, keys, round);
        // uint32_t t0 = Td0[b[0]]  ^ Td1[b[13]] ^ Td2[b[10]] ^ Td3[b[7]];
        // uint32_t t1 = Td0[b[4]]  ^ Td1[b[1]]  ^ Td2[b[14]] ^ Td3[b[11]];
        // uint32_t t2 = Td0[b[8]]  ^ Td1[b[5]]  ^ Td2[b[2]]  ^ Td3[b[15]];
        // uint32_t t3 = Td0[b[12]] ^ Td1[b[9]]  ^ Td2[b[6]]  ^ Td3[b[3]];

        // print_words_matrix(state[0], state[1], state[2], state[3]);

        // state[0] = t0;
        // state[1] = t1;
        // state[2] = t2;
        // state[3] = t3;

        // inv_mix_columns(state8);
        // sub_bytes(state8, aes_inv_sbox);

        // print_state_matrix(state8);
        // return;

        // inv_shift_rows(state8);

        callback(
            data,
            round_keys,
            key_count,
            block_count,
            block_index + 1
        );
    }

    // Final round
    {
        const uint32_t *rkey = (uint32_t *)keys[0];

        state[0] ^= rkey[0];
        state[1] ^= rkey[1];
        state[2] ^= rkey[2];
        state[3] ^= rkey[3];
    }
}