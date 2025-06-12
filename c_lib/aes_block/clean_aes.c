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
#include "clean_aes.h"
#include "aes_utils.h"
#include "aes_shared.h"


/**
 * Applies the AES MixColumns transformation to one 4-byte column.
 */
static void mix_single_column(uint8_t state[16], const uint8_t i) {
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
static void inv_mix_single_column(uint8_t state[16], const uint8_t i) {
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
static void mix_columns(uint8_t state[16]) {
    mix_single_column(state, 0);
    mix_single_column(state, 4);
    mix_single_column(state, 8);
    mix_single_column(state, 12);
}


/**
 * Applies the AES InvMixColumns transformation to the entire state.
 */
static void inv_mix_columns(uint8_t state[16]) {
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
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, keys, round);
    }
    sub_bytes(state);
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
    inv_sub_bytes(state);
    for (uint8_t round = n_rounds - 1; round > 0; round--) {
        add_round_key(state, keys, round);
        inv_mix_columns(state);
        inv_shift_rows(state);
        inv_sub_bytes(state);
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
