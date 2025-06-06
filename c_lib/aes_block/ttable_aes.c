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

#include <stdbool.h>
#include <stdint.h>
#include "ttable_aes.h"
#include "aes_sbox.h"


static uint32_t Te0[256];
static uint32_t Te1[256];
static uint32_t Te2[256];
static uint32_t Te3[256];
static uint32_t Te4[256];

static bool tables_generated = false;


static void generate_tables(void) {
    for (int i = 0; i < 256; i++) {
        uint8_t s = aes_sbox[i];
        uint8_t s2 = (uint8_t)(s << 1) ^ (uint8_t)((s >> 7) * 0x1B);
        uint8_t s3 = (uint8_t)(s2 ^ s);

        Te0[i] = (uint32_t)s3 << 24
               | (uint32_t)s  << 16
               | (uint32_t)s  << 8
               | (uint32_t)s2;

        Te1[i] = (uint32_t)s  << 24
               | (uint32_t)s  << 16
               | (uint32_t)s2 << 8
               | (uint32_t)s3;

        Te2[i] = (uint32_t)s  << 24
               | (uint32_t)s2 << 16
               | (uint32_t)s3 << 8
               | (uint32_t)s;

        Te3[i] = (uint32_t)s2 << 24
               | (uint32_t)s3 << 16
               | (uint32_t)s  <<  8
               | (uint32_t)s;

        Te4[i] = (uint32_t)s;
    }
    tables_generated = true;
}


void ttable_aes_encrypt(
    uint8_t data[],
    const uint8_t round_keys[][16],
    const uint8_t key_count,
    const uint8_t block_count,
    const uint8_t block_index,
    const AES_YieldCallback callback
) {
    if (!tables_generated) {
        generate_tables();
    }
    uint32_t *state = (uint32_t *)(data + block_index * 16);
    const uint8_t (*keys)[16] = &round_keys[block_index * key_count];
    const uint8_t n_rounds = key_count - 1;

    const uint32_t *rkey = (uint32_t *)keys[0];
    state[0] ^= rkey[0];
    state[1] ^= rkey[1];
    state[2] ^= rkey[2];
    state[3] ^= rkey[3];

    for (uint8_t round = 1; round < n_rounds; round++) {
        callback(
            data,
            round_keys,
            key_count,
            block_count,
            block_index + 1
        );
        rkey = (uint32_t *)keys[round];

        uint32_t t0 = Te0[(uint8_t)state[0]]
                    ^ Te1[(uint8_t)(state[1] >> 8)]
                    ^ Te2[(uint8_t)(state[2] >> 16)]
                    ^ Te3[(uint8_t)(state[3] >> 24)]
                    ^ rkey[0];

        uint32_t t1 = Te0[(uint8_t)state[1]]
                    ^ Te1[(uint8_t)(state[2] >> 8)]
                    ^ Te2[(uint8_t)(state[3] >> 16)]
                    ^ Te3[(uint8_t)(state[0] >> 24)]
                    ^ rkey[1];

        uint32_t t2 = Te0[(uint8_t)state[2]]
                    ^ Te1[(uint8_t)(state[3] >> 8)]
                    ^ Te2[(uint8_t)(state[0] >> 16)]
                    ^ Te3[(uint8_t)(state[1] >> 24)]
                    ^ rkey[2];

        uint32_t t3 = Te0[(uint8_t)state[3]]
                    ^ Te1[(uint8_t)(state[0] >> 8)]
                    ^ Te2[(uint8_t)(state[1] >> 16)]
                    ^ Te3[(uint8_t)(state[2] >> 24)]
                    ^ rkey[3];

        state[0] = t0;
        state[1] = t1;
        state[2] = t2;
        state[3] = t3;
    }

    /* Final round (round = n_rounds): SubBytes + ShiftRows + AddRoundKey (no MixColumns) */
    rkey = (uint32_t *)keys[n_rounds];

    uint32_t out0 = Te4[(uint8_t)state[0]]
                  | Te4[(uint8_t)(state[1] >> 8)] << 8
                  | Te4[(uint8_t)(state[2] >> 16)] << 16
                  | Te4[(uint8_t)(state[3] >> 24)] << 24;

    uint32_t out1 = Te4[(uint8_t)state[1]]
                  | Te4[(uint8_t)(state[2] >> 8)] << 8
                  | Te4[(uint8_t)(state[3] >> 16)] << 16
                  | Te4[(uint8_t)(state[0] >> 24)] << 24;

    uint32_t out2 = Te4[(uint8_t)state[2]]
                  | Te4[(uint8_t)(state[3] >> 8)] << 8
                  | Te4[(uint8_t)(state[0] >> 16)] << 16
                  | Te4[(uint8_t)(state[1] >> 24)] << 24;

    uint32_t out3 = Te4[(uint8_t)state[3]]
                  | Te4[(uint8_t)(state[0] >> 8)] << 8
                  | Te4[(uint8_t)(state[1] >> 16)] << 16
                  | Te4[(uint8_t)(state[2] >> 24)] << 24;

    state[0] = out0 ^ rkey[0];
    state[1] = out1 ^ rkey[1];
    state[2] = out2 ^ rkey[2];
    state[3] = out3 ^ rkey[3];
}


void ttable_aes_decrypt(
    uint8_t data[],
    const uint8_t round_keys[][16],
    uint8_t key_count,
    uint8_t block_count,
    uint8_t block_index,
    AES_YieldCallback callback
)
{
    // Not implemented
}