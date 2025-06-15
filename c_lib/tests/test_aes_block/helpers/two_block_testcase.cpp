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

#include <catch2/catch_all.hpp>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <cerrno>
#include "csprng.h"
#include "aes_types.h"
#include "helpers.h"


void run_two_block_random_vectors(const AES_Func encrypt_fn, const AES_Func decrypt_fn) {
    // Generate a random plaintext
    uint8_t plaintext[32];
    csprng_read_array(plaintext, sizeof(plaintext));

    uint8_t data[32];
    memcpy(data, plaintext, 32);

    // Generate two random secret keys
    uint8_t secret_key0[16], secret_key1[16];
    for (int i = 0; i < 16; ++i) {
        secret_key0[i] = csprng_read();
        secret_key1[i] = csprng_read();
    }

    constexpr uint8_t key_count = 11;
    constexpr uint8_t block_count = 2;

    // Generate round keys for both AES blocks
    uint8_t round_keys0[key_count][16];
    uint8_t round_keys1[key_count][16];
    generate_original_aes128_round_keys(secret_key0, round_keys0);
    generate_original_aes128_round_keys(secret_key1, round_keys1);

    // Concatenate round keys into a flat array
    uint8_t round_keys[block_count * key_count][16];
    for (int r = 0; r < key_count; ++r) {
        memcpy(round_keys[r], round_keys0[r], 16);
        memcpy(round_keys[r + key_count], round_keys1[r], 16);
    }

    // Encrypt both blocks in-place
    for (uint8_t block_index = 0; block_index < block_count; ++block_index) {
        encrypt_fn(
            data,
            round_keys,
            key_count,
            block_count,
            block_index,
            noop_callback
        );
    }

    // Decrypt both blocks in-place
    for (uint8_t block_index = 0; block_index < block_count; ++block_index) {
        decrypt_fn(
            data,
            round_keys,
            key_count,
            block_count,
            block_index,
            noop_callback
        );
    }

    // Verify recovered plaintext
    for (int i = 0; i < 32; ++i) {
        REQUIRE(data[i] == plaintext[i]);
    }
}