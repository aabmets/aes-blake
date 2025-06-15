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
#include "aes_block.h"
#include "helpers.h"


void run_fips197_vectors(const AES_Func encrypt_fn, const AES_Func decrypt_fn) {
    struct TestVector {
        const char *plaintext_hex;
        const char *key_hex;
        const char *ciphertext_hex;
    };

    // Define test vectors from FIPS-197 Appendix A.1
    TestVector vectors[] = {
        {
            "3243f6a8885a308d313198a2e0370734", // plaintext
            "2b7e151628aed2a6abf7158809cf4f3c", // secret_key
            "3925841d02dc09fbdc118597196a0b32"  // expected ciphertext
        },
        {
            "00112233445566778899aabbccddeeff", // plaintext
            "000102030405060708090a0b0c0d0e0f", // secret_key
            "69c4e0d86a7b0430d8cdb78070b4c55a"  // expected ciphertext
        }
    };

    for (const auto & [plaintext_hex, key_hex, ciphertext_hex] : vectors) {
        uint8_t plaintext[16], key[16], expected_ct[16];
        hex_to_bytes(plaintext_hex, plaintext);
        hex_to_bytes(key_hex, key);
        hex_to_bytes(ciphertext_hex, expected_ct);

        constexpr uint8_t key_count = 11;
        constexpr uint8_t block_count = 1;
        constexpr uint8_t block_index = 0;

        // Generate round keys
        uint8_t round_keys[key_count][16];
        generate_original_aes128_round_keys(key, round_keys);

        // Encrypt in-place
        uint8_t state_enc[16];
        memcpy(state_enc, plaintext, 16);
        encrypt_fn(
            state_enc,
            round_keys,
            key_count,
            block_count,
            block_index,
            noop_callback
        );

        // Verify computed ciphertext
        for (int i = 0; i < 16; ++i) {
            REQUIRE(state_enc[i] == expected_ct[i]);
        }

        // Decrypt in-place
        uint8_t state_dec[16];
        memcpy(state_dec, state_enc, 16);
        decrypt_fn(
            state_dec,
            round_keys,
            key_count,
            block_count,
            block_index,
            noop_callback
        );

        // Verify recovered plaintext
        for (int i = 0; i < 16; ++i) {
            REQUIRE(state_dec[i] == plaintext[i]);
        }
    }
}
