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
#include "aes.h"
#include "cp_csprng.h"
#include "../helpers.hpp"


TEST_CASE("AES-128 FIPS-197 example vectors", "[aes][fips197]") {
    struct TestVector {
        const char *plaintext_hex;
        const char *key_hex;
        const char *ciphertext_hex;
    };

    // From FIPS-197 Appendix A.1
    TestVector vectors[] = {
        {
            "3243f6a8885a308d313198a2e0370734", // plaintext
            "2b7e151628aed2a6abf7158809cf4f3c", // secret_key
            "3925841d02dc09fbdc118597196a0b32"  // expected ciphertext
        },
        {
            "00112233445566778899aabbccddeeff",
            "000102030405060708090a0b0c0d0e0f",
            "69c4e0d86a7b0430d8cdb78070b4c55a"
        }
    };

    for (const auto & [plaintext_hex, key_hex, ciphertext_hex] : vectors) {
        uint8_t plaintext[16], key[16], expected_ct[16];
        hex_to_bytes(plaintext_hex, plaintext);
        hex_to_bytes(key_hex, key);
        hex_to_bytes(ciphertext_hex, expected_ct);

        // Generate 11 round keys (AES-128 uses Nr=10, so key_count = 11)
        uint8_t round_keys[11][16];
        generate_original_aes128_round_keys(key, round_keys);

        // Encrypt
        uint8_t state_enc[16];
        memcpy(state_enc, plaintext, 16);
        aes_encrypt(
            state_enc,
            round_keys,
            11,  // key_count
            1,   // block_count
            0,   // block_index
            noop_callback
        );

        // Check against expected ciphertext
        for (int i = 0; i < 16; ++i) {
            REQUIRE(state_enc[i] == expected_ct[i]);
        }

        // Decrypt back
        uint8_t state_dec[16];
        memcpy(state_dec, state_enc, 16);
        aes_decrypt(
            state_dec,
            round_keys,
            11,  // key_count
            1,   // block_count
            0,   // block_index
            noop_callback
        );

        // Check that decryption returns original plaintext
        for (int i = 0; i < 16; ++i) {
            REQUIRE(state_dec[i] == plaintext[i]);
        }
    }
}


TEST_CASE("AES-128: two-block random plaintext with two independent CSPRNG keys", "[aes][two_block][csprng]") {
    csprng_open();

    // Generate a 32-byte random plaintext via 32 calls to csprng_read():
    uint8_t plaintext[32];
    for (unsigned char & i : plaintext) {
        i = csprng_read();
    }

    // Copy plaintext → data[] so we can encrypt in-place:
    uint8_t data[32];
    memcpy(data, plaintext, 32);

    // Generate two independent 16-byte AES-128 keys from csprng_read():
    uint8_t secret_key0[16], secret_key1[16];
    for (int i = 0; i < 16; ++i) {
                    secret_key0[i] = csprng_read();
        secret_key1[i] = csprng_read();
    }

    // Build two separate [11][16] schedules via generate_original_aes128_round_keys():
    // AES-128 has Nk=4, Nr=10 → key_count = Nr+1 = 11.
    uint8_t round_keys0[11][16];
    uint8_t round_keys1[11][16];
    generate_original_aes128_round_keys(secret_key0, round_keys0);
    generate_original_aes128_round_keys(secret_key1, round_keys1);

    // Concatenate them into one flat [22][16] array:
    constexpr int KEY_COUNT   = 11;
    constexpr int BLOCK_COUNT = 2;
    uint8_t round_keys[BLOCK_COUNT * KEY_COUNT][16];
    //   indices 0..10 ← round_keys0[0..10] for block 0
    //   indices 11..21 ← round_keys1[0..10] for block 1
    for (int r = 0; r < KEY_COUNT; ++r) {
        memcpy(round_keys[r],                  round_keys0[r], 16);
        memcpy(round_keys[r + KEY_COUNT],      round_keys1[r], 16);
    }

    // Encrypt both blocks “in place”:
    for (uint8_t block_idx = 0; block_idx < BLOCK_COUNT; ++block_idx) {
        aes_encrypt(
            data,
            round_keys,
            KEY_COUNT,
            BLOCK_COUNT,
            block_idx,
            noop_callback
        );
    }
    // Now data[0..15] is ciphertext for block 0 (with secret_key0),
    // and data[16..31] is ciphertext for block 1 (with secret_key1).

    // Decrypt both blocks “in place” similarly:
    for (uint8_t block_idx = 0; block_idx < BLOCK_COUNT; ++block_idx) {
        aes_decrypt(
            data,
            round_keys,
            KEY_COUNT,
            BLOCK_COUNT,
            block_idx,
            noop_callback
        );
    }
    // After decryption, data[0..31] should match plaintext[0..31].

    // Verify that decryption recovered the original plaintext:
    for (int i = 0; i < 32; ++i) {
        REQUIRE(data[i] == plaintext[i]);
    }

    csprng_close();
}