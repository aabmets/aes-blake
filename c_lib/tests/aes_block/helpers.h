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


#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H

#include <cstring>
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <cerrno>
#include "aes_sbox.h"
#include "cp_csprng.h"


inline void noop_callback(
    uint8_t state[],
    const uint8_t round_keys[][16],
    uint8_t key_count,
    uint8_t block_count,
    uint8_t block_index
) {
    // no operation
}


inline void hex_to_bytes(const char *hex, uint8_t out[16]) {
    for (int i = 0; i < 16; ++i) {
        const char buf[3] = { hex[2*i], hex[2*i + 1], 0 };
        char *endPtr = nullptr;
        errno = 0;

        if (const unsigned long byte = strtoul(buf, &endPtr, 16);
                errno != 0 || endPtr != buf + 2 || byte > UINT8_MAX) {
            throw std::runtime_error("Invalid hex input in hex_to_bytes");
        } else {
            out[i] = static_cast<uint8_t>(byte);
        }
    }

}


inline void generate_original_aes128_round_keys(
    const uint8_t key[16], uint8_t round_keys[11][16]
) {
    // Number of 32-bit words comprising the key (Nk), block (Nb), and total rounds (Nr)
    constexpr int Nk = 4;
    constexpr int Nb = 4;
    constexpr int Nr = 10;

    // Rcon values for AES-128 (first byte of the round constant word)
    // Rcon[i] = 2^(i-1) in GF(2^8).  We need Rcon[1..10].
    static const uint8_t Rcon[10] = {
        0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1B, 0x36
    };

    // W will hold 44 4-byte words: W[0..43][0..3].
    // Words 0..3 come directly from the original key.  Words 4..43 are expanded.
    uint8_t W[ Nb * (Nr + 1) ][4];

    // Copy the original key bytes into W[0..3]
    for (int i = 0; i < Nk; ++i) {
        W[i][0] = key[4*i + 0];
        W[i][1] = key[4*i + 1];
        W[i][2] = key[4*i + 2];
        W[i][3] = key[4*i + 3];
    }

    // Key expansion: generate W[4..43]
    for (int i = Nk; i < Nb * (Nr + 1); ++i) {
        uint8_t temp[4];
        // Copy previous word into temp
        memcpy(temp, W[i - 1], 4);

        if (i % Nk == 0) {
            // RotWord: rotate left by one byte
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            // SubWord: apply S-box to each byte
            temp[0] = aes_sbox[temp[0]];
            temp[1] = aes_sbox[temp[1]];
            temp[2] = aes_sbox[temp[2]];
            temp[3] = aes_sbox[temp[3]];
            // XOR Rcon: only the first byte is XORed with Rcon[i/Nk - 1]
            temp[0] ^= Rcon[i / Nk - 1];
        }
        // W[i] = W[i - Nk] XOR temp
        W[i][0] = W[i - Nk][0] ^ temp[0];
        W[i][1] = W[i - Nk][1] ^ temp[1];
        W[i][2] = W[i - Nk][2] ^ temp[2];
        W[i][3] = W[i - Nk][3] ^ temp[3];
    }

    // Now pack W into round_keys: each round r uses words W[4r..4r+3]
    for (int r = 0; r <= Nr; ++r) {
        // Each round key is 16 bytes: 4 words × 4 bytes
        for (int word_index = 0; word_index < Nb; ++word_index) {
            const int idx = 4*r + word_index;
            round_keys[r][4*word_index + 0] = W[idx][0];
            round_keys[r][4*word_index + 1] = W[idx][1];
            round_keys[r][4*word_index + 2] = W[idx][2];
            round_keys[r][4*word_index + 3] = W[idx][3];
        }
    }
}


using AesFunc = void (*)(
    uint8_t data[],
    const uint8_t round_keys[][16],
    uint8_t key_count,
    uint8_t block_count,
    uint8_t block_index,
    AES_YieldCallback callback
);


inline void run_fips197_vectors(const AesFunc encrypt_fn, const AesFunc decrypt_fn) {
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


inline void run_two_block_random_vectors(const AesFunc encrypt_fn, const AesFunc decrypt_fn) {
    csprng_open();

    // Generate a random plaintext
    uint8_t plaintext[32];
    for (unsigned char & i : plaintext) {
        i = csprng_read();
    }
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

    csprng_close();
}

#endif // TEST_HELPERS_H
