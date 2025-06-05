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
#include "aes_sbox.h"


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
    // Assumes `hex` is exactly 32 hex characters (16 bytes).
    for (int i = 0; i < 16; ++i) {
        unsigned int byte;
        // Read exactly two hex digits → one byte
        sscanf(hex + 2*i, "%2x", &byte);
        out[i] = static_cast<uint8_t>(byte);
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


#endif // TEST_HELPERS_H
