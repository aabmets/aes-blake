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


#ifndef AES_BLOCK_HELPERS_H
#define AES_BLOCK_HELPERS_H

#include <catch2/catch_all.hpp>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <cerrno>
#include "aes_block.h"


    inline void noop_callback(
        uint8_t state[],
        const uint8_t round_keys[][16],
        uint8_t key_count,
        uint8_t block_count,
        uint8_t block_index
    ) { /* no operation */ }

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

    uint8_t xtime(uint8_t x);

    uint8_t gf_mul(uint8_t x, uint8_t y);

    uint8_t gf_inv(uint8_t x);

    uint8_t compute_sbox(uint8_t x);

    void compute_enc_table_words(
        uint8_t x,
        uint32_t *t0,
        uint32_t *t1,
        uint32_t *t2,
        uint32_t *t3,
        bool little_endian
    );

    void generate_enc_tables(
        uint32_t Te0[256],
        uint32_t Te1[256],
        uint32_t Te2[256],
        uint32_t Te3[256],
        bool little_endian
    );

    void compute_imc_table_words(
        uint8_t x,
        uint32_t *t0,
        uint32_t *t1,
        uint32_t *t2,
        uint32_t *t3,
        bool little_endian
    );

    void generate_imc_tables(
        uint32_t IMC0[256],
        uint32_t IMC1[256],
        uint32_t IMC2[256],
        uint32_t IMC3[256],
        bool little_endian
    );

    void generate_original_aes128_round_keys(
        const uint8_t key[16],
        uint8_t round_keys[11][16]
    );

    void run_fips197_vectors(
        AES_Func encrypt_fn,
        AES_Func decrypt_fn
    );

    void run_two_block_random_vectors(
        AES_Func encrypt_fn,
        AES_Func decrypt_fn
    );


#endif // AES_BLOCK_HELPERS_H