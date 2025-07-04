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

#ifndef AES_UTILS_H
#define AES_UTILS_H

#ifdef __cplusplus
#include <cstdint>
#include <cstdbool>
extern "C" {
#else
#include <stdint.h>
#include <stdbool.h>
#endif


    void transpose_state_matrix(uint8_t state[16]);

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


#ifdef __cplusplus
}
#endif

#endif //AES_UTILS_H
