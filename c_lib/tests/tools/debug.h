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

#ifndef TEST_DEBUG_H
#define TEST_DEBUG_H

#include <cstdint>


    void print_state(const uint8_t state[16], const char* sep);

    void print_state_matrix(uint8_t state[16]);

    void print_state_vector(uint8_t state[16]);

    void words_into_state(
        uint8_t state[16],
        uint32_t w0,
        uint32_t w1,
        uint32_t w2,
        uint32_t w3
    );

    void print_words_matrix(uint32_t w0, uint32_t w1, uint32_t w2, uint32_t w3);

    void print_words_vector(uint32_t w0, uint32_t w1, uint32_t w2, uint32_t w3);

    void print_uint32_array_hex_table(const uint32_t* array, size_t length, size_t per_row);


#endif // TEST_DEBUG_H
