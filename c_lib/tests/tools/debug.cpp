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
#include <stdio.h>


void print_state(const uint8_t state[16], const char* sep) {
    printf("\n");
    for (int row = 0; row < 4; ++row) {
        for (int col = 0; col < 4; ++col) {
            printf("%02X ", state[row * 4 + col]);
        }
        if (row < 3) {
            printf("%s", sep);
        }
    }
    printf("\n");
}


void print_state_matrix(uint8_t state[16]) {
    print_state(state, "\n");
}


void print_state_vector(uint8_t state[16]) {
    print_state(state, " ");
}


void words_into_state(
        uint8_t state[16],
        const uint32_t w0,
        const uint32_t w1,
        const uint32_t w2,
        const uint32_t w3
) {
    for (int i = 0; i < 4; ++i) {
        state[i     ] = static_cast<uint8_t>(w0 >> (8 * i));
        state[i + 4 ] = static_cast<uint8_t>(w1 >> (8 * i));
        state[i + 8 ] = static_cast<uint8_t>(w2 >> (8 * i));
        state[i + 12] = static_cast<uint8_t>(w3 >> (8 * i));
    }
}


void print_words_matrix(const uint32_t w0, const uint32_t w1, const uint32_t w2, const uint32_t w3) {
    uint8_t state[16];
    words_into_state(state, w0, w1, w2, w3);
    print_state(state, "\n");
}


void print_words_vector(const uint32_t w0, const uint32_t w1, const uint32_t w2, const uint32_t w3) {
    uint8_t state[16];
    words_into_state(state, w0, w1, w2, w3);
    print_state(state, " ");
}


void print_uint32_array_hex_table(const uint32_t* array, const size_t length, const size_t per_row) {
    if (!array || per_row == 0) {
        return;
    }
    printf("\n");
    for (size_t i = 0; i < length; ++i) {
        printf("0x%08XU", array[i]);
        if ((i + 1) % per_row == 0 || i + 1 == length) {
            printf(",\n");
        } else {
            printf(", ");
        }
    }
    printf("\n");
}
