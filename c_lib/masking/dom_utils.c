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
#include "csprng.h"
#include "masking.h"


/* --- 8-BIT FUNCTIONS --- */

void dom_mask8(const uint8_t x, uint8_t s[N_SHARES]) {
    s[1] = csprng_read();
    s[2] = csprng_read();
    s[0] = x ^ s[1] ^ s[2];
}

uint8_t dom_unmask8(const uint8_t s[3]) {
    return s[0] ^ s[1] ^ s[2];
}

void dom_refresh_mask8(uint8_t s[N_SHARES]) {
    const uint8_t r1 = csprng_read();
    const uint8_t r2 = csprng_read();
    s[0] ^= r1;
    s[1] ^= r2;
    s[2] ^= r1 ^ r2;
}

void dom_copy8(const uint8_t x[N_SHARES], uint8_t s[N_SHARES]) {
    s[0] = x[0]; s[1] = x[1]; s[2] = x[2];
}


/* --- 32-BIT FUNCTIONS --- */

void dom_mask32(const uint32_t x, uint32_t s[N_SHARES]) {
    csprng_read_array((uint8_t*)&s[1], sizeof(uint32_t));
    csprng_read_array((uint8_t*)&s[2], sizeof(uint32_t));
    s[0] = x ^ s[1] ^ s[2];
}

uint32_t dom_unmask32(const uint32_t s[3]) {
    return s[0] ^ s[1] ^ s[2];
}

void dom_refresh_mask32(uint32_t s[N_SHARES]) {
    uint32_t r1, r2;
    csprng_read_array((uint8_t*)&r1, sizeof(uint32_t));
    csprng_read_array((uint8_t*)&r2, sizeof(uint32_t));
    s[0] ^= r1;
    s[1] ^= r2;
    s[2] ^= r1 ^ r2;
}

void dom_copy32(const uint32_t x[N_SHARES], uint32_t s[N_SHARES]) {
    s[0] = x[0]; s[1] = x[1]; s[2] = x[2];
}


/* --- 64-BIT FUNCTIONS --- */

void dom_mask64(const uint64_t x, uint64_t s[N_SHARES]) {
    csprng_read_array((uint8_t*)&s[1], sizeof(uint64_t));
    csprng_read_array((uint8_t*)&s[2], sizeof(uint64_t));
    s[0] = x ^ s[1] ^ s[2];
}

uint64_t dom_unmask64(const uint64_t s[3]) {
    return s[0] ^ s[1] ^ s[2];
}

void dom_refresh_mask64(uint64_t s[N_SHARES]) {
    uint64_t r1, r2;
    csprng_read_array((uint8_t*)&r1, sizeof(uint64_t));
    csprng_read_array((uint8_t*)&r2, sizeof(uint64_t));
    s[0] ^= r1;
    s[1] ^= r2;
    s[2] ^= r1 ^ r2;
}

void dom_copy64(const uint64_t x[N_SHARES], uint64_t s[N_SHARES]) {
    s[0] = x[0]; s[1] = x[1]; s[2] = x[2];
}