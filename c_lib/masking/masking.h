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

#ifndef MASKING_H
#define MASKING_H

#include <limits.h>
#include "csprng.h"

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif


    /*
     * Security order of the Domain Object Masking.
     * Changing this value requires reworking DOM masking functions.
     */
    #define S_ORDER    2

    #define N_SHARES  (S_ORDER + 1)  // Number of Boolean shares (=3 for 2nd order)

    static const uint8_t BITS_8  = CHAR_BIT * sizeof(uint8_t);
    static const uint8_t BITS_32 = CHAR_BIT * sizeof(uint32_t);
    static const uint8_t BITS_64 = CHAR_BIT * sizeof(uint64_t);


    /* --- 8-BIT FUNCTIONS --- */
    inline void dom_mask8(const uint8_t x, uint8_t s[N_SHARES]) {
        s[1] = csprng_read();
        s[2] = csprng_read();
        s[0] = x ^ s[1] ^ s[2];
    }

    inline uint8_t dom_unmask8(const uint8_t s[3]) {
        return s[0] ^ s[1] ^ s[2];
    }

    inline void dom_refresh_mask8(uint8_t s[N_SHARES]) {
        const uint8_t r1 = csprng_read();
        const uint8_t r2 = csprng_read();
        s[0] ^= r1;
        s[1] ^= r2;
        s[2] ^= r1 ^ r2;
    }

    inline void dom_copy8(uint8_t x[N_SHARES], uint8_t s[N_SHARES]) {
        s[0] = x[0]; s[1] = x[1]; s[2] = x[2];
    }

    void dom_bw_and8(const uint8_t x[N_SHARES], const uint8_t y[N_SHARES], uint8_t out[N_SHARES]);

    void dom_bw_or8(const uint8_t x[N_SHARES], const uint8_t y[N_SHARES], uint8_t out[N_SHARES]);

    void dom_bw_xor8(const uint8_t x[N_SHARES], const uint8_t y[N_SHARES], uint8_t out[N_SHARES]);

    void dom_bw_not8(const uint8_t x[N_SHARES], uint8_t out[N_SHARES]);

    void dom_bw_rotr8(const uint8_t x[N_SHARES], uint8_t out[N_SHARES],uint8_t n);

    void dom_ar_add8(const uint8_t x[N_SHARES], const uint8_t y[N_SHARES], uint8_t out[N_SHARES]);


    /* --- 32-BIT FUNCTIONS --- */
    inline void dom_mask32(const uint32_t x, uint32_t s[N_SHARES]) {
        csprng_read_array((uint8_t*)&s[1], sizeof(uint32_t));
        csprng_read_array((uint8_t*)&s[2], sizeof(uint32_t));
        s[0] = x ^ s[1] ^ s[2];
    }

    inline uint32_t dom_unmask32(const uint32_t s[3]) {
        return s[0] ^ s[1] ^ s[2];
    }

    inline void dom_refresh_mask32(uint32_t s[N_SHARES]) {
        uint32_t r1, r2;
        csprng_read_array((uint8_t*)&r1, sizeof(uint32_t));
        csprng_read_array((uint8_t*)&r2, sizeof(uint32_t));
        s[0] ^= r1;
        s[1] ^= r2;
        s[2] ^= r1 ^ r2;
    }

    inline void dom_copy32(uint32_t x[N_SHARES], uint32_t s[N_SHARES]) {
        s[0] = x[0]; s[1] = x[1]; s[2] = x[2];
    }

    void dom_bw_and32(const uint32_t x[N_SHARES], const uint32_t y[N_SHARES], uint32_t out[N_SHARES]);

    void dom_bw_or32(const uint32_t x[N_SHARES], const uint32_t y[N_SHARES], uint32_t out[N_SHARES]);

    void dom_bw_xor32(const uint32_t x[N_SHARES], const uint32_t y[N_SHARES], uint32_t out[N_SHARES]);

    void dom_bw_not32(const uint32_t x[N_SHARES], uint32_t out[N_SHARES]);

    void dom_bw_rotr32(const uint32_t x[N_SHARES], uint32_t out[N_SHARES], uint32_t n);

    void dom_ar_add32(const uint32_t x[N_SHARES], const uint32_t y[N_SHARES], uint32_t out[N_SHARES]);


    /* --- 64-BIT FUNCTIONS --- */
    inline void dom_mask64(const uint64_t x, uint64_t s[N_SHARES]) {
        csprng_read_array((uint8_t*)&s[1], sizeof(uint64_t));
        csprng_read_array((uint8_t*)&s[2], sizeof(uint64_t));
        s[0] = x ^ s[1] ^ s[2];
    }

    inline uint64_t dom_unmask64(const uint64_t s[3]) {
        return s[0] ^ s[1] ^ s[2];
    }

    inline void dom_refresh_mask64(uint64_t s[N_SHARES]) {
        uint64_t r1, r2;
        csprng_read_array((uint8_t*)&r1, sizeof(uint64_t));
        csprng_read_array((uint8_t*)&r2, sizeof(uint64_t));
        s[0] ^= r1;
        s[1] ^= r2;
        s[2] ^= r1 ^ r2;
    }

    inline void dom_copy64(uint64_t x[N_SHARES], uint64_t s[N_SHARES]) {
        s[0] = x[0]; s[1] = x[1]; s[2] = x[2];
    }

    void dom_bw_and64(const uint64_t x[N_SHARES], const uint64_t y[N_SHARES], uint64_t out[N_SHARES]);

    void dom_bw_or64(const uint64_t x[N_SHARES], const uint64_t y[N_SHARES], uint64_t out[N_SHARES]);

    void dom_bw_xor64(const uint64_t x[N_SHARES], const uint64_t y[N_SHARES], uint64_t out[N_SHARES]);

    void dom_bw_not64(const uint64_t x[N_SHARES], uint64_t out[N_SHARES]);

    void dom_bw_rotr64(const uint64_t x[N_SHARES], uint64_t out[N_SHARES], uint64_t n);

    void dom_ar_add64(const uint64_t x[N_SHARES], const uint64_t y[N_SHARES], uint64_t out[N_SHARES]);


#ifdef __cplusplus
}
#endif

#endif //MASKING_H
