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

#ifndef BLAKE_INTERNALS_H
#define BLAKE_INTERNALS_H

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif


    void blake32_clean_gmix(
        uint32_t state[16],
        uint8_t a,
        uint8_t b,
        uint8_t c,
        uint8_t d,
        uint32_t mx,
        uint32_t my
    );
    void blake64_clean_gmix(
        uint64_t state[16],
        uint8_t a,
        uint8_t b,
        uint8_t c,
        uint8_t d,
        uint64_t mx,
        uint64_t my
    );

    void blake32_clean_mix_state(uint32_t state[16], const uint32_t m[16]);
    void blake64_clean_mix_state(uint64_t state[16], const uint64_t m[16]);

    void blake32_clean_permute(uint32_t m[16]);
    void blake64_clean_permute(uint64_t m[16]);

    void blake32_optimized_mix_state(uint32_t state[16], const uint32_t m[16]);
    void blake64_optimized_mix_state(uint64_t state[16], const uint64_t m[16]);

    void blake32_optimized_permute(uint32_t m[16]);
    void blake64_optimized_permute(uint64_t m[16]);


#ifdef __cplusplus
}
#endif

#endif //BLAKE_INTERNALS_H
