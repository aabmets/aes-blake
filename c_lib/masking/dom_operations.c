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
#include "dom_types.h"


/*
 *   Parametrized preprocessor macro template for all operations functions.
 */
#ifndef DOM_OPERATION_FUNCTIONS
#define DOM_OPERATION_FUNCTIONS(TYPE, FN_SUFFIX)                                \
                                                                                \
/*   Implements the DOM-indep secure multiplication/AND   */                    \
/*   of 2-nd order shares, as described by Gross et al.   */                    \
/*   in “Domain-Oriented Masking” (CHES 2016).            */                    \
void dom_bool_and_##FN_SUFFIX(                                                  \
        const masked_##TYPE* mv_a,                                              \
        const masked_##TYPE* mv_b,                                              \
        masked_##TYPE* mv_out                                                   \
) {                                                                             \
    /* --- Generate randomness --- */                                           \
    TYPE rand[N_SHARES];                                                        \
    csprng_read_array((uint8_t*)rand, sizeof(rand));                            \
    const TYPE r01 = rand[0], r02 = rand[1], r12 = rand[2];                     \
                                                                                \
    /* --- Load shares into local variables --- */                              \
    const TYPE* x = mv_a->shares;                                               \
    const TYPE* y = mv_b->shares;                                               \
    const TYPE x0 = x[0], x1 = x[1], x2 = x[2];                                 \
    const TYPE y0 = y[0], y1 = y[1], y2 = y[2];                                 \
                                                                                \
    /* --- Resharing phase (computation) --- */                                 \
    const TYPE p01_masked = x0 & y1 ^ r01;                                      \
    const TYPE p10_masked = x1 & y0 ^ r01;                                      \
                                                                                \
    const TYPE p02_masked = x0 & y2 ^ r02;                                      \
    const TYPE p20_masked = x2 & y0 ^ r02;                                      \
                                                                                \
    const TYPE p12_masked = x1 & y2 ^ r12;                                      \
    const TYPE p21_masked = x2 & y1 ^ r12;                                      \
                                                                                \
    /* --- Integration phase --- */                                             \
    TYPE* out = mv_out->shares;                                                 \
    out[0] = x0 & y0 ^ p01_masked ^ p02_masked;                                 \
    out[1] = x1 & y1 ^ p10_masked ^ p12_masked;                                 \
    out[2] = x2 & y2 ^ p20_masked ^ p21_masked;                                 \
                                                                                \
    /* --- Compiler memory barrier --- */                                       \
    asm volatile ("" ::: "memory");                                             \
}                                                                               \
                                                                                \
                                                                                \
void dom_bool_or_##FN_SUFFIX(                                                   \
        const masked_##TYPE* mv_a,                                              \
        const masked_##TYPE* mv_b,                                              \
        masked_##TYPE* mv_out                                                   \
) {                                                                             \
    dom_bool_and_##FN_SUFFIX(mv_a, mv_b, mv_out);                               \
                                                                                \
    const TYPE* x = mv_a->shares;                                               \
    const TYPE* y = mv_b->shares;                                               \
    TYPE* out = mv_out->shares;                                                 \
                                                                                \
    /*  Based on the identity: a | b = a ^ b ^ (a & b)  */                      \
    out[0] ^= x[0] ^ y[0];                                                      \
    out[1] ^= x[1] ^ y[1];                                                      \
    out[2] ^= x[2] ^ y[2];                                                      \
                                                                                \
    /* --- Compiler memory barrier --- */                                       \
    asm volatile ("" ::: "memory");                                             \
}                                                                               \
                                                                                \
                                                                                \
void dom_bool_xor_##FN_SUFFIX(                                                  \
        const masked_##TYPE* mv_a,                                              \
        const masked_##TYPE* mv_b,                                              \
        masked_##TYPE* mv_out                                                   \
) {                                                                             \
    const TYPE* x = mv_a->shares;                                               \
    const TYPE* y = mv_b->shares;                                               \
    TYPE* out = mv_out->shares;                                                 \
                                                                                \
    out[0] = x[0] ^ y[0];                                                       \
    out[1] = x[1] ^ y[1];                                                       \
    out[2] = x[2] ^ y[2];                                                       \
                                                                                \
    /* --- Compiler memory barrier --- */                                       \
    asm volatile ("" ::: "memory");                                             \
}                                                                               \
                                                                                \
                                                                                \
void dom_bool_not_##FN_SUFFIX(masked_##TYPE* mv) {                              \
    mv->shares[0] = ~mv->shares[0];                                             \
}                                                                               \
                                                                                \
                                                                                \
void dom_bool_shr_##FN_SUFFIX(masked_##TYPE* mv, uint8_t n) {                   \
    TYPE* s = mv->shares;                                                       \
    s[0] >>= n; s[1] >>= n; s[2] >>= n;                                         \
}                                                                               \
                                                                                \
                                                                                \
void dom_bool_shl_##FN_SUFFIX(masked_##TYPE* mv, uint8_t n) {                   \
    TYPE* s = mv->shares;                                                       \
    s[0] <<= n; s[1] <<= n; s[2] <<= n;                                         \
}                                                                               \
                                                                                \
                                                                                \
void dom_bool_rotr_##FN_SUFFIX(masked_##TYPE* mv, uint8_t n) {                  \
    TYPE* s = mv->shares;                                                       \
    const TYPE x = s[0], y = s[1], z = s[2];                                    \
    bit_length_t bl = mv->bit_length;                                           \
                                                                                \
    s[0] = x >> n | x << (bl - n);                                              \
    s[1] = y >> n | y << (bl - n);                                              \
    s[2] = z >> n | z << (bl - n);                                              \
}                                                                               \
                                                                                \
                                                                                \
void dom_bool_rotl_##FN_SUFFIX(masked_##TYPE* mv, uint8_t n) {                  \
    TYPE* s = mv->shares;                                                       \
    const TYPE x = s[0], y = s[1], z = s[2];                                    \
    bit_length_t bl = mv->bit_length;                                           \
                                                                                \
    s[0] = x << n | x >> (bl - n);                                              \
    s[1] = y << n | y >> (bl - n);                                              \
    s[2] = z << n | z >> (bl - n);                                              \
}                                                                               \
                                                                                \
                                                                                \
void dom_arith_add_##FN_SUFFIX(                                                 \
        const masked_##TYPE* mv_a,                                              \
        const masked_##TYPE* mv_b,                                              \
        masked_##TYPE* mv_out                                                   \
) {                                                                             \
    const TYPE* x = mv_a->shares;                                               \
    const TYPE* y = mv_b->shares;                                               \
    TYPE* out = mv_out->shares;                                                 \
                                                                                \
    out[0] = x[0] + y[0];                                                       \
    out[1] = x[1] + y[1];                                                       \
    out[2] = x[2] + y[2];                                                       \
                                                                                \
    /* --- Compiler memory barrier --- */                                       \
    asm volatile ("" ::: "memory");                                             \
}                                                                               \
                                                                                \
                                                                                \
/*   Implements the DOM-indep secure multiplication/AND   */                    \
/*   of 2-nd order shares, as described by Gross et al.   */                    \
/*   in “Domain-Oriented Masking” (CHES 2016).            */                    \
void dom_arith_mult_##FN_SUFFIX(                                                \
        const masked_##TYPE* mv_a,                                              \
        const masked_##TYPE* mv_b,                                              \
        masked_##TYPE* mv_out                                                   \
) {                                                                             \
    /* --- Generate fresh randomness --- */                                     \
    TYPE rand[N_SHARES];                                                        \
    csprng_read_array((uint8_t*)rand, sizeof(rand));                            \
    const TYPE r01 = rand[0], r02 = rand[1], r12 = rand[2];                     \
                                                                                \
    /* --- Load input shares into locals --- */                                 \
    const TYPE* x = mv_a->shares;                                               \
    const TYPE* y = mv_b->shares;                                               \
    const TYPE x0 = x[0], x1 = x[1], x2 = x[2];                                 \
    const TYPE y0 = y[0], y1 = y[1], y2 = y[2];                                 \
                                                                                \
    /* --- Resharing phase (second-order DOM-indep) --- */                      \
    const TYPE p01_masked = x0 * y1 +  r01;                                     \
    const TYPE p10_masked = x1 * y0 -  r01;                                     \
                                                                                \
    const TYPE p02_masked = x0 * y2 +  r02;                                     \
    const TYPE p20_masked = x2 * y0 -  r02;                                     \
                                                                                \
    const TYPE p12_masked = x1 * y2 +  r12;                                     \
    const TYPE p21_masked = x2 * y1 -  r12;                                     \
                                                                                \
    /* --- Integration phase --- */                                             \
    TYPE* out = mv_out->shares;                                                 \
    out[0] = x0 * y0 + p01_masked + p02_masked;                                 \
    out[1] = x1 * y1 + p10_masked + p12_masked;                                 \
    out[2] = x2 * y2 + p20_masked + p21_masked;                                 \
                                                                                \
    /* --- Compiler memory barrier --- */                                       \
    asm volatile ("" ::: "memory");                                             \
}                                                                               \

#endif //DOM_OPERATION_FUNCTIONS


/*
 *   Create operations functions for all supported types.
 */
DOM_OPERATION_FUNCTIONS(uint8_t, u8)
DOM_OPERATION_FUNCTIONS(uint32_t, u32)
DOM_OPERATION_FUNCTIONS(uint64_t, u64)
