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

#include <stdlib.h>
#include <stdint.h>

#include "csprng.h"
#include "masking.h"
#include "dom_types.h"


/* ─────────────────────────────────────────────────────────────────────────── */
/*   Internal helpers for the dom_conv_btoa function                           */
/* ─────────────────────────────────────────────────────────────────────────── */
#define DOM_BTOA_HELPERS(TYPE, FN_SUFFIX)                                       \
static inline TYPE psi_##FN_SUFFIX(TYPE masked, TYPE mask) {                    \
    return (masked ^ mask) - mask;                                              \
}                                                                               \
                                                                                \
static TYPE *convert_##FN_SUFFIX(const TYPE *x, uint8_t n_plus1) {              \
    uint8_t n = n_plus1 - 1;                                                    \
    if (n == 1) {                                                               \
        TYPE *out = (TYPE *)malloc(sizeof(TYPE));                               \
        out[0] = x[0] ^ x[1];                                                   \
        return out;                                                             \
    }                                                                           \
                                                                                \
    TYPE *rnd = (TYPE *)malloc(n * sizeof(TYPE));                               \
    csprng_read_array((uint8_t *)rnd, n * sizeof(TYPE));                        \
                                                                                \
    TYPE *x_mut = (TYPE *)malloc(n_plus1 * sizeof(TYPE));                       \
    for (uint8_t i = 0; i < n_plus1; ++i) {                                     \
        x_mut[i] = x[i];                                                        \
    }                                                                           \
                                                                                \
    for (uint8_t i = 1; i < n_plus1; ++i) {                                     \
        TYPE r = rnd[i - 1];                                                    \
        x_mut[i] ^= r;                                                          \
        x_mut[0] ^= r;                                                          \
    }                                                                           \
                                                                                \
    TYPE *y = (TYPE *)malloc(n * sizeof(TYPE));                                 \
    TYPE first_term = ((n - 1) & 1U) ? x_mut[0] : (TYPE)0;                      \
    y[0] = first_term ^ psi_##FN_SUFFIX(x_mut[0], x_mut[1]);                    \
    for (uint8_t i = 1; i < n; ++i) {                                           \
        y[i] = psi_##FN_SUFFIX(x_mut[0], x_mut[i + 1]);                         \
    }                                                                           \
                                                                                \
    TYPE *first  = convert_##FN_SUFFIX(&x_mut[1], n);                           \
    TYPE *second = convert_##FN_SUFFIX(y, n);                                   \
                                                                                \
    TYPE *out = (TYPE *)malloc(n * sizeof(TYPE));                               \
    for (uint8_t i = 0; i < n - 2; ++i) {                                       \
        out[i] = first[i] + second[i];                                          \
    }                                                                           \
    uint8_t n_1 = n - 1;                                                        \
    uint8_t n_2 = n - 2;                                                        \
    out[n_2] = first[n_2];                                                      \
    out[n_1] = second[n_2];                                                     \
                                                                                \
    free(rnd);                                                                  \
    free(x_mut);                                                                \
    free(y);                                                                    \
    free(first);                                                                \
    free(second);                                                               \
    return out;                                                                 \
}                                                                               \


/* ─────────────────────────────────────────────────────────────────────────── */
/*   Converter macro – generates btoa & atob for each integer width            */
/* ─────────────────────────────────────────────────────────────────────────── */
#ifndef DOM_CONVERTER_FUNCTIONS
#define DOM_CONVERTER_FUNCTIONS(TYPE, FN_SUFFIX)                                \
                                                                                \
DOM_BTOA_HELPERS(TYPE, FN_SUFFIX)                                               \
                                                                                \
/*   Converts masked shares from boolean to arithmetic domain using        */   \
/*   the affine psi recursive decomposition method of Bettale et al.,      */   \
/*   "Improved High-Order Conversion From Boolean to Arithmetic Masking"   */   \
/*   Link: https://eprint.iacr.org/2018/328.pdf                            */   \
void dom_conv_btoa_##FN_SUFFIX(masked_##TYPE *mv) {                             \
    if (mv->domain == DOMAIN_ARITHMETIC) return;                                \
    uint8_t sc = mv->share_count;                                               \
    uint8_t sc_extra = sc + 1;                                                  \
    TYPE *shares = mv->shares;                                                  \
                                                                                \
    TYPE *tmp = (TYPE *)malloc(sc_extra * sizeof(TYPE));                        \
    for (uint8_t i = 0; i < sc; ++i) {                                          \
        tmp[i] = shares[i];                                                     \
    }                                                                           \
    tmp[sc] = (TYPE)0;                                                          \
                                                                                \
    TYPE *new_shares = convert_##FN_SUFFIX(tmp, sc_extra);                      \
    for (uint8_t i = 0; i < sc; ++i) {                                          \
        mv->shares[i] = new_shares[i];                                          \
    }                                                                           \
    mv->domain = DOMAIN_ARITHMETIC;                                             \
                                                                                \
    free(tmp);                                                                  \
    free(new_shares);                                                           \
    asm volatile ("" ::: "memory");                                             \
}                                                                               \
                                                                                \
/*   TODO: Replace this insecure atob implementation   */                       \
void dom_conv_atob_##FN_SUFFIX(masked_##TYPE* mv) {                             \
    if (mv->domain == DOMAIN_BOOLEAN) return;                                   \
    TYPE *s = mv->shares;                                                       \
    uint8_t sc = mv->share_count;                                               \
    TYPE value = s[0];                                                          \
    for (uint8_t i = 1; i < sc; ++i) {                                          \
        value += s[i];                                                          \
    }                                                                           \
    for (uint8_t i = 1; i < sc; ++i) {                                          \
        value ^= s[i];                                                          \
    }                                                                           \
    s[0] = value;                                                               \
    mv->domain = DOMAIN_BOOLEAN;                                                \
    asm volatile("" ::: "memory");                                              \
}                                                                               \

#endif //DOM_CONVERTER_FUNCTIONS


/* ─────────────────────────────────────────────────────────────────────────── */
/*   Instantiate converters for all supported integer widths                   */
/* ─────────────────────────────────────────────────────────────────────────── */
DOM_CONVERTER_FUNCTIONS(uint8_t, u8)
DOM_CONVERTER_FUNCTIONS(uint32_t, u32)
DOM_CONVERTER_FUNCTIONS(uint64_t, u64)
