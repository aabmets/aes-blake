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
#include <string.h>

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
    const uint8_t n = n_plus1 - 1;                                              \
    if (n == 1) {                                                               \
        TYPE *out = (TYPE *)malloc(sizeof(TYPE));                               \
        if (!out) return NULL;                                                  \
        *out = x[0] ^ x[1];                                                     \
        return out;                                                             \
    }                                                                           \
                                                                                \
    TYPE rnd[n];                                                                \
    csprng_read_array((uint8_t *)rnd, n * sizeof(TYPE));                        \
                                                                                \
    TYPE x_mut[n_plus1];                                                        \
    memcpy(x_mut, x, n_plus1 * sizeof(TYPE));                                   \
                                                                                \
    for (uint8_t i = 1; i < n_plus1; ++i) {                                     \
        TYPE r = rnd[i - 1];                                                    \
        x_mut[i] ^= r;                                                          \
        x_mut[0] ^= r;                                                          \
    }                                                                           \
                                                                                \
    TYPE y[n];                                                                  \
    TYPE first_term = ((n - 1) & 1U) ? x_mut[0] : (TYPE)0;                      \
    y[0] = first_term ^ psi_##FN_SUFFIX(x_mut[0], x_mut[1]);                    \
    for (uint8_t i = 1; i < n; ++i) {                                           \
        y[i] = psi_##FN_SUFFIX(x_mut[0], x_mut[i + 1]);                         \
    }                                                                           \
                                                                                \
    TYPE *first = convert_##FN_SUFFIX(&x_mut[1], n);                            \
    TYPE *second = convert_##FN_SUFFIX(y, n);                                   \
    if (!first || !second) {                                                    \
        free(first);                                                            \
        free(second);                                                           \
        return NULL;                                                            \
    }                                                                           \
                                                                                \
    size_t buf_size = (size_t)(n - 1) * sizeof(TYPE);                           \
    TYPE *out = (TYPE *)malloc(n * sizeof(TYPE));                               \
    if (!out) {                                                                 \
        secure_memzero(first, buf_size);                                        \
        secure_memzero(second, buf_size);                                       \
        free(first);                                                            \
        free(second);                                                           \
        return NULL;                                                            \
    }                                                                           \
    for (uint8_t i = 0; i < n - 2; ++i) {                                       \
        out[i] = first[i] + second[i];                                          \
    }                                                                           \
    out[n - 2] = first[n - 2];                                                  \
    out[n - 1] = second[n - 2];                                                 \
                                                                                \
    secure_memzero(first, buf_size);                                            \
    secure_memzero(second, buf_size);                                           \
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
    if (mv->domain == DOMAIN_ARITHMETIC)                                        \
        return;                                                                 \
                                                                                \
    uint8_t sc = mv->share_count;                                               \
    uint8_t sc_extra = sc + 1;                                                  \
                                                                                \
    TYPE *tmp = (TYPE *)malloc(sc_extra * sizeof(TYPE));                        \
    if (!tmp)                                                                   \
        return;                                                                 \
                                                                                \
    TYPE *shares = mv->shares;                                                  \
    for (uint8_t i = 0; i < sc; ++i) {                                          \
        tmp[i] = shares[i];                                                     \
    }                                                                           \
    tmp[sc] = (TYPE)0;                                                          \
                                                                                \
    TYPE *new_shares = convert_##FN_SUFFIX(tmp, sc_extra);                      \
    if (!new_shares) {                                                          \
        secure_memzero(tmp, sc_extra * sizeof(TYPE));                           \
        free(tmp);                                                              \
        return;                                                                 \
    }                                                                           \
    for (uint8_t i = 0; i < sc; ++i) {                                          \
        mv->shares[i] = new_shares[i];                                          \
    }                                                                           \
    mv->domain = DOMAIN_ARITHMETIC;                                             \
                                                                                \
    secure_memzero(tmp, sc_extra * sizeof(TYPE));                               \
    secure_memzero(new_shares, sc * sizeof(TYPE));                              \
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
