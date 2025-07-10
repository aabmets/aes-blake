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


#define DOM_BTOA_HELPERS(TYPE, FN_SUFFIX)                                       \
static inline TYPE psi_##FN_SUFFIX(TYPE masked, TYPE mask) {                    \
    return (masked ^ mask) - mask;                                              \
}                                                                               \
                                                                                \
/* NOLINTNEXTLINE(bugprone-macro-parentheses, misc-no-recursion) */             \
static TYPE* convert_##FN_SUFFIX(const TYPE* x, uint8_t n_plus1) {              \
    const uint8_t n = n_plus1 - 1;                                              \
    if (n == 1) {                                                               \
        TYPE* out = (TYPE*)malloc(sizeof(TYPE));                                \
        if (!out) return NULL;                                                  \
        *out = x[0] ^ x[1];                                                     \
        return out;                                                             \
    }                                                                           \
                                                                                \
    TYPE rnd[n];                                                                \
    csprng_read_array((uint8_t*)rnd, n * sizeof(TYPE));                         \
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
    TYPE* first = convert_##FN_SUFFIX(&x_mut[1], n);                            \
    TYPE* second = convert_##FN_SUFFIX(y, n);                                   \
    if (!first || !second) {                                                    \
        free(first);                                                            \
        free(second);                                                           \
        return NULL;                                                            \
    }                                                                           \
                                                                                \
    size_t buf_size = (size_t)(n - 1) * sizeof(TYPE);                           \
    TYPE* out = (TYPE*)malloc(n * sizeof(TYPE));                                \
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


#ifndef DOM_CONV_BTOA
#define DOM_CONV_BTOA(TYPE, FN_SUFFIX)                                          \
                                                                                \
DOM_BTOA_HELPERS(TYPE, FN_SUFFIX)                                               \
                                                                                \
/*   Converts masked shares from boolean to arithmetic domain using        */   \
/*   the affine psi recursive decomposition method of Bettale et al.,      */   \
/*   "Improved High-Order Conversion From Boolean to Arithmetic Masking"   */   \
/*   Link: https://eprint.iacr.org/2018/328.pdf                            */   \
int dom_conv_btoa_##FN_SUFFIX(masked_##TYPE *mv) {                              \
    if (mv->domain == DOMAIN_ARITHMETIC)                                        \
        return 0;                                                               \
                                                                                \
    uint8_t share_bytes = mv->share_bytes;                                      \
    uint8_t share_count = mv->share_count;                                      \
    uint8_t sc_extra = share_count + 1;                                         \
    uint8_t sce_bytes = sc_extra * sizeof(TYPE);                                \
    TYPE* shares = mv->shares;                                                  \
                                                                                \
    TYPE* tmp = (TYPE*)malloc(sce_bytes);                                       \
    if (!tmp)                                                                   \
        return 1;                                                               \
                                                                                \
    memcpy(tmp, shares, share_bytes);                                           \
    tmp[share_count] = (TYPE)0;                                                 \
                                                                                \
    TYPE* new_shares = convert_##FN_SUFFIX(tmp, sc_extra);                      \
    if (!new_shares) {                                                          \
        secure_memzero(tmp, sce_bytes);                                         \
        free(tmp);                                                              \
        return 1;                                                               \
    }                                                                           \
    memcpy(shares, new_shares, share_bytes);                                    \
    mv->domain = DOMAIN_ARITHMETIC;                                             \
                                                                                \
    secure_memzero(tmp, sce_bytes);                                             \
    secure_memzero(new_shares, share_bytes);                                    \
    free(tmp);                                                                  \
    free(new_shares);                                                           \
    asm volatile ("" ::: "memory");                                             \
    return 0;                                                                   \
}                                                                               \

#endif //DOM_CONV_BTOA


DOM_CONV_BTOA(uint8_t, u8)
DOM_CONV_BTOA(uint32_t, u32)
DOM_CONV_BTOA(uint64_t, u64)
