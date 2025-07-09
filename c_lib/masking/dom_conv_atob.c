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

#include "masking.h"
#include "dom_types.h"


#define DOM_ATOB_HELPERS(TYPE, FN_SUFFIX)                                       \
static void csa_##FN_SUFFIX(                                                    \
        masked_##TYPE *x,                                                       \
        masked_##TYPE *y,                                                       \
        masked_##TYPE *z,                                                       \
        masked_##TYPE **s_res,                                                  \
        masked_##TYPE **c_res                                                   \
) {                                                                             \
    masked_##TYPE *tmp[5];                                                      \
    for (uint8_t i = 0; i < 5; ++i) {                                           \
        tmp[i] = dom_clone_##FN_SUFFIX(x);                                      \
        if (!tmp[i]) {                                                          \
            for (uint8_t j = 0; j < i; ++j) {                                   \
                dom_free_##FN_SUFFIX(tmp[j]);                                   \
            }                                                                   \
            return;                                                             \
        }                                                                       \
    }                                                                           \
    /*  a = x ^ y  */                                                           \
    masked_##TYPE *a = tmp[0];                                                  \
    dom_bool_xor_##FN_SUFFIX(x, y, a);                                          \
                                                                                \
    /*  s = a ^ z  */                                                           \
    masked_##TYPE *s = tmp[1];                                                  \
    dom_bool_xor_##FN_SUFFIX(a, z, s);                                          \
                                                                                \
    /*  w = x ^ z  */                                                           \
    masked_##TYPE *w = tmp[2];                                                  \
    dom_bool_xor_##FN_SUFFIX(x, z, w);                                          \
                                                                                \
    /*  v = a & w  */                                                           \
    masked_##TYPE *v = tmp[3];                                                  \
    dom_bool_and_##FN_SUFFIX(a, w, v);                                          \
                                                                                \
    /*  c = x ^ v  */                                                           \
    masked_##TYPE *c = tmp[4];                                                  \
    dom_bool_xor_##FN_SUFFIX(x, v, c);                                          \
    dom_bool_shl_##FN_SUFFIX(c, 1);                                             \
                                                                                \
    *s_res = s;                                                                 \
    *c_res = c;                                                                 \
                                                                                \
    dom_free_##FN_SUFFIX(a);                                                    \
    dom_free_##FN_SUFFIX(w);                                                    \
    dom_free_##FN_SUFFIX(v);                                                    \
                                                                                \
    asm volatile ("" ::: "memory");                                             \
}                                                                               \
                                                                                \
void csa_tree_##FN_SUFFIX(                                                      \
        masked_##TYPE *vals[],                                                  \
        masked_##TYPE **s_res,                                                  \
        masked_##TYPE **c_res,                                                  \
        const uint8_t len                                                       \
) {                                                                             \
    if (len == 3) {                                                             \
        csa_##FN_SUFFIX(vals[0], vals[1], vals[2], s_res, c_res);               \
        return;                                                                 \
    }                                                                           \
    masked_##TYPE *s_tmp, *c_tmp;                                               \
    const uint8_t len_min1 = len - 1;                                           \
                                                                                \
    csa_tree_##FN_SUFFIX(vals, &s_tmp, &c_tmp, len_min1);                       \
    csa_##FN_SUFFIX(s_tmp, c_tmp, vals[len_min1], s_res, c_res);                \
                                                                                \
    dom_free_##FN_SUFFIX(s_tmp);                                                \
    dom_free_##FN_SUFFIX(c_tmp);                                                \
                                                                                \
    asm volatile ("" ::: "memory");                                             \
}                                                                               \
                                                                                \
masked_##TYPE* ksa_##FN_SUFFIX(masked_##TYPE *a, masked_##TYPE *b)              \
{                                                                               \
    masked_##TYPE *p = dom_clone_##FN_SUFFIX(a);                                \
    dom_bool_xor_##FN_SUFFIX(a, b, p);                                          \
                                                                                \
    masked_##TYPE *g = dom_clone_##FN_SUFFIX(a);                                \
    dom_bool_and_##FN_SUFFIX(a, b, g);                                          \
                                                                                \
    const uint8_t bl = (uint8_t)a->bit_length;                                  \
    for (uint8_t dist = 1; dist < bl; dist <<= 1) {                             \
        masked_##TYPE *g_shift = dom_clone_##FN_SUFFIX(g);                      \
        dom_bool_shl_##FN_SUFFIX(g_shift, dist);                                \
                                                                                \
        masked_##TYPE *p_shift = dom_clone_##FN_SUFFIX(p);                      \
        dom_bool_shl_##FN_SUFFIX(p_shift, dist);                                \
                                                                                \
        masked_##TYPE *tmp = dom_clone_##FN_SUFFIX(p);                          \
        dom_bool_and_##FN_SUFFIX(p, g_shift, tmp);                              \
        dom_bool_xor_##FN_SUFFIX(g, tmp, g);                                    \
        dom_bool_and_##FN_SUFFIX(p, p_shift, p);                                \
                                                                                \
        dom_free_##FN_SUFFIX(g_shift);                                          \
        dom_free_##FN_SUFFIX(p_shift);                                          \
        dom_free_##FN_SUFFIX(tmp);                                              \
    }                                                                           \
    dom_bool_shl_##FN_SUFFIX(g, 1);                                             \
    dom_free_##FN_SUFFIX(p);                                                    \
    return g;                                                                   \
}                                                                               \


#ifndef DOM_CONV_ATOB
#define DOM_CONV_ATOB(TYPE, FN_SUFFIX)                                          \
                                                                                \
DOM_ATOB_HELPERS(TYPE, FN_SUFFIX)                                               \
                                                                                \
/*   Converts masked shares from arithmetic to boolean domain using        */   \
/*   the high-order recursive carry-save-adder method of Liu et al.,       */   \
/*   “A Low-Latency High-Order Arithmetic to Boolean Masking Conversion”   */   \
/*   Link: https://eprint.iacr.org/2024/045.pdf                            */   \
void dom_conv_atob_##FN_SUFFIX(masked_##TYPE *mv) {                             \
    if (mv->domain == DOMAIN_BOOLEAN)                                           \
        return;                                                                 \
                                                                                \
    TYPE *shares = mv->shares;                                                  \
    const uint8_t order = mv->order;                                            \
    const uint8_t share_count = mv->share_count;                                \
                                                                                \
    masked_##TYPE *vals[share_count];                                           \
    for (uint8_t i = 0; i < share_count; ++i) {                                 \
        vals[i] = dom_mask_##FN_SUFFIX(shares[i], DOMAIN_BOOLEAN, order);       \
        if (!vals[i]) {                                                         \
            for (uint8_t j = 0; j < i; ++j) {                                   \
                dom_free_##FN_SUFFIX(vals[j]);                                  \
            }                                                                   \
            return;                                                             \
        }                                                                       \
    }                                                                           \
                                                                                \
    masked_##TYPE *s_res = NULL;                                                \
    masked_##TYPE *c_res = NULL;                                                \
                                                                                \
    if (share_count == 2) {                                                     \
        s_res = vals[0];                                                        \
        c_res = vals[1];                                                        \
    } else {                                                                    \
        csa_tree_##FN_SUFFIX(vals, &s_res, &c_res, share_count);                \
    }                                                                           \
    masked_##TYPE *k_res = ksa_##FN_SUFFIX(s_res, c_res);                       \
                                                                                \
    dom_bool_xor_##FN_SUFFIX(s_res, k_res, k_res);                              \
    dom_bool_xor_##FN_SUFFIX(c_res, k_res, k_res);                              \
                                                                                \
    memcpy(shares, k_res->shares, share_count * sizeof(TYPE));                  \
    mv->domain = DOMAIN_BOOLEAN;                                                \
                                                                                \
    dom_free_##FN_SUFFIX(k_res);                                                \
    for (uint8_t i = 0; i < share_count; ++i) {                                 \
        dom_free_##FN_SUFFIX(vals[i]);                                          \
    }                                                                           \
    asm volatile ("" ::: "memory");                                             \
}                                                                               \

#endif //DOM_CONV_ATOB


DOM_CONV_ATOB(uint8_t, u8)
DOM_CONV_ATOB(uint32_t, u32)
DOM_CONV_ATOB(uint64_t, u64)
