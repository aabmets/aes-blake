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


#define DOM_ATOB_HELPERS(TYPE, SHORT)                                           \
static int csa_##SHORT(                                                         \
        masked_##TYPE* x,                                                       \
        masked_##TYPE* y,                                                       \
        masked_##TYPE* z,                                                       \
        masked_##TYPE** s_res,                                                  \
        masked_##TYPE** c_res                                                   \
) {                                                                             \
    masked_##TYPE** tmp = dom_alloc_many_##SHORT(x->domain, x->order, 5);       \
    if (!tmp)                                                                   \
        return 1;                                                               \
                                                                                \
    /*  a = x ^ y  */                                                           \
    masked_##TYPE* a = tmp[0];                                                  \
    dom_bool_xor_##SHORT(x, y, a);                                              \
                                                                                \
    /*  s = a ^ z  */                                                           \
    masked_##TYPE* s = tmp[1];                                                  \
    dom_bool_xor_##SHORT(a, z, s);                                              \
                                                                                \
    /*  w = x ^ z  */                                                           \
    masked_##TYPE* w = tmp[2];                                                  \
    dom_bool_xor_##SHORT(x, z, w);                                              \
                                                                                \
    /*  v = a & w  */                                                           \
    masked_##TYPE* v = tmp[3];                                                  \
    dom_bool_and_##SHORT(a, w, v);                                              \
                                                                                \
    /*  c = x ^ v  */                                                           \
    masked_##TYPE* c = tmp[4];                                                  \
    dom_bool_xor_##SHORT(x, v, c);                                              \
    dom_bool_shl_##SHORT(c, 1);                                                 \
                                                                                \
    *s_res = s;                                                                 \
    *c_res = c;                                                                 \
                                                                                \
    dom_free_many_##SHORT(tmp, 5, 0b10010u);                                    \
    asm volatile ("" ::: "memory");                                             \
    return 0;                                                                   \
}                                                                               \
                                                                                \
/* NOLINTNEXTLINE(misc-no-recursion) */                                         \
static int csa_tree_##SHORT(                                                    \
        masked_##TYPE* vals[],                                                  \
        masked_##TYPE** s_res,                                                  \
        masked_##TYPE** c_res,                                                  \
        const uint8_t len                                                       \
) {                                                                             \
    if (len == 3) {                                                             \
        return csa_##SHORT(vals[0], vals[1], vals[2], s_res, c_res);            \
    }                                                                           \
    const uint8_t len_min1 = len - 1;                                           \
    const domain_t domain = vals[0]->domain;                                    \
    const uint8_t order = vals[0]->order;                                       \
                                                                                \
    masked_##TYPE** tmp = dom_alloc_many_##SHORT(domain, order, 2);             \
    if (!tmp)                                                                   \
        return 1;                                                               \
                                                                                \
    int err = csa_tree_##SHORT(vals, &tmp[0], &tmp[1], len_min1);               \
    if (err) {                                                                  \
        dom_free_many_##SHORT(tmp, 2, 0);                                       \
        return 1;                                                               \
    }                                                                           \
    err = csa_##SHORT(tmp[0], tmp[1], vals[len_min1], s_res, c_res);            \
                                                                                \
    dom_free_many_##SHORT(tmp, 2, 0);                                           \
    asm volatile ("" ::: "memory");                                             \
    return err;                                                                 \
}                                                                               \


#ifndef DOM_CONV_ATOB
#define DOM_CONV_ATOB(TYPE, SHORT)                                              \
                                                                                \
DOM_ATOB_HELPERS(TYPE, SHORT)                                                   \
                                                                                \
/*   Converts masked shares from arithmetic to boolean domain using        */   \
/*   the high-order recursive carry-save-adder method of Liu et al.,       */   \
/*   “A Low-Latency High-Order Arithmetic to Boolean Masking Conversion”   */   \
/*   Link: https://eprint.iacr.org/2024/045.pdf                            */   \
int dom_conv_atob_##SHORT(masked_##TYPE *mv) {                                  \
    if (mv->domain == DOMAIN_BOOLEAN)                                           \
        return 0;                                                               \
                                                                                \
    const uint8_t order = mv->order;                                            \
    const uint8_t share_count = mv->share_count;                                \
                                                                                \
    masked_##TYPE** vals = dom_mask_many_##SHORT                                \
        (mv->shares, DOMAIN_BOOLEAN, order, share_count);                       \
    if (!vals)                                                                  \
        return 1;                                                               \
                                                                                \
    masked_##TYPE* s_res = NULL;                                                \
    masked_##TYPE* c_res = NULL;                                                \
                                                                                \
    if (share_count == 2) {                                                     \
        s_res = vals[0];                                                        \
        c_res = vals[1];                                                        \
    } else {                                                                    \
        if (csa_tree_##SHORT(vals, &s_res, &c_res, share_count)) {              \
            dom_free_many_##SHORT(vals, share_count, 0);                        \
            if (s_res != NULL)                                                  \
                dom_free_##SHORT(s_res);                                        \
            if (c_res != NULL)                                                  \
                dom_free_##SHORT(c_res);                                        \
            return 1;                                                           \
        }                                                                       \
    }                                                                           \
    masked_##TYPE* k_res = dom_ksa_carry_##SHORT(s_res, c_res);                 \
    if (!k_res) {                                                               \
        dom_free_many_##SHORT(vals, share_count, 0);                            \
        if (share_count > 2) {                                                  \
            dom_free_##SHORT(s_res);                                            \
            dom_free_##SHORT(c_res);                                            \
        }                                                                       \
        return 1;                                                               \
    }                                                                           \
                                                                                \
    dom_bool_xor_##SHORT(s_res, k_res, k_res);                                  \
    dom_bool_xor_##SHORT(c_res, k_res, k_res);                                  \
                                                                                \
    memcpy(mv->shares, k_res->shares, mv->share_bytes);                         \
    mv->domain = DOMAIN_BOOLEAN;                                                \
                                                                                \
    dom_free_many_##SHORT(vals, share_count, 0);                                \
    dom_free_##SHORT(k_res);                                                    \
    if (share_count > 2) {                                                      \
        dom_free_##SHORT(s_res);                                                \
        dom_free_##SHORT(c_res);                                                \
    }                                                                           \
    asm volatile ("" ::: "memory");                                             \
    return 0;                                                                   \
}                                                                               \

#endif //DOM_CONV_ATOB


DOM_CONV_ATOB(uint8_t, u8)
DOM_CONV_ATOB(uint16_t, u16)
DOM_CONV_ATOB(uint32_t, u32)
DOM_CONV_ATOB(uint64_t, u64)
