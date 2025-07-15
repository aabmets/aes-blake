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
#include "dom_internal_defs.h"


#define DOM_ATOB_HELPERS(BL)                                                    \
static int FN(csa, BL)(                                                         \
        MTP(BL) x,                                                              \
        MTP(BL) y,                                                              \
        MTP(BL) z,                                                              \
        MTPA(BL) s_res,                                                         \
        MTPA(BL) c_res                                                          \
) {                                                                             \
    MTPA(BL) tmp = FN(dom_alloc_many, BL)(x->domain, x->order, 5);              \
    if (!tmp)                                                                   \
        return 1;                                                               \
                                                                                \
    /*  a = x ^ y  */                                                           \
    MTP(BL) a = tmp[0];                                                         \
    FN(dom_bool_xor, BL)(x, y, a);                                              \
                                                                                \
    /*  s = a ^ z  */                                                           \
    MTP(BL) s = tmp[1];                                                         \
    FN(dom_bool_xor, BL)(a, z, s);                                              \
                                                                                \
    /*  w = x ^ z  */                                                           \
    MTP(BL) w = tmp[2];                                                         \
    FN(dom_bool_xor, BL)(x, z, w);                                              \
                                                                                \
    /*  v = a & w  */                                                           \
    MTP(BL) v = tmp[3];                                                         \
    FN(dom_bool_and, BL)(a, w, v);                                              \
                                                                                \
    /*  c = x ^ v  */                                                           \
    MTP(BL) c = tmp[4];                                                         \
    FN(dom_bool_xor, BL)(x, v, c);                                              \
    FN(dom_bool_shl, BL)(c, 1);                                                 \
                                                                                \
    *s_res = s;                                                                 \
    *c_res = c;                                                                 \
                                                                                \
    FN(dom_free_many, BL)(tmp, 5, 0b10010u);                                    \
    asm volatile ("" ::: "memory");                                             \
    return 0;                                                                   \
}                                                                               \
                                                                                \
/* NOLINTNEXTLINE(misc-no-recursion) */                                         \
static int FN(csa_tree, BL)(                                                    \
        MTP(BL) vals[],                                                         \
        MTPA(BL) s_res,                                                         \
        MTPA(BL) c_res,                                                         \
        const uint8_t len                                                       \
) {                                                                             \
    if (len == 3) {                                                             \
        return FN(csa, BL)(vals[0], vals[1], vals[2], s_res, c_res);            \
    }                                                                           \
    const uint8_t len_min1 = len - 1;                                           \
    MTP(BL) mv = vals[0];                                                       \
                                                                                \
    MTPA(BL) tmp = FN(dom_alloc_many, BL)(mv->domain, mv->order, 2);            \
    if (!tmp)                                                                   \
        return 1;                                                               \
                                                                                \
    int err = FN(csa_tree, BL)(vals, &tmp[0], &tmp[1], len_min1);               \
    if (err) {                                                                  \
        FN(dom_free_many, BL)(tmp, 2, 0);                                       \
        return 1;                                                               \
    }                                                                           \
    err = FN(csa, BL)(tmp[0], tmp[1], vals[len_min1], s_res, c_res);            \
                                                                                \
    FN(dom_free_many, BL)(tmp, 2, 0);                                           \
    asm volatile ("" ::: "memory");                                             \
    return err;                                                                 \
}                                                                               \


#ifndef DOM_CONV_ATOB
#define DOM_CONV_ATOB(BL)                                                       \
                                                                                \
DOM_ATOB_HELPERS(BL)                                                            \
                                                                                \
/*   Converts masked shares from arithmetic to boolean domain using        */   \
/*   the high-order recursive carry-save-adder method of Liu et al.,       */   \
/*   “A Low-Latency High-Order Arithmetic to Boolean Masking Conversion”   */   \
/*   Link: https://eprint.iacr.org/2024/045.pdf                            */   \
int FN(dom_conv_atob, BL)(MT(BL) *mv) {                                         \
    if (mv->domain == DOMAIN_BOOLEAN)                                           \
        return 0;                                                               \
                                                                                \
    const uint8_t order = mv->order;                                            \
    const uint8_t share_count = mv->share_count;                                \
                                                                                \
    MTPA(BL) vals = FN(dom_mask_many, BL)                                       \
        (mv->shares, DOMAIN_BOOLEAN, order, share_count);                       \
    if (!vals)                                                                  \
        return 1;                                                               \
                                                                                \
    MTP(BL) s_res = NULL;                                                       \
    MTP(BL) c_res = NULL;                                                       \
                                                                                \
    if (share_count == 2) {                                                     \
        s_res = vals[0];                                                        \
        c_res = vals[1];                                                        \
    } else {                                                                    \
        if (FN(csa_tree, BL)(vals, &s_res, &c_res, share_count)) {              \
            FN(dom_free_many, BL)(vals, share_count, 0);                        \
            if (s_res != NULL)                                                  \
                FN(dom_free, BL)(s_res);                                        \
            if (c_res != NULL)                                                  \
                FN(dom_free, BL)(c_res);                                        \
            return 1;                                                           \
        }                                                                       \
    }                                                                           \
    MTP(BL) k_res = FN(dom_ksa_carry, BL)(s_res, c_res);                        \
    if (!k_res) {                                                               \
        FN(dom_free_many, BL)(vals, share_count, 0);                            \
        if (share_count > 2) {                                                  \
            FN(dom_free, BL)(s_res);                                            \
            FN(dom_free, BL)(c_res);                                            \
        }                                                                       \
        return 1;                                                               \
    }                                                                           \
                                                                                \
    FN(dom_bool_xor, BL)(s_res, k_res, k_res);                                  \
    FN(dom_bool_xor, BL)(c_res, k_res, k_res);                                  \
                                                                                \
    memcpy(mv->shares, k_res->shares, mv->share_bytes);                         \
    mv->domain = DOMAIN_BOOLEAN;                                                \
                                                                                \
    FN(dom_free_many, BL)(vals, share_count, 0);                                \
    FN(dom_free, BL)(k_res);                                                    \
    if (share_count > 2) {                                                      \
        FN(dom_free, BL)(s_res);                                                \
        FN(dom_free, BL)(c_res);                                                \
    }                                                                           \
    asm volatile ("" ::: "memory");                                             \
    return 0;                                                                   \
}                                                                               \

#endif //DOM_CONV_ATOB


DOM_CONV_ATOB(8)
DOM_CONV_ATOB(16)
DOM_CONV_ATOB(32)
DOM_CONV_ATOB(64)
