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


#ifndef DOM_KSA
#define DOM_KSA(BL)                                                             \
                                                                                \
/* NOLINTNEXTLINE(bugprone-macro-parentheses) */                                \
MTP(BL) FN(dom_ksa_carry, BL)(MTP(BL) a, MTP(BL) b) {                           \
    MTP(BL) mvs[] = { a, b };                                                   \
    if (FN(dom_conv_many, BL)(mvs, 2, DOMAIN_BOOLEAN))                          \
        return NULL;                                                            \
                                                                                \
    MTPA(BL) clones = FN(dom_clone_many, BL)(a, false, 5);                      \
    if (!clones)                                                                \
        return NULL;                                                            \
                                                                                \
    MTP(BL) p = clones[0];                                                      \
    MTP(BL) g = clones[1];                                                      \
    MTP(BL) tmp = clones[2];                                                    \
    MTP(BL) p_shift = clones[3];                                                \
    MTP(BL) g_shift = clones[4];                                                \
                                                                                \
    FN(dom_bool_xor, BL)(a, b, p);                                              \
    FN(dom_bool_and, BL)(a, b, g);                                              \
                                                                                \
    const uint8_t bl = (uint8_t)a->bit_length;                                  \
    for (uint8_t dist = 1; dist < bl; dist <<= 1) {                             \
        secure_memzero(tmp->shares, tmp->share_bytes);                          \
        memcpy(p_shift->shares, p->shares, p->share_bytes);                     \
        memcpy(g_shift->shares, g->shares, g->share_bytes);                     \
                                                                                \
        FN(dom_bool_shl, BL)(p_shift, dist);                                    \
        FN(dom_bool_shl, BL)(g_shift, dist);                                    \
                                                                                \
        FN(dom_bool_and, BL)(p, g_shift, tmp);                                  \
        FN(dom_bool_xor, BL)(g, tmp, g);                                        \
        FN(dom_bool_and, BL)(p, p_shift, p);                                    \
    }                                                                           \
    FN(dom_bool_shl, BL)(g, 1);                                                 \
    FN(dom_free_many, BL)(clones, 5, 0b10u);                                    \
    asm volatile ("" ::: "memory");                                             \
    return g;                                                                   \
}                                                                               \
                                                                                \
                                                                                \
/* NOLINTNEXTLINE(bugprone-macro-parentheses) */                                \
MTP(BL) FN(dom_ksa_borrow, BL)(MTP(BL) a, MTP(BL) b) {                          \
    MTP(BL) mvs[] = { a, b };                                                   \
    if (FN(dom_conv_many, BL)(mvs, 2, DOMAIN_BOOLEAN))                          \
        return NULL;                                                            \
                                                                                \
    MTPA(BL) clones = FN(dom_clone_many, BL)(a, false, 6);                      \
    if (!clones)                                                                \
        return NULL;                                                            \
                                                                                \
    MTP(BL) p = clones[0];                                                      \
    MTP(BL) g = clones[1];                                                      \
    MTP(BL) tmp = clones[2];                                                    \
    MTP(BL) p_shift = clones[3];                                                \
    MTP(BL) g_shift = clones[4];                                                \
    MTP(BL) a_inv = clones[5];                                                  \
                                                                                \
    FN(dom_bool_not, BL)(a_inv);                                                \
    FN(dom_bool_xor, BL)(a_inv, b, p);                                          \
    FN(dom_bool_and, BL)(a_inv, b, g);                                          \
                                                                                \
    const uint8_t bl = (uint8_t)a->bit_length;                                  \
    for (uint8_t dist = 1; dist < bl; dist <<= 1) {                             \
        secure_memzero(tmp->shares, tmp->share_bytes);                          \
        memcpy(p_shift->shares, p->shares, p->share_bytes);                     \
        memcpy(g_shift->shares, g->shares, g->share_bytes);                     \
                                                                                \
        FN(dom_bool_shl, BL)(p_shift, dist);                                    \
        FN(dom_bool_shl, BL)(g_shift, dist);                                    \
                                                                                \
        FN(dom_bool_and, BL)(p, g_shift, tmp);                                  \
        FN(dom_bool_and, BL)(g, tmp, g_shift);                                  \
        FN(dom_bool_xor, BL)(g, tmp, g);                                        \
        FN(dom_bool_xor, BL)(g, g_shift, g);                                    \
        FN(dom_bool_and, BL)(p, p_shift, p);                                    \
    }                                                                           \
    FN(dom_bool_shl, BL)(g, 1);                                                 \
    FN(dom_free_many, BL)(clones, 6, 0b10u);                                    \
    asm volatile ("" ::: "memory");                                             \
    return g;                                                                   \
}                                                                               \

#endif //DOM_KSA


DOM_KSA(8)
DOM_KSA(16)
DOM_KSA(32)
DOM_KSA(64)
