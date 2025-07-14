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


#ifndef DOM_KSA
#define DOM_KSA(TYPE, SHORT)                                                    \
                                                                                \
/* NOLINTNEXTLINE(bugprone-macro-parentheses) */                                \
masked_##TYPE* dom_ksa_carry_##SHORT(masked_##TYPE* a, masked_##TYPE* b) {      \
    masked_##TYPE* mvs[] = { a, b };                                            \
    if (dom_conv_many_##SHORT(mvs, 2, DOMAIN_BOOLEAN))                          \
        return NULL;                                                            \
    if (a->sig != b->sig)                                                       \
        return NULL;                                                            \
                                                                                \
    masked_##TYPE** clones = dom_clone_many_##SHORT(a, false, 5);               \
    if (!clones)                                                                \
        return NULL;                                                            \
                                                                                \
    masked_##TYPE* p = clones[0];                                               \
    masked_##TYPE* g = clones[1];                                               \
    masked_##TYPE* tmp = clones[2];                                             \
    masked_##TYPE* p_shift = clones[3];                                         \
    masked_##TYPE* g_shift = clones[4];                                         \
                                                                                \
    dom_bool_xor_##SHORT(a, b, p);                                              \
    dom_bool_and_##SHORT(a, b, g);                                              \
                                                                                \
    const uint8_t bl = (uint8_t)a->bit_length;                                  \
    for (uint8_t dist = 1; dist < bl; dist <<= 1) {                             \
        secure_memzero(tmp->shares, tmp->share_bytes);                          \
        memcpy(p_shift->shares, p->shares, p->share_bytes);                     \
        memcpy(g_shift->shares, g->shares, g->share_bytes);                     \
                                                                                \
        dom_bool_shl_##SHORT(p_shift, dist);                                    \
        dom_bool_shl_##SHORT(g_shift, dist);                                    \
                                                                                \
        dom_bool_and_##SHORT(p, g_shift, tmp);                                  \
        dom_bool_xor_##SHORT(g, tmp, g);                                        \
        dom_bool_and_##SHORT(p, p_shift, p);                                    \
    }                                                                           \
    dom_bool_shl_##SHORT(g, 1);                                                 \
    dom_free_many_##SHORT(clones, 5, 0b10u);                                    \
    asm volatile ("" ::: "memory");                                             \
    return g;                                                                   \
}                                                                               \
                                                                                \
                                                                                \
/* NOLINTNEXTLINE(bugprone-macro-parentheses) */                                \
masked_##TYPE* dom_ksa_borrow_##SHORT(masked_##TYPE* a, masked_##TYPE* b) {     \
    masked_##TYPE* mvs[] = { a, b };                                            \
    if (dom_conv_many_##SHORT(mvs, 2, DOMAIN_BOOLEAN))                          \
        return NULL;                                                            \
    if (a->sig != b->sig)                                                       \
        return NULL;                                                            \
                                                                                \
    masked_##TYPE** clones = dom_clone_many_##SHORT(a, false, 6);               \
    if (!clones)                                                                \
        return NULL;                                                            \
                                                                                \
    masked_##TYPE* p = clones[0];                                               \
    masked_##TYPE* g = clones[1];                                               \
    masked_##TYPE* tmp = clones[2];                                             \
    masked_##TYPE* p_shift = clones[3];                                         \
    masked_##TYPE* g_shift = clones[4];                                         \
    masked_##TYPE* a_inv = clones[5];                                           \
                                                                                \
    dom_bool_not_##SHORT(a_inv);                                                \
    dom_bool_xor_##SHORT(a_inv, b, p);                                          \
    dom_bool_and_##SHORT(a_inv, b, g);                                          \
                                                                                \
    const uint8_t bl = (uint8_t)a->bit_length;                                  \
    for (uint8_t dist = 1; dist < bl; dist <<= 1) {                             \
        secure_memzero(tmp->shares, tmp->share_bytes);                          \
        memcpy(p_shift->shares, p->shares, p->share_bytes);                     \
        memcpy(g_shift->shares, g->shares, g->share_bytes);                     \
                                                                                \
        dom_bool_shl_##SHORT(p_shift, dist);                                    \
        dom_bool_shl_##SHORT(g_shift, dist);                                    \
                                                                                \
        dom_bool_and_##SHORT(p, g_shift, tmp);                                  \
        dom_bool_and_##SHORT(g, tmp, g_shift);                                  \
        dom_bool_xor_##SHORT(g, tmp, g);                                        \
        dom_bool_xor_##SHORT(g, g_shift, g);                                    \
        dom_bool_and_##SHORT(p, p_shift, p);                                    \
    }                                                                           \
    dom_bool_shl_##SHORT(g, 1);                                                 \
    dom_free_many_##SHORT(clones, 6, 0b10u);                                    \
    asm volatile ("" ::: "memory");                                             \
    return g;                                                                   \
}                                                                               \

#endif //DOM_KSA


DOM_KSA(uint8_t, u8)
DOM_KSA(uint16_t, u16)
DOM_KSA(uint32_t, u32)
DOM_KSA(uint64_t, u64)
