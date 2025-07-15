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

#include "masking.h"
#include "dom_types.h"
#include "dom_internal_defs.h"


#ifndef DOM_TYPE_CONV_2TO1
#define DOM_CONV_TYPE_2TO1(L_TYPE, L_SHORT, S_TYPE, S_SHORT)                    \
                                                                                \
masked_##L_TYPE* dom_conv_##S_SHORT##_to_##L_SHORT(masked_##S_TYPE** mvs) {     \
    masked_##L_TYPE* mv = dom_alloc_##L_SHORT(                                  \
        mvs[0]->domain, mvs[0]->order                                           \
    );                                                                          \
    if (!mv)                                                                    \
        return NULL;                                                            \
                                                                                \
    const uint8_t share_count = mv->share_count;                                \
    const uint8_t dist = mvs[0]->bit_length;                                    \
                                                                                \
    L_TYPE* out = mv->shares;                                                   \
    S_TYPE* s0 = mvs[0]->shares;                                                \
    S_TYPE* s1 = mvs[1]->shares;                                                \
                                                                                \
    for (uint8_t i = 0; i < share_count; ++i) {                                 \
        out[i] = (L_TYPE)s1[i] << dist | s0[i];                                 \
    }                                                                           \
    return mv;                                                                  \
}                                                                               \
                                                                                \
/* NOLINTNEXTLINE(bugprone-macro-parentheses) */                                \
masked_##S_TYPE** dom_conv_##L_SHORT##_to_##S_SHORT(masked_##L_TYPE* mv) {      \
    masked_##S_TYPE** mvs = dom_alloc_many_##S_SHORT(                           \
        mv->domain, mv->order, 2                                                \
    );                                                                          \
    if (!mvs)                                                                   \
        return NULL;                                                            \
                                                                                \
    const uint8_t share_count = mv->share_count;                                \
    const uint8_t* p = (uint8_t*)mv->shares;                                    \
    const uint8_t stride = sizeof(L_TYPE);                                      \
                                                                                \
    S_TYPE* s0 = mvs[0]->shares;                                                \
    S_TYPE* s1 = mvs[1]->shares;                                                \
                                                                                \
    for (uint8_t i = 0; i < share_count; ++i, p += stride) {                    \
        s0[i] = *(S_TYPE*)(p);                                                  \
        s1[i] = *(S_TYPE*)(p + sizeof(S_TYPE));                                 \
    }                                                                           \
    return mvs;                                                                 \
}                                                                               \

#endif //DOM_TYPE_CONV_2TO1


#ifndef DOM_TYPE_CONV_4TO1
#define DOM_CONV_TYPE_4TO1(L_TYPE, L_SHORT, S_TYPE, S_SHORT)                    \
                                                                                \
masked_##L_TYPE* dom_conv_##S_SHORT##_to_##L_SHORT(masked_##S_TYPE** mvs) {     \
    masked_##L_TYPE* mv = dom_alloc_##L_SHORT(                                  \
        mvs[0]->domain, mvs[0]->order                                           \
    );                                                                          \
    if (!mv)                                                                    \
        return NULL;                                                            \
                                                                                \
    const uint8_t share_count = mv->share_count;                                \
    const uint8_t dist = mvs[0]->bit_length;                                    \
                                                                                \
    uint8_t offset1 = 1 * dist;                                                 \
    uint8_t offset2 = 2 * dist;                                                 \
    uint8_t offset3 = 3 * dist;                                                 \
                                                                                \
    L_TYPE* out = mv->shares;                                                   \
    S_TYPE* s0 = mvs[0]->shares;                                                \
    S_TYPE* s1 = mvs[1]->shares;                                                \
    S_TYPE* s2 = mvs[2]->shares;                                                \
    S_TYPE* s3 = mvs[3]->shares;                                                \
                                                                                \
    for (uint8_t i = 0; i < share_count; ++i) {                                 \
        out[i] = ((L_TYPE)s3[i] << offset3)                                     \
               | ((L_TYPE)s2[i] << offset2)                                     \
               | ((L_TYPE)s1[i] << offset1)                                     \
               | ((L_TYPE)s0[i]);                                               \
    }                                                                           \
    return mv;                                                                  \
}                                                                               \
                                                                                \
                                                                                \
/* NOLINTNEXTLINE(bugprone-macro-parentheses) */                                \
masked_##S_TYPE** dom_conv_##L_SHORT##_to_##S_SHORT(masked_##L_TYPE *mv) {      \
    masked_##S_TYPE** mvs = dom_alloc_many_##S_SHORT(                           \
        mv->domain, mv->order, 4                                                \
    );                                                                          \
    if (!mvs)                                                                   \
        return NULL;                                                            \
                                                                                \
    const uint8_t share_count = mv->share_count;                                \
    const uint8_t* p = (uint8_t*)mv->shares;                                    \
    const uint8_t stride = sizeof(L_TYPE);                                      \
                                                                                \
    uint8_t offset1 = 1 * sizeof(S_TYPE);                                       \
    uint8_t offset2 = 2 * sizeof(S_TYPE);                                       \
    uint8_t offset3 = 3 * sizeof(S_TYPE);                                       \
                                                                                \
    S_TYPE* s0 = mvs[0]->shares;                                                \
    S_TYPE* s1 = mvs[1]->shares;                                                \
    S_TYPE* s2 = mvs[2]->shares;                                                \
    S_TYPE* s3 = mvs[3]->shares;                                                \
                                                                                \
    for (uint8_t i = 0; i < share_count; ++i, p += stride) {                    \
        s0[i] = *(S_TYPE*)(p);                                                  \
        s1[i] = *(S_TYPE*)(p + offset1);                                        \
        s2[i] = *(S_TYPE*)(p + offset2);                                        \
        s3[i] = *(S_TYPE*)(p + offset3);                                        \
    }                                                                           \
    return mvs;                                                                 \
}                                                                               \

#endif //DOM_TYPE_CONV_4TO1


#ifndef DOM_TYPE_CONV_8TO1
#define DOM_CONV_TYPE_8TO1(L_TYPE, L_SHORT, S_TYPE, S_SHORT)                    \
                                                                                \
masked_##L_TYPE* dom_conv_##S_SHORT##_to_##L_SHORT(masked_##S_TYPE** mvs) {     \
    masked_##L_TYPE* mv = dom_alloc_##L_SHORT(                                  \
        mvs[0]->domain, mvs[0]->order                                           \
    );                                                                          \
    if (!mv)                                                                    \
        return NULL;                                                            \
                                                                                \
    const uint8_t share_count = mv->share_count;                                \
    const uint8_t dist = mvs[0]->bit_length;                                    \
                                                                                \
    uint8_t offset1 = 1 * dist;                                                 \
    uint8_t offset2 = 2 * dist;                                                 \
    uint8_t offset3 = 3 * dist;                                                 \
    uint8_t offset4 = 4 * dist;                                                 \
    uint8_t offset5 = 5 * dist;                                                 \
    uint8_t offset6 = 6 * dist;                                                 \
    uint8_t offset7 = 7 * dist;                                                 \
                                                                                \
    L_TYPE* out = mv->shares;                                                   \
    S_TYPE* s0 = mvs[0]->shares;                                                \
    S_TYPE* s1 = mvs[1]->shares;                                                \
    S_TYPE* s2 = mvs[2]->shares;                                                \
    S_TYPE* s3 = mvs[3]->shares;                                                \
    S_TYPE* s4 = mvs[4]->shares;                                                \
    S_TYPE* s5 = mvs[5]->shares;                                                \
    S_TYPE* s6 = mvs[6]->shares;                                                \
    S_TYPE* s7 = mvs[7]->shares;                                                \
                                                                                \
    for (uint8_t i = 0; i < share_count; ++i) {                                 \
        out[i] = ((L_TYPE)s7[i] << offset7)                                     \
               | ((L_TYPE)s6[i] << offset6)                                     \
               | ((L_TYPE)s5[i] << offset5)                                     \
               | ((L_TYPE)s4[i] << offset4)                                     \
               | ((L_TYPE)s3[i] << offset3)                                     \
               | ((L_TYPE)s2[i] << offset2)                                     \
               | ((L_TYPE)s1[i] << offset1)                                     \
               | (L_TYPE)s0[i];                                                 \
    }                                                                           \
    return mv;                                                                  \
}                                                                               \
                                                                                \
                                                                                \
/* NOLINTNEXTLINE(bugprone-macro-parentheses) */                                \
masked_##S_TYPE** dom_conv_##L_SHORT##_to_##S_SHORT(masked_##L_TYPE* mv) {      \
    masked_##S_TYPE** mvs = dom_alloc_many_##S_SHORT(                           \
        mv->domain, mv->order, 8                                                \
    );                                                                          \
    if (!mvs)                                                                   \
        return NULL;                                                            \
                                                                                \
    const uint8_t share_count = mv->share_count;                                \
    const uint8_t* p = (uint8_t*)mv->shares;                                    \
    const uint8_t stride = sizeof(L_TYPE);                                      \
                                                                                \
    uint8_t offset1 = 1 * sizeof(S_TYPE);                                       \
    uint8_t offset2 = 2 * sizeof(S_TYPE);                                       \
    uint8_t offset3 = 3 * sizeof(S_TYPE);                                       \
    uint8_t offset4 = 4 * sizeof(S_TYPE);                                       \
    uint8_t offset5 = 5 * sizeof(S_TYPE);                                       \
    uint8_t offset6 = 6 * sizeof(S_TYPE);                                       \
    uint8_t offset7 = 7 * sizeof(S_TYPE);                                       \
                                                                                \
    S_TYPE* s0 = mvs[0]->shares;                                                \
    S_TYPE* s1 = mvs[1]->shares;                                                \
    S_TYPE* s2 = mvs[2]->shares;                                                \
    S_TYPE* s3 = mvs[3]->shares;                                                \
    S_TYPE* s4 = mvs[4]->shares;                                                \
    S_TYPE* s5 = mvs[5]->shares;                                                \
    S_TYPE* s6 = mvs[6]->shares;                                                \
    S_TYPE* s7 = mvs[7]->shares;                                                \
                                                                                \
    for (uint8_t i = 0; i < share_count; ++i, p += stride) {                    \
        s0[i] = *(S_TYPE*)(p);                                                  \
        s1[i] = *(S_TYPE*)(p + offset1);                                        \
        s2[i] = *(S_TYPE*)(p + offset2);                                        \
        s3[i] = *(S_TYPE*)(p + offset3);                                        \
        s4[i] = *(S_TYPE*)(p + offset4);                                        \
        s5[i] = *(S_TYPE*)(p + offset5);                                        \
        s6[i] = *(S_TYPE*)(p + offset6);                                        \
        s7[i] = *(S_TYPE*)(p + offset7);                                        \
    }                                                                           \
    return mvs;                                                                 \
}                                                                               \

#endif //DOM_TYPE_CONV_8TO1


// 2-to-1 ratio
DOM_CONV_TYPE_2TO1(uint64_t, u64, uint32_t, u32)
DOM_CONV_TYPE_2TO1(uint32_t, u32, uint16_t, u16)
DOM_CONV_TYPE_2TO1(uint16_t, u16, uint8_t, u8)

// 4-to-1 ratio
DOM_CONV_TYPE_4TO1(uint64_t, u64, uint16_t, u16)
DOM_CONV_TYPE_4TO1(uint32_t, u32, uint8_t,  u8)

// 8-to-1 ratio
DOM_CONV_TYPE_8TO1(uint64_t, u64, uint8_t, u8)
