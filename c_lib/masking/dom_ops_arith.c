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
#include <string.h>
#include "csprng.h"
#include "dom_types.h"
#include "masking.h"


#ifndef DOM_OPS_ARITH
#define DOM_OPS_ARITH(TYPE, SHORT)                                              \
                                                                                \
int dom_arith_add_##SHORT(                                                      \
        masked_##TYPE* mv_a,                                                    \
        masked_##TYPE* mv_b,                                                    \
        masked_##TYPE* mv_out                                                   \
) {                                                                             \
    masked_##TYPE* mvs[] = { mv_a, mv_b, mv_out };                              \
    if (dom_conv_many_##SHORT(mvs, 3, DOMAIN_ARITHMETIC))                       \
        return 1;                                                               \
    if (!(mv_a->sig == mv_b->sig && mv_b->sig == mv_out->sig))                  \
        return 1;                                                               \
                                                                                \
    const TYPE* x = mv_a->shares;                                               \
    const TYPE* y = mv_b->shares;                                               \
    TYPE* out = mv_out->shares;                                                 \
    const uint8_t sc = mv_out->share_count;                                     \
    for (uint8_t i = 0; i < sc; ++i) {                                          \
        out[i] = x[i] + y[i];                                                   \
    }                                                                           \
    asm volatile ("" ::: "memory");                                             \
    return 0;                                                                   \
}                                                                               \
                                                                                \
                                                                                \
int dom_arith_sub_##SHORT(                                                      \
        masked_##TYPE* mv_a,                                                    \
        masked_##TYPE* mv_b,                                                    \
        masked_##TYPE* mv_out                                                   \
) {                                                                             \
    masked_##TYPE* mvs[] = { mv_a, mv_b, mv_out };                              \
    if (dom_conv_many_##SHORT(mvs, 3, DOMAIN_ARITHMETIC))                       \
        return 1;                                                               \
    if (!(mv_a->sig == mv_b->sig && mv_b->sig == mv_out->sig))                  \
        return 1;                                                               \
                                                                                \
    const TYPE* x = mv_a->shares;                                               \
    const TYPE* y = mv_b->shares;                                               \
    TYPE* out = mv_out->shares;                                                 \
    const uint8_t sc = mv_out->share_count;                                     \
    for (uint8_t i = 0; i < sc; ++i) {                                          \
        out[i] = x[i] - y[i];                                                   \
    }                                                                           \
    asm volatile ("" ::: "memory");                                             \
    return 0;                                                                   \
}                                                                               \
                                                                                \
                                                                                \
/*   Performs multiplication/AND logic on two masked shares    */               \
/*   using the DOM-independent secure gadget as described by   */               \
/*   Gross et al. in “Domain-Oriented Masking” (CHES 2016).    */               \
/*   Link: https://eprint.iacr.org/2016/486.pdf                */               \
int dom_arith_mult_##SHORT(                                                     \
        masked_##TYPE* mv_a,                                                    \
        masked_##TYPE* mv_b,                                                    \
        masked_##TYPE* mv_out                                                   \
) {                                                                             \
    masked_##TYPE* mvs[] = { mv_a, mv_b, mv_out };                              \
    if (dom_conv_many_##SHORT(mvs, 3, DOMAIN_ARITHMETIC))                       \
        return 1;                                                               \
    if (!(mv_a->sig == mv_b->sig && mv_b->sig == mv_out->sig))                  \
        return 1;                                                               \
                                                                                \
    const uint8_t order = mv_a->order;                                          \
    const uint8_t share_count = mv_a->share_count;                              \
    const uint16_t share_bytes = mv_a->share_bytes;                             \
    const uint32_t pair_count = (uint32_t)(share_count * order / 2);            \
    const uint32_t pair_bytes = pair_count * sizeof(TYPE);                      \
                                                                                \
    TYPE rnd[pair_count];                                                       \
    csprng_read_array((uint8_t*)rnd, pair_bytes);                               \
                                                                                \
    const TYPE* a_shares = mv_a->shares;                                        \
    const TYPE* b_shares = mv_b->shares;                                        \
    TYPE out[share_count];                                                      \
                                                                                \
    for (uint8_t i = 0; i < share_count; ++i) {                                 \
        out[i] = a_shares[i] * b_shares[i];                                     \
    }                                                                           \
    uint16_t r_idx = 0;                                                         \
    for (uint8_t i = 0; i < order; ++i) {                                       \
        for (uint8_t j = i + 1; j < share_count; ++j) {                         \
            const TYPE r = rnd[r_idx++];                                        \
            out[i] += (a_shares[i] * b_shares[j]) + r;                          \
            out[j] += (a_shares[j] * b_shares[i]) - r;                          \
        }                                                                       \
    }                                                                           \
    memcpy(mv_out->shares, out, share_bytes);                                   \
    dom_refresh_##SHORT(mv_out);                                                \
                                                                                \
    secure_memzero(rnd, pair_bytes);                                            \
    secure_memzero(out, share_bytes);                                           \
    asm volatile ("" ::: "memory");                                             \
    return 0;                                                                   \
}                                                                               \

#endif //DOM_OPS_ARITH


DOM_OPS_ARITH(uint8_t, u8)
DOM_OPS_ARITH(uint16_t, u16)
DOM_OPS_ARITH(uint32_t, u32)
DOM_OPS_ARITH(uint64_t, u64)
