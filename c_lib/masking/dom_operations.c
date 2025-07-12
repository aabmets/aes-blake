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


/*
 *   Parametrized preprocessor macro template for all operations functions.
 */
#ifndef DOM_OPERATION_FUNCTIONS
#define DOM_OPERATION_FUNCTIONS(TYPE, SHORT)                                    \
                                                                                \
/*   Performs multiplication/AND logic on two masked shares    */               \
/*   using the DOM-independent secure gadget as described by   */               \
/*   Gross et al. in “Domain-Oriented Masking” (CHES 2016).    */               \
/*   Link: https://eprint.iacr.org/2016/486.pdf                */               \
int dom_bool_and_##SHORT(                                                       \
        masked_##TYPE* mv_a,                                                    \
        masked_##TYPE* mv_b,                                                    \
        masked_##TYPE* mv_out                                                   \
) {                                                                             \
    masked_##TYPE* mvs[] = { mv_a, mv_b, mv_out };                              \
    if (dom_conv_many_##SHORT(mvs, 3, DOMAIN_BOOLEAN))                          \
        return 1;                                                               \
    if (!(mv_a->sig == mv_b->sig && mv_b->sig == mv_out->sig))                  \
        return 1;                                                               \
                                                                                \
    const uint8_t order = mv_a->order;                                          \
    const uint8_t share_count = mv_a->share_count;                              \
    const uint32_t share_bytes = mv_a->share_bytes;                             \
    const uint32_t pair_count = (uint32_t)(share_count * order / 2);            \
    const uint32_t pair_bytes = pair_count * sizeof(TYPE);                      \
                                                                                \
    TYPE rnd[pair_count];                                                       \
    csprng_read_array((uint8_t*)rnd, pair_bytes);                               \
                                                                                \
    TYPE x[share_count], y[share_count];                                        \
    memcpy(x, mv_a->shares, share_bytes);                                       \
    memcpy(y, mv_b->shares, share_bytes);                                       \
    TYPE* out = mv_out->shares;                                                 \
                                                                                \
    for (uint8_t i = 0; i < share_count; ++i) {                                 \
        out[i] = x[i] & y[i];                                                   \
    }                                                                           \
    uint16_t r_idx = 0;                                                         \
    for (uint8_t i = 0; i < order; ++i) {                                       \
        for (uint8_t j = i + 1; j < share_count; ++j) {                         \
            const TYPE r = rnd[r_idx++];                                        \
            out[i] ^= (x[i] & y[j]) ^ r;                                        \
            out[j] ^= (x[j] & y[i]) ^ r;                                        \
        }                                                                       \
    }                                                                           \
    secure_memzero(rnd, pair_bytes);                                            \
    secure_memzero(x, share_bytes);                                             \
    secure_memzero(y, share_bytes);                                             \
    asm volatile ("" ::: "memory");                                             \
    return 0;                                                                   \
}                                                                               \
                                                                                \
                                                                                \
int dom_bool_or_##SHORT(                                                        \
        masked_##TYPE* mv_a,                                                    \
        masked_##TYPE* mv_b,                                                    \
        masked_##TYPE* mv_out                                                   \
) {                                                                             \
    if (dom_bool_and_##SHORT(mv_a, mv_b, mv_out))                               \
        return 1;                                                               \
    if (!(mv_a->sig == mv_b->sig && mv_b->sig == mv_out->sig))                  \
        return 1;                                                               \
                                                                                \
    const uint8_t share_count = mv_out->share_count;                            \
    const TYPE* x = mv_a->shares;                                               \
    const TYPE* y = mv_b->shares;                                               \
    TYPE* out = mv_out->shares;                                                 \
                                                                                \
    for (uint8_t i = 0; i < share_count; ++i) {                                 \
        out[i] ^= x[i] ^ y[i];                                                  \
    }                                                                           \
    asm volatile ("" ::: "memory");                                             \
    return 0;                                                                   \
}                                                                               \
                                                                                \
                                                                                \
int dom_bool_xor_##SHORT(                                                       \
        masked_##TYPE* mv_a,                                                    \
        masked_##TYPE* mv_b,                                                    \
        masked_##TYPE* mv_out                                                   \
) {                                                                             \
    masked_##TYPE* mvs[] = { mv_a, mv_b, mv_out };                              \
    if (dom_conv_many_##SHORT(mvs, 3, DOMAIN_BOOLEAN))                          \
        return 1;                                                               \
    if (!(mv_a->sig == mv_b->sig && mv_b->sig == mv_out->sig))                  \
        return 1;                                                               \
                                                                                \
    const TYPE* x = mv_a->shares;                                               \
    const TYPE* y = mv_b->shares;                                               \
    TYPE* out = mv_out->shares;                                                 \
    const uint8_t sc = mv_out->share_count;                                     \
    for (uint8_t i = 0; i < sc; ++i) {                                          \
        out[i] = x[i] ^ y[i];                                                   \
    }                                                                           \
    asm volatile ("" ::: "memory");                                             \
    return 0;                                                                   \
}                                                                               \
                                                                                \
                                                                                \
int dom_bool_not_##SHORT(masked_##TYPE* mv) {                                   \
    if (!mv || dom_conv_atob_##SHORT(mv))                                       \
        return 1;                                                               \
                                                                                \
    mv->shares[0] = ~mv->shares[0];                                             \
    asm volatile ("" ::: "memory");                                             \
    return 0;                                                                   \
}                                                                               \
                                                                                \
                                                                                \
int dom_bool_shr_##SHORT(masked_##TYPE* mv, uint8_t n) {                        \
    if (!mv || dom_conv_atob_##SHORT(mv))                                       \
        return 1;                                                               \
                                                                                \
    bit_length_t bl = mv->bit_length;                                           \
    n %= bl;                                                                    \
    if (n == 0)                                                                 \
        return 0;                                                               \
                                                                                \
    TYPE* s = mv->shares;                                                       \
    const uint8_t sc = mv->share_count;                                         \
                                                                                \
    for (uint8_t i = 0; i < sc; ++i) {                                          \
        s[i] >>= n;                                                             \
    }                                                                           \
    asm volatile ("" ::: "memory");                                             \
    return 0;                                                                   \
}                                                                               \
                                                                                \
                                                                                \
int dom_bool_shl_##SHORT(masked_##TYPE* mv, uint8_t n) {                        \
    if (!mv || dom_conv_atob_##SHORT(mv))                                       \
        return 1;                                                               \
                                                                                \
    bit_length_t bl = mv->bit_length;                                           \
    n %= bl;                                                                    \
    if (n == 0)                                                                 \
        return 0;                                                               \
                                                                                \
    TYPE* s = mv->shares;                                                       \
    const uint8_t sc = mv->share_count;                                         \
                                                                                \
    for (uint8_t i = 0; i < sc; ++i) {                                          \
        s[i] <<= n;                                                             \
    }                                                                           \
    asm volatile ("" ::: "memory");                                             \
    return 0;                                                                   \
}                                                                               \
                                                                                \
                                                                                \
int dom_bool_rotr_##SHORT(masked_##TYPE* mv, uint8_t n) {                       \
    if (!mv || dom_conv_atob_##SHORT(mv))                                       \
        return 1;                                                               \
                                                                                \
    bit_length_t bl = mv->bit_length;                                           \
    n %= bl;                                                                    \
    if (n == 0)                                                                 \
        return 0;                                                               \
                                                                                \
    TYPE* s = mv->shares;                                                       \
    const uint8_t sc = mv->share_count;                                         \
                                                                                \
    for (uint8_t i = 0; i < sc; ++i) {                                          \
        const TYPE v = s[i];                                                    \
        s[i] = (v >> n) | (v << (bl - n));                                      \
    }                                                                           \
    asm volatile ("" ::: "memory");                                             \
    return 0;                                                                   \
}                                                                               \
                                                                                \
                                                                                \
int dom_bool_rotl_##SHORT(masked_##TYPE* mv, uint8_t n) {                       \
    if (!mv || dom_conv_atob_##SHORT(mv))                                       \
        return 1;                                                               \
                                                                                \
    bit_length_t bl = mv->bit_length;                                           \
    n %= bl;                                                                    \
    if (n == 0)                                                                 \
        return 0;                                                               \
                                                                                \
    TYPE* s = mv->shares;                                                       \
    const uint8_t sc = mv->share_count;                                         \
                                                                                \
    for (uint8_t i = 0; i < sc; ++i) {                                          \
        const TYPE v = s[i];                                                    \
        s[i] = (v << n) | (v >> (bl - n));                                      \
    }                                                                           \
    asm volatile ("" ::: "memory");                                             \
    return 0;                                                                   \
}                                                                               \
                                                                                \
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
    const uint32_t share_bytes = mv_a->share_bytes;                             \
    const uint32_t pair_count = (uint32_t)(share_count * order / 2);            \
    const uint32_t pair_bytes = pair_count * sizeof(TYPE);                      \
                                                                                \
    TYPE rnd[pair_count];                                                       \
    csprng_read_array((uint8_t*)rnd, pair_bytes);                               \
                                                                                \
    TYPE x[share_count], y[share_count];                                        \
    memcpy(x, mv_a->shares, share_bytes);                                       \
    memcpy(y, mv_b->shares, share_bytes);                                       \
    TYPE* out = mv_out->shares;                                                 \
                                                                                \
    for (uint8_t i = 0; i < share_count; ++i) {                                 \
        out[i] = x[i] * y[i];                                                   \
    }                                                                           \
    uint16_t r_idx = 0;                                                         \
    for (uint8_t i = 0; i < order; ++i) {                                       \
        for (uint8_t j = i + 1; j < share_count; ++j) {                         \
            const TYPE r = rnd[r_idx++];                                        \
            out[i] += (x[i] * y[j]) + r;                                        \
            out[j] += (x[j] * y[i]) - r;                                        \
        }                                                                       \
    }                                                                           \
    secure_memzero(rnd, pair_bytes);                                            \
    secure_memzero(x, share_bytes);                                             \
    secure_memzero(y, share_bytes);                                             \
    asm volatile ("" ::: "memory");                                             \
    return 0;                                                                   \
}                                                                               \

#endif //DOM_OPERATION_FUNCTIONS


/*
 *   Create operations functions for all supported types.
 */
DOM_OPERATION_FUNCTIONS(uint8_t, u8)
DOM_OPERATION_FUNCTIONS(uint16_t, u16)
DOM_OPERATION_FUNCTIONS(uint32_t, u32)
DOM_OPERATION_FUNCTIONS(uint64_t, u64)
