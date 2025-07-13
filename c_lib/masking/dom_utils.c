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
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdalign.h>
#include "csprng.h"
#include "dom_types.h"
#include "masking.h"


#ifndef ALIGNED_ALLOC_FUNC
#define ALIGNED_ALLOC_FUNC
    #if defined(_WIN32)
        #define aligned_alloc(alignment, size) _aligned_malloc(size, alignment)
        #define aligned_free(ptr) _aligned_free(ptr)
    #else
        #define aligned_free(ptr) free(ptr)
    #endif
#endif //ALIGNED_ALLOC_FUNC


void secure_memzero(void* ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0u;
    asm volatile ("" ::: "memory");
}


/*
 *   Parametrized preprocessor macro template for all utility functions.
 */
#ifndef DOM_UTILITY_FUNCTIONS
#define DOM_UTILITY_FUNCTIONS(TYPE, SHORT, BIT_LENGTH)                          \
                                                                                \
void dom_free_##SHORT(masked_##TYPE* mv) {                                      \
    secure_memzero(mv, mv->total_bytes);                                        \
    aligned_free(mv);                                                           \
}                                                                               \
                                                                                \
                                                                                \
/* Note: skip_mask applies only to the first 32 elements of **mvs */            \
void dom_free_many_##SHORT(                                                     \
        masked_##TYPE** mvs,                                                    \
        const uint8_t count,                                                    \
        const uint32_t skip_mask                                                \
) {                                                                             \
    for (uint8_t i = 0; i < count; ++i) {                                       \
        if (i < 32 && (skip_mask >> i) & 1u)                                    \
            continue;                                                           \
        masked_##TYPE* mv = mvs[i];                                             \
        secure_memzero(mv, mv->total_bytes);                                    \
        aligned_free(mv);                                                       \
    }                                                                           \
    aligned_free(mvs);                                                          \
}                                                                               \
                                                                                \
                                                                                \
void dom_clear_##SHORT(masked_##TYPE* mv) {                                     \
    secure_memzero(mv->shares, mv->share_bytes);                                \
}                                                                               \
                                                                                \
                                                                                \
/* Note: skip_mask applies only to the first 32 elements of **mvs */            \
void dom_clear_many_##SHORT(                                                    \
        masked_##TYPE** mvs,                                                    \
        const uint8_t count,                                                    \
        const uint32_t skip_mask                                                \
) {                                                                             \
    for (uint8_t i = 0; i < count; ++i) {                                       \
        if (i < 32 && (skip_mask >> i) & 1u)                                    \
            continue;                                                           \
        masked_##TYPE* mv = mvs[i];                                             \
        secure_memzero(mv->shares, mv->share_bytes);                            \
    }                                                                           \
}                                                                               \
                                                                                \
                                                                                \
masked_##TYPE* dom_alloc_##SHORT(                                               \
        const domain_t domain,                                                  \
        const uint8_t order                                                     \
) {                                                                             \
    if (order == 0 || order > MAX_SEC_ORDER)                                    \
        return NULL;                                                            \
                                                                                \
    const uint8_t share_count = order + 1;                                      \
    const uint16_t share_bytes = share_count * sizeof(TYPE);                    \
    const size_t struct_size = share_bytes + sizeof(masked_##TYPE);             \
    const size_t align = alignof(TYPE);                                         \
    const size_t offset = align - 1;                                            \
    const size_t total_bytes = (struct_size + offset) & ~offset;                \
                                                                                \
    masked_##TYPE* mv = aligned_alloc(align, total_bytes);                      \
    if (!mv)                                                                    \
        return NULL;                                                            \
                                                                                \
    mv->bit_length = BIT_LENGTH;                                                \
    mv->total_bytes = total_bytes;                                              \
    mv->domain = domain;                                                        \
    mv->order = order;                                                          \
    mv->share_count = share_count;                                              \
    mv->share_bytes = share_bytes;                                              \
    mv->sig = (uint16_t)order << 8 | BIT_LENGTH;                                \
    secure_memzero(mv->shares, share_bytes);                                    \
    return mv;                                                                  \
}                                                                               \
                                                                                \
                                                                                \
masked_##TYPE** dom_alloc_many_##SHORT(                                         \
        const domain_t domain,                                                  \
        const uint8_t order,                                                    \
        const uint8_t count                                                     \
) {                                                                             \
    if (order == 0 || order > MAX_SEC_ORDER || count < 2)                       \
        return NULL;                                                            \
                                                                                \
    const size_t align = alignof(TYPE);                                         \
    masked_##TYPE** mvs = aligned_alloc(align, count * sizeof(*mvs));           \
    if (!mvs)                                                                   \
        return NULL;                                                            \
                                                                                \
    for (uint8_t i = 0; i < count; ++i) {                                       \
        mvs[i] = dom_alloc_##SHORT(domain, order);                              \
        if (!mvs[i]) {                                                          \
            dom_free_many_##SHORT(mvs, i, 0);                                   \
            return NULL;                                                        \
        }                                                                       \
    }                                                                           \
    return mvs;                                                                 \
}                                                                               \
                                                                                \
                                                                                \
masked_##TYPE* dom_mask_##SHORT(                                                \
        const TYPE value,                                                       \
        const domain_t domain,                                                  \
        const uint8_t order                                                     \
) {                                                                             \
    if (order == 0 || order > MAX_SEC_ORDER)                                    \
        return NULL;                                                            \
                                                                                \
    masked_##TYPE* mv = dom_alloc_##SHORT(domain, order);                       \
    if (!mv)                                                                    \
        return NULL;                                                            \
                                                                                \
    TYPE* shares = (TYPE*)mv->shares;                                           \
    csprng_read_array((uint8_t*)&shares[1], order * sizeof(TYPE));              \
                                                                                \
    TYPE masked = value;                                                        \
    if (domain == DOMAIN_BOOLEAN) {  /* XOR masking */                          \
        for (uint8_t i = 1; i < mv->share_count; ++i) {                         \
            masked ^= shares[i];                                                \
        }                                                                       \
    } else {  /* DOMAIN_ARITHMETIC - subtractive masking */                     \
        for (uint8_t i = 1; i < mv->share_count; ++i) {                         \
            masked -= shares[i];                                                \
        }                                                                       \
    }                                                                           \
    shares[0] = masked;                                                         \
    return mv;                                                                  \
}                                                                               \
                                                                                \
                                                                                \
masked_##TYPE** dom_mask_many_##SHORT(                                          \
        const TYPE* values,                                                     \
        const domain_t domain,                                                  \
        const uint8_t order,                                                    \
        const uint32_t count                                                    \
) {                                                                             \
    if (order == 0 || order > MAX_SEC_ORDER || count < 2)                       \
        return NULL;                                                            \
                                                                                \
    const size_t align = alignof(TYPE);                                         \
    masked_##TYPE** mvs = aligned_alloc(align, count * sizeof(*mvs));           \
    if (!mvs)                                                                   \
        return NULL;                                                            \
                                                                                \
    for (uint32_t i = 0; i < count; ++i) {                                      \
        mvs[i] = dom_mask_##SHORT(values[i], domain, order);                    \
        if (!mvs[i]) {                                                          \
            dom_free_many_##SHORT(mvs, i, 0);                                   \
            return NULL;                                                        \
        }                                                                       \
    }                                                                           \
    return mvs;                                                                 \
}                                                                               \
                                                                                \
                                                                                \
TYPE dom_unmask_##SHORT(masked_##TYPE* mv) {                                    \
    TYPE* shares = (TYPE*)mv->shares;                                           \
    TYPE result = shares[0];                                                    \
    if (mv->domain == DOMAIN_BOOLEAN) {  /* XOR unmasking */                    \
        for (uint8_t i = 1; i < mv->share_count; ++i) {                         \
            result ^= shares[i];                                                \
        }                                                                       \
    } else { /* DOMAIN_ARITHMETIC - additive unmasking */                       \
        for (uint8_t i = 1; i < mv->share_count; ++i) {                         \
            result += shares[i];                                                \
        }                                                                       \
    }                                                                           \
    return result;                                                              \
}                                                                               \
                                                                                \
                                                                                \
void dom_unmask_many_##SHORT(                                                   \
        masked_##TYPE** mvs,                                                    \
        TYPE* out,                                                              \
        uint8_t count                                                           \
) {                                                                             \
    for (uint8_t i = 0; i < count; ++i) {                                       \
        out[i] = dom_unmask_##SHORT(mvs[i]);                                    \
    }                                                                           \
}                                                                               \
                                                                                \
                                                                                \
void dom_refresh_##SHORT(masked_##TYPE* mv) {                                   \
    uint8_t order = mv->order;                                                  \
    TYPE rnd[order];                                                            \
    uint8_t order_bytes = order * sizeof(TYPE);                                 \
    csprng_read_array((uint8_t*)rnd, order_bytes);                              \
                                                                                \
    TYPE* shares = (TYPE*)mv->shares;                                           \
    if (mv->domain == DOMAIN_BOOLEAN) {                                         \
        for (uint8_t i = 1; i < mv->share_count; ++i) {                         \
            TYPE rand_val = rnd[i - 1];                                         \
            shares[0] ^= rand_val;                                              \
            shares[i] ^= rand_val;                                              \
        }                                                                       \
    } else { /* DOMAIN_ARITHMETIC */                                            \
        for (uint8_t i = 1; i < mv->share_count; ++i) {                         \
            TYPE rand_val = rnd[i - 1];                                         \
            shares[0] -= rand_val;                                              \
            shares[i] += rand_val;                                              \
        }                                                                       \
    }                                                                           \
    secure_memzero(rnd, order_bytes);                                           \
}                                                                               \
                                                                                \
                                                                                \
void dom_refresh_many_##SHORT(masked_##TYPE** mvs, uint8_t count) {             \
    for (uint8_t i = 0; i < count; ++i) {                                       \
        dom_refresh_##SHORT(mvs[i]);                                            \
    }                                                                           \
}                                                                               \
                                                                                \
                                                                                \
masked_##TYPE* dom_clone_##SHORT(                                               \
        const masked_##TYPE* mv,                                                \
        const bool zero_shares                                                  \
) {                                                                             \
    const size_t align = sizeof(void *);                                        \
    masked_##TYPE *clone = aligned_alloc(align, mv->total_bytes);               \
    if (!clone)                                                                 \
        return NULL;                                                            \
                                                                                \
    memcpy(clone, mv, mv->total_bytes);                                         \
    if (zero_shares)                                                            \
        secure_memzero(clone->shares, clone->share_bytes);                      \
    return clone;                                                               \
}                                                                               \
                                                                                \
                                                                                \
masked_##TYPE** dom_clone_many_##SHORT(                                         \
        const masked_##TYPE* mv,                                                \
        const bool zero_shares,                                                 \
        const uint8_t count                                                     \
) {                                                                             \
    if (count < 2)                                                              \
        return NULL;                                                            \
                                                                                \
    const size_t align = alignof(TYPE);                                         \
    masked_##TYPE** mvs = aligned_alloc(align, count * sizeof(*mvs));           \
    if (!mvs)                                                                   \
        return NULL;                                                            \
                                                                                \
    for (uint8_t i = 0; i < count; ++i) {                                       \
        mvs[i] = dom_clone_##SHORT(mv, zero_shares);                            \
        if (!mvs[i]) {                                                          \
            dom_free_many_##SHORT(mvs, i, 0);                                   \
            return NULL;                                                        \
        }                                                                       \
    }                                                                           \
    return mvs;                                                                 \
}                                                                               \

#endif //DOM_UTILITY_FUNCTIONS


/*
 *   Create utility functions for all supported types.
 */
DOM_UTILITY_FUNCTIONS(uint8_t, u8, BIT_LENGTH_8)
DOM_UTILITY_FUNCTIONS(uint16_t, u16, BIT_LENGTH_16)
DOM_UTILITY_FUNCTIONS(uint32_t, u32, BIT_LENGTH_32)
DOM_UTILITY_FUNCTIONS(uint64_t, u64, BIT_LENGTH_64)
