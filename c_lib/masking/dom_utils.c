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
#include "csprng.h"
#include "dom_types.h"


#ifndef ALIGNED_ALLOC_FUNC
#define ALIGNED_ALLOC_FUNC
    #if defined(_WIN32)
        #define aligned_alloc(alignment, size) _aligned_malloc(size, alignment)
        #define aligned_free(ptr) _aligned_free(ptr)
    #else
        #define aligned_free(ptr) free(ptr)
    #endif
#endif //ALIGNED_ALLOC_FUNC


/*
 *   Parametrized preprocessor macro template for all utility functions.
 */
#ifndef DOM_UTILITY_FUNCTIONS
#define DOM_UTILITY_FUNCTIONS(TYPE, FN_SUFFIX, BIT_LENGTH)                      \
                                                                                \
masked_##TYPE *dom_alloc_##FN_SUFFIX(const uint8_t share_count) {               \
    const size_t share_bytes = share_count * sizeof(TYPE);                      \
    const size_t struct_size = share_bytes + sizeof(masked_##TYPE);             \
    const size_t alignment = sizeof(void*);                                     \
    const size_t offset = alignment - 1;                                        \
    const size_t total_bytes = (struct_size + offset) & ~offset;                \
    masked_##TYPE *mv = aligned_alloc(alignment, total_bytes);                  \
    return mv ? mv : NULL;                                                      \
}                                                                               \
                                                                                \
void dom_free_##FN_SUFFIX(masked_##TYPE *mv) {                                  \
    aligned_free(mv);                                                           \
}                                                                               \
                                                                                \
masked_##TYPE *dom_mask_##FN_SUFFIX(                                            \
        const TYPE value,                                                       \
        const domain_t domain,                                                  \
        const uint8_t order                                                     \
) {                                                                             \
    const uint8_t share_count = order + 1;                                      \
    masked_##TYPE *mv = dom_alloc_##FN_SUFFIX(share_count);                     \
    if (!mv) return NULL;                                                       \
                                                                                \
    mv->domain = domain;                                                        \
    mv->order = order;                                                          \
    mv->share_count = share_count;                                              \
    mv->bit_length = BIT_LENGTH;                                                \
                                                                                \
    TYPE *shares = (TYPE*)mv->shares;                                           \
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
TYPE dom_unmask_##FN_SUFFIX(masked_##TYPE *mv) {                                \
    TYPE *shares = (TYPE*)mv->shares;                                           \
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
masked_##TYPE *dom_clone_##FN_SUFFIX(const masked_##TYPE *mv) {                 \
    masked_##TYPE *clone = dom_alloc_##FN_SUFFIX(mv->share_count);              \
    if (!mv) return NULL;                                                       \
                                                                                \
    clone->domain = mv->domain;                                                 \
    clone->order = mv->order;                                                   \
    clone->share_count = mv->share_count;                                       \
    clone->bit_length = mv->bit_length;                                         \
                                                                                \
    for (uint8_t i = 0; i < mv->share_count; ++i) {                             \
        clone->shares[i] = mv->shares[i];                                       \
    }                                                                           \
    return clone;                                                               \
}                                                                               \
                                                                                \
                                                                                \
void dom_refresh_mask_##FN_SUFFIX(masked_##TYPE *mv) {                          \
    TYPE *shares = (TYPE*)mv->shares;                                           \
    TYPE rnd[mv->order];                                                        \
    uint32_t rnd_size = mv->order * sizeof(TYPE);                               \
    csprng_read_array((uint8_t*)rnd, rnd_size);                                 \
                                                                                \
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
}                                                                               \

#endif //DOM_UTILITY_FUNCTIONS


/*
 *   Create utility functions for all supported types.
 */
DOM_UTILITY_FUNCTIONS(uint8_t, u8, BIT_LENGTH_8)
DOM_UTILITY_FUNCTIONS(uint32_t, u32, BIT_LENGTH_32)
DOM_UTILITY_FUNCTIONS(uint64_t, u64, BIT_LENGTH_64)
