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
 *   We define a parametrized preprocessor macro template for all utility functions.
 */
#ifndef DOM_UTILITY_FUNCTIONS
#define DOM_UTILITY_FUNCTIONS(TYPE, FN_SUFFIX, BIT_LENGTH)                      \
                                                                                \
masked_##TYPE* dom_mask_##FN_SUFFIX(                                            \
        const TYPE value,                                                       \
        const domain_t domain                                                   \
) {                                                                             \
    const size_t alignment = sizeof(void*);                                     \
    const size_t offset = (sizeof(masked_##TYPE) + alignment - 1);              \
    const size_t aligned_bytes = offset & ~(alignment - 1);                     \
                                                                                \
    masked_##TYPE* mv = aligned_alloc(alignment, aligned_bytes);                \
    if (!mv) return NULL;                                                       \
                                                                                \
    mv->bit_length = BIT_LENGTH;                                                \
    mv->share_count = N_SHARES;                                                 \
    mv->domain = domain;                                                        \
                                                                                \
    TYPE rval[N_SHARES - 1];                                                    \
    csprng_read_array((uint8_t*)&rval, sizeof(rval));                           \
                                                                                \
    if (domain == DOMAIN_BOOLEAN) {                                             \
        mv->shares[0] = value ^ rval[0] ^ rval[1];                              \
    } else {  /* DOMAIN_ARITHMETIC */                                           \
        mv->shares[0] = (TYPE)(value + rval[0] + rval[1]);                      \
    }                                                                           \
    mv->shares[1] = rval[0];                                                    \
    mv->shares[2] = rval[1];                                                    \
    return mv;                                                                  \
}                                                                               \
                                                                                \
                                                                                \
TYPE dom_unmask_##FN_SUFFIX(masked_##TYPE* mv) {                                \
    TYPE result;                                                                \
    if (mv->domain == DOMAIN_BOOLEAN) {                                         \
        result = mv->shares[0] ^ mv->shares[1] ^ mv->shares[2];                 \
    } else {  /* DOMAIN_ARITHMETIC */                                           \
        result = mv->shares[0] - mv->shares[1] - mv->shares[2];                 \
    }                                                                           \
    aligned_free(mv);                                                           \
    return result;                                                              \
}                                                                               \
                                                                                \
                                                                                \
void dom_copy_##FN_SUFFIX(                                                      \
        const masked_##TYPE* mv_src,                                            \
        masked_##TYPE* mv_tgt                                                   \
) {                                                                             \
    mv_tgt->domain = mv_src->domain;                                            \
    mv_tgt->shares[0] = mv_src->shares[0];                                      \
    mv_tgt->shares[1] = mv_src->shares[1];                                      \
    mv_tgt->shares[2] = mv_src->shares[2];                                      \
}                                                                               \
                                                                                \
                                                                                \
void dom_refresh_mask_##FN_SUFFIX(masked_##TYPE* mv) {                          \
    TYPE rval[N_SHARES - 1];                                                    \
    csprng_read_array((uint8_t*)&rval, sizeof(rval));                           \
                                                                                \
    if (mv->domain == DOMAIN_BOOLEAN) {                                         \
        mv->shares[0] ^= rval[0] ^ rval[1];                                     \
        mv->shares[1] ^= rval[0];                                               \
        mv->shares[2] ^= rval[1];                                               \
    } else { /* DOMAIN_ARITHMETIC */                                            \
        mv->shares[0] += rval[0] + rval[1];                                     \
        mv->shares[1] += rval[0];                                               \
        mv->shares[2] += rval[1];                                               \
    }                                                                           \
}

#endif //DOM_UTILITY_FUNCTIONS


/*
 *   We use the macro to create utility functions for all supported types.
 */
DOM_UTILITY_FUNCTIONS(uint8_t, u8, BIT_LENGTH_8)
DOM_UTILITY_FUNCTIONS(uint32_t, u32, BIT_LENGTH_32)
DOM_UTILITY_FUNCTIONS(uint64_t, u64, BIT_LENGTH_64)
