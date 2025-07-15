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
#include "masking.h"
#include "dom_types.h"
#include "dom_internal_defs.h"


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


#ifndef DOM_UTILS
#define DOM_UTILS(TYPE, BL, BIT_LENGTH)                                         \
                                                                                \
void FN(dom_free, BL)(MTP(BL) mv) {                                             \
    secure_memzero(mv, mv->total_bytes);                                        \
    aligned_free(mv);                                                           \
}                                                                               \
                                                                                \
                                                                                \
/* Note: skip_mask applies only to the first 32 elements of **mvs */            \
void FN(dom_free_many, BL)(                                                     \
        MTPA(BL) mvs,                                                           \
        const uint8_t count,                                                    \
        const uint32_t skip_mask                                                \
) {                                                                             \
    for (uint8_t i = 0; i < count; ++i) {                                       \
        if (i < 32 && (skip_mask >> i) & 1u)                                    \
            continue;                                                           \
        MTP(BL) mv = mvs[i];                                                    \
        secure_memzero(mv, mv->total_bytes);                                    \
        aligned_free(mv);                                                       \
    }                                                                           \
    aligned_free(mvs);                                                          \
}                                                                               \
                                                                                \
                                                                                \
void FN(dom_clear, BL)(MTP(BL) mv) {                                            \
    secure_memzero(mv->shares, mv->share_bytes);                                \
}                                                                               \
                                                                                \
                                                                                \
/* Note: skip_mask applies only to the first 32 elements of **mvs */            \
void FN(dom_clear_many, BL)(                                                    \
        MTPA(BL) mvs,                                                           \
        const uint8_t count,                                                    \
        const uint32_t skip_mask                                                \
) {                                                                             \
    for (uint8_t i = 0; i < count; ++i) {                                       \
        if (i < 32 && (skip_mask >> i) & 1u)                                    \
            continue;                                                           \
        MTP(BL) mv = mvs[i];                                                    \
        secure_memzero(mv->shares, mv->share_bytes);                            \
    }                                                                           \
}                                                                               \
                                                                                \
                                                                                \
MTP(BL) FN(dom_alloc, BL)(const domain_t domain, const uint8_t order)           \
{                                                                               \
    if (order == 0 || order > MAX_SEC_ORDER)                                    \
        return NULL;                                                            \
                                                                                \
    const uint8_t share_count = order + 1;                                      \
    const uint16_t share_bytes = share_count * sizeof(TYPE);                    \
    const size_t struct_size = share_bytes + sizeof(MT(BL));                    \
    const size_t align = alignof(TYPE);                                         \
    const size_t offset = align - 1;                                            \
    const size_t total_bytes = (struct_size + offset) & ~offset;                \
                                                                                \
    MTP(BL) mv = aligned_alloc(align, total_bytes);                             \
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
MTPA(BL) FN(dom_alloc_many, BL)(                                                \
        const domain_t domain,                                                  \
        const uint8_t order,                                                    \
        const uint8_t count                                                     \
) {                                                                             \
    if (order == 0 || order > MAX_SEC_ORDER || count < 2)                       \
        return NULL;                                                            \
                                                                                \
    const size_t align = alignof(TYPE);                                         \
    MTPA(BL) mvs = aligned_alloc(align, count * sizeof(*mvs));                  \
    if (!mvs)                                                                   \
        return NULL;                                                            \
                                                                                \
    for (uint8_t i = 0; i < count; ++i) {                                       \
        mvs[i] = FN(dom_alloc, BL)(domain, order);                             \
        if (!mvs[i]) {                                                          \
            FN(dom_free_many, BL)(mvs, i, 0);                                   \
            return NULL;                                                        \
        }                                                                       \
    }                                                                           \
    return mvs;                                                                 \
}                                                                               \
                                                                                \
                                                                                \
MTP(BL) FN(dom_mask, BL)(                                                       \
        const TYPE value,                                                       \
        const domain_t domain,                                                  \
        const uint8_t order                                                     \
) {                                                                             \
    if (order == 0 || order > MAX_SEC_ORDER)                                    \
        return NULL;                                                            \
                                                                                \
    MTP(BL) mv = FN(dom_alloc, BL)(domain, order);                              \
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
MTPA(BL) FN(dom_mask_many, BL)(                                                 \
        const TYPE* values,                                                     \
        const domain_t domain,                                                  \
        const uint8_t order,                                                    \
        const uint32_t count                                                    \
) {                                                                             \
    if (order == 0 || order > MAX_SEC_ORDER || count < 2)                       \
        return NULL;                                                            \
                                                                                \
    const size_t align = alignof(TYPE);                                         \
    MTPA(BL) mvs = aligned_alloc(align, count * sizeof(*mvs));                  \
    if (!mvs)                                                                   \
        return NULL;                                                            \
                                                                                \
    for (uint32_t i = 0; i < count; ++i) {                                      \
        mvs[i] = FN(dom_mask, BL)(values[i], domain, order);                    \
        if (!mvs[i]) {                                                          \
            FN(dom_free_many, BL)(mvs, i, 0);                                   \
            return NULL;                                                        \
        }                                                                       \
    }                                                                           \
    return mvs;                                                                 \
}                                                                               \
                                                                                \
                                                                                \
TYPE FN(dom_unmask, BL)(MTP(BL) mv) {                                           \
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
void FN(dom_unmask_many, BL)(MTPA(BL) mvs, TYPE* out, uint8_t count)            \
{                                                                               \
    for (uint8_t i = 0; i < count; ++i) {                                       \
        out[i] = FN(dom_unmask, BL)(mvs[i]);                                    \
    }                                                                           \
}                                                                               \
                                                                                \
                                                                                \
void FN(dom_refresh, BL)(MTP(BL) mv) {                                          \
    TYPE rnd[mv->order];                                                        \
    uint8_t order_bytes = mv->order * sizeof(TYPE);                             \
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
void FN(dom_refresh_many, BL)(MTPA(BL) mvs, uint8_t count)                      \
{                                                                               \
    for (uint8_t i = 0; i < count; ++i) {                                       \
        FN(dom_refresh, BL)(mvs[i]);                                            \
    }                                                                           \
}                                                                               \
                                                                                \
                                                                                \
MTP(BL) FN(dom_clone, BL)(const MTP(BL) mv, const bool zero_shares)             \
{                                                                               \
    const size_t align = sizeof(void *);                                        \
    MTP(BL) clone = aligned_alloc(align, mv->total_bytes);                      \
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
MTPA(BL) FN(dom_clone_many, BL)(                                                \
        const MTP(BL) mv,                                                       \
        const bool zero_shares,                                                 \
        const uint8_t count                                                     \
) {                                                                             \
    if (count < 2)                                                              \
        return NULL;                                                            \
                                                                                \
    const size_t align = alignof(TYPE);                                         \
    MTPA(BL) mvs = aligned_alloc(align, count * sizeof(*mvs));                  \
    if (!mvs)                                                                   \
        return NULL;                                                            \
                                                                                \
    for (uint8_t i = 0; i < count; ++i) {                                       \
        mvs[i] = FN(dom_clone, BL)(mv, zero_shares);                            \
        if (!mvs[i]) {                                                          \
            FN(dom_free_many, BL)(mvs, i, 0);                                   \
            return NULL;                                                        \
        }                                                                       \
    }                                                                           \
    return mvs;                                                                 \
}                                                                               \

#endif //DOM_UTILS


DOM_UTILS(uint8_t, 8, BIT_LENGTH_8)
DOM_UTILS(uint16_t, 16, BIT_LENGTH_16)
DOM_UTILS(uint32_t, 32, BIT_LENGTH_32)
DOM_UTILS(uint64_t, 64, BIT_LENGTH_64)
