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

#ifndef MASKING_H
#define MASKING_H

#include "dom_types.h"
#include "dom_internal_defs.h"

#ifdef __cplusplus
#include <cstdint>
#include <cstdbool>
#include <cassert>
extern "C" {
#else
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#endif


static_assert(
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
    "Domain-object masking library requires the target platform to be little-endian"
);


void secure_memzero(void *ptr, size_t len);


// ---------------------------------------------------------------------------------------------------------------------
#define MASKING_FUNCTIONS(TYPE, BL)                                                                                     \
                                                                                                                        \
void            FN(dom_free, BL)            (MTP(BL) mv);                                                               \
void            FN(dom_clear, BL)           (MTP(BL) mv);                                                               \
MTP(BL)         FN(dom_alloc, BL)           (domain_t domain, uint8_t order);                                           \
MTP(BL)         FN(dom_mask, BL)            (const TYPE value, domain_t domain, uint8_t order);                         \
TYPE            FN(dom_unmask, BL)          (MTP(BL) mv);                                                               \
void            FN(dom_refresh, BL)         (MTP(BL) mv);                                                               \
MTP(BL)         FN(dom_clone, BL)           (const MTP(BL) mv, bool with_shares);                                       \
                                                                                                                        \
void            FN(dom_free_many, BL)       (MTPA(BL) mvs, uint8_t count, uint32_t skip_mask);                          \
void            FN(dom_clear_many, BL)      (MTPA(BL) mvs, uint8_t count, uint32_t skip_mask);                          \
MTPA(BL)        FN(dom_alloc_many, BL)      (domain_t domain, uint8_t order, uint8_t count);                            \
MTPA(BL)        FN(dom_mask_many, BL)       (const TYPE* values, domain_t domain, uint8_t order, uint32_t count);       \
void            FN(dom_unmask_many, BL)     (MTPA(BL) mvs, TYPE* out, uint8_t count);                                   \
void            FN(dom_refresh_many, BL)    (MTPA(BL) mvs, uint8_t count);                                              \
MTPA(BL)        FN(dom_clone_many, BL)      (const MTP(BL) mv, bool with_shares, uint8_t count);                        \
                                                                                                                        \
int             FN(dom_conv, BL)            (MTP(BL) mv, domain_t target_domain);                                       \
int             FN(dom_conv_many, BL)       (MTPA(BL) mvs, uint8_t count, domain_t target_domain);                      \
int             FN(dom_conv_btoa, BL)       (MTP(BL) mv);                                                               \
int             FN(dom_conv_atob, BL)       (MTP(BL) mv);                                                               \
                                                                                                                        \
MTP(BL)         FN(dom_ksa_carry, BL)       (MTP(BL) a, MTP(BL) b);                                                     \
MTP(BL)         FN(dom_ksa_borrow, BL)      (MTP(BL) a, MTP(BL) b);                                                     \
                                                                                                                        \
int             FN(dom_bool_and, BL)        (MTP(BL) a, MTP(BL) b, MTP(BL) out);                                        \
int             FN(dom_bool_or, BL)         (MTP(BL) a, MTP(BL) b, MTP(BL) out);                                        \
int             FN(dom_bool_xor, BL)        (MTP(BL) a, MTP(BL) b, MTP(BL) out);                                        \
int             FN(dom_bool_not, BL)        (MTP(BL) mv);                                                               \
int             FN(dom_bool_shr, BL)        (MTP(BL) mv, uint8_t n);                                                    \
int             FN(dom_bool_shl, BL)        (MTP(BL) mv, uint8_t n);                                                    \
int             FN(dom_bool_rotr, BL)       (MTP(BL) mv, uint8_t n);                                                    \
int             FN(dom_bool_rotl, BL)       (MTP(BL) mv, uint8_t n);                                                    \
int             FN(dom_bool_add, BL)        (MTP(BL) a, MTP(BL) b, MTP(BL) out);                                        \
int             FN(dom_bool_sub, BL)        (MTP(BL) a, MTP(BL) b, MTP(BL) out);                                        \
                                                                                                                        \
int             FN(dom_arith_add, BL)       (MTP(BL) a, MTP(BL) b, MTP(BL) out);                                        \
int             FN(dom_arith_sub, BL)       (MTP(BL) a, MTP(BL) b, MTP(BL) out);                                        \
int             FN(dom_arith_mult, BL)      (MTP(BL) a, MTP(BL) b, MTP(BL) out);                                        \


// ---------------------------------------------------------------------------------------------------------------------
#define MASKING_FUNCTIONS_CONV_TYPE(BLL, BLS)                                                                           \
                                                                                                                        \
MTP(BLL)        FN_CONV(BLS, BLL)           (MTPA(BLS) mvs);                                                            \
MTPA(BLS)       FN_CONV(BLL, BLS)           (MTP(BLL) mv);                                                              \


// ---------------------------------------------------------------------------------------------------------------------
MASKING_FUNCTIONS(uint8_t, 8)
MASKING_FUNCTIONS(uint16_t, 16)
MASKING_FUNCTIONS(uint32_t, 32)
MASKING_FUNCTIONS(uint64_t, 64)

MASKING_FUNCTIONS_CONV_TYPE(64, 32)   // 2/1 ratio
MASKING_FUNCTIONS_CONV_TYPE(32, 16)   // 2/1 ratio
MASKING_FUNCTIONS_CONV_TYPE(16, 8)    // 2/1 ratio
MASKING_FUNCTIONS_CONV_TYPE(64, 16)   // 4/1 ratio
MASKING_FUNCTIONS_CONV_TYPE(32, 8)    // 4/1 ratio
MASKING_FUNCTIONS_CONV_TYPE(64, 8)    // 8/1 ratio


#ifdef __cplusplus
}
#endif

#include "dom_internal_undefs.h"

#endif //MASKING_H
