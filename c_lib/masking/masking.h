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

#ifdef __cplusplus
#include <cstdint>
#include <cstdbool>
extern "C" {
#else
#include <stdint.h>
#include "stdbool.h"
#endif


void secure_memzero(void *ptr, size_t len);

#define MASKING_FUNCTIONS(TYPE, SHORT)                                                                                  \
void              dom_free_##SHORT           (masked_##TYPE* mv);                                                       \
void              dom_free_many_##SHORT      (masked_##TYPE** mvs, uint8_t count, uint32_t skip_mask);                  \
                                                                                                                        \
void              dom_clear_##SHORT          (masked_##TYPE* mv);                                                       \
void              dom_clear_many_##SHORT     (masked_##TYPE** mvs, uint8_t count, uint32_t skip_mask);                  \
                                                                                                                        \
masked_##TYPE*    dom_alloc_##SHORT          (domain_t domain, uint8_t order);                                          \
masked_##TYPE**   dom_alloc_many_##SHORT     (domain_t domain, uint8_t order, uint8_t count);                           \
                                                                                                                        \
masked_##TYPE*    dom_mask_##SHORT           (const TYPE value, domain_t domain, uint8_t order);                        \
masked_##TYPE**   dom_mask_many_##SHORT      (const TYPE* values, domain_t domain, uint8_t order, uint32_t count);      \
                                                                                                                        \
TYPE              dom_unmask_##SHORT         (masked_##TYPE* mv);                                                       \
void              dom_unmask_many_##SHORT    (masked_##TYPE** mvs, TYPE* out, uint8_t count);                           \
                                                                                                                        \
void              dom_refresh_##SHORT        (masked_##TYPE* mv);                                                       \
void              dom_refresh_many_##SHORT   (masked_##TYPE** mvs, uint8_t count);                                      \
                                                                                                                        \
masked_##TYPE*    dom_clone_##SHORT          (const masked_##TYPE* mv, bool zero_shares);                               \
masked_##TYPE**   dom_clone_many_##SHORT     (const masked_##TYPE* mv, bool zero_shares, uint8_t count);                \
                                                                                                                        \
int               dom_conv_btoa_##SHORT      (masked_##TYPE* mv);                                                       \
int               dom_conv_atob_##SHORT      (masked_##TYPE* mv);                                                       \
int               dom_conv_many_##SHORT      (masked_##TYPE** mvs, uint8_t count, domain_t target_domain);              \
                                                                                                                        \
int               dom_bool_and_##SHORT       (masked_##TYPE* mv_a, masked_##TYPE* mv_b, masked_##TYPE* mv_out);         \
int               dom_bool_or_##SHORT        (masked_##TYPE* mv_a, masked_##TYPE* mv_b, masked_##TYPE* mv_out);         \
int               dom_bool_xor_##SHORT       (masked_##TYPE* mv_a, masked_##TYPE* mv_b, masked_##TYPE* mv_out);         \
int               dom_bool_not_##SHORT       (masked_##TYPE* mv);                                                       \
int               dom_bool_shr_##SHORT       (masked_##TYPE* mv, uint8_t n);                                            \
int               dom_bool_shl_##SHORT       (masked_##TYPE* mv, uint8_t n);                                            \
int               dom_bool_rotr_##SHORT      (masked_##TYPE* mv, uint8_t n);                                            \
int               dom_bool_rotl_##SHORT      (masked_##TYPE* mv, uint8_t n);                                            \
                                                                                                                        \
int               dom_arith_add_##SHORT      (masked_##TYPE* mv_a, masked_##TYPE* mv_b, masked_##TYPE* mv_out);         \
int               dom_arith_mult_##SHORT     (masked_##TYPE* mv_a, masked_##TYPE* mv_b, masked_##TYPE* mv_out);         \

MASKING_FUNCTIONS(uint8_t, u8)
MASKING_FUNCTIONS(uint32_t, u32)
MASKING_FUNCTIONS(uint64_t, u64)


#ifdef __cplusplus
}
#endif

#endif //MASKING_H
