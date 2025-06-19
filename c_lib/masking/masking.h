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
extern "C" {
#else
#include <stdint.h>
#endif


    masked_uint8_t * dom_mask_u8 (uint8_t value, domain_t domain);
    masked_uint32_t * dom_mask_u32 (uint32_t value, domain_t domain);
    masked_uint64_t * dom_mask_u64 (uint64_t value, domain_t domain);

    uint8_t dom_unmask_u8 (masked_uint8_t * ms);
    uint32_t dom_unmask_u32 (masked_uint32_t * ms);
    uint64_t dom_unmask_u64 (masked_uint64_t * ms);

    void dom_copy_u8 (masked_uint8_t * mv_src, masked_uint8_t * mv_tgt);
    void dom_copy_u32 (masked_uint32_t * mv_src, masked_uint32_t * mv_tgt);
    void dom_copy_u64 (masked_uint64_t * mv_src, masked_uint64_t * mv_tgt);

    void dom_refresh_mask_u8 (masked_uint8_t * ms);
    void dom_refresh_mask_u32 (masked_uint32_t * ms);
    void dom_refresh_mask_u64 (masked_uint64_t * ms);

    void dom_conv_btoa_u8 (masked_uint8_t * ms);
    void dom_conv_btoa_u32 (masked_uint32_t * ms);
    void dom_conv_btoa_u64 (masked_uint64_t * ms);

    void dom_conv_atob_u8 (masked_uint8_t * ms);
    void dom_conv_atob_u32 (masked_uint32_t * ms);
    void dom_conv_atob_u64 (masked_uint64_t * ms);

    void dom_bool_and_u8 (masked_uint8_t * ms_a, masked_uint8_t * ms_b, masked_uint8_t * ms_out);
    void dom_bool_and_u32 (masked_uint32_t * ms_a, masked_uint32_t * ms_b, masked_uint32_t * ms_out);
    void dom_bool_and_u64 (masked_uint64_t * ms_a, masked_uint64_t * ms_b, masked_uint64_t * ms_out);

    void dom_bool_or_u8 (masked_uint8_t * ms_a, masked_uint8_t * ms_b, masked_uint8_t * ms_out);
    void dom_bool_or_u32 (masked_uint32_t * ms_a, masked_uint32_t * ms_b, masked_uint32_t * ms_out);
    void dom_bool_or_u64 (masked_uint64_t * ms_a, masked_uint64_t * ms_b, masked_uint64_t * ms_out);

    void dom_bool_xor_u8 (masked_uint8_t * ms_a, masked_uint8_t * ms_b, masked_uint8_t * ms_out);
    void dom_bool_xor_u32 (masked_uint32_t * ms_a, masked_uint32_t * ms_b, masked_uint32_t * ms_out);
    void dom_bool_xor_u64 (masked_uint64_t * ms_a, masked_uint64_t * ms_b, masked_uint64_t * ms_out);

    void dom_bool_not_u8 (masked_uint8_t * ms);
    void dom_bool_not_u32 (masked_uint32_t * ms);
    void dom_bool_not_u64 (masked_uint64_t * ms);

    void dom_bool_shr_u8 (masked_uint8_t * ms, uint8_t n);
    void dom_bool_shr_u32 (masked_uint32_t * ms, uint8_t n);
    void dom_bool_shr_u64 (masked_uint64_t * ms, uint8_t n);

    void dom_bool_shl_u8 (masked_uint8_t * ms, uint8_t n);
    void dom_bool_shl_u32 (masked_uint32_t * ms, uint8_t n);
    void dom_bool_shl_u64 (masked_uint64_t * ms, uint8_t n);

    void dom_bool_rotr_u8 (masked_uint8_t * ms, uint8_t n);
    void dom_bool_rotr_u32 (masked_uint32_t * ms, uint8_t n);
    void dom_bool_rotr_u64 (masked_uint64_t * ms, uint8_t n);

    void dom_bool_rotl_u8 (masked_uint8_t * ms, uint8_t n);
    void dom_bool_rotl_u32 (masked_uint32_t * ms, uint8_t n);
    void dom_bool_rotl_u64 (masked_uint64_t * ms, uint8_t n);

    void dom_arith_add_u8 (masked_uint8_t * ms_a, masked_uint8_t * ms_b, masked_uint8_t * ms_out);
    void dom_arith_add_u32 (masked_uint32_t * ms_a, masked_uint32_t * ms_b, masked_uint32_t * ms_out);
    void dom_arith_add_u64 (masked_uint64_t * ms_a, masked_uint64_t * ms_b, masked_uint64_t * ms_out);

    void dom_arith_mult_u8 (masked_uint8_t * ms_a, masked_uint8_t * ms_b, masked_uint8_t * ms_out);
    void dom_arith_mult_u32 (masked_uint32_t * ms_a, masked_uint32_t * ms_b, masked_uint32_t * ms_out);
    void dom_arith_mult_u64 (masked_uint64_t * ms_a, masked_uint64_t * ms_b, masked_uint64_t * ms_out);


#ifdef __cplusplus
}
#endif

#endif //MASKING_H
