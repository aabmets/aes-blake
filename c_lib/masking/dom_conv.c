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


#ifndef DOM_CONV
#define DOM_CONV(TYPE, SHORT)                                                   \
                                                                                \
int dom_conv_##SHORT(masked_##TYPE* mv, domain_t target_domain) {               \
    int(*conv)(masked_##TYPE*) = target_domain == DOMAIN_BOOLEAN                \
        ? dom_conv_atob_##SHORT                                                 \
        : dom_conv_btoa_##SHORT;                                                \
    if (!mv || (mv->domain != target_domain && conv(mv)))                       \
        return 1;                                                               \
    return 0;                                                                   \
}                                                                               \
                                                                                \
                                                                                \
int dom_conv_many_##SHORT(                                                      \
        masked_##TYPE** mvs,                                                    \
        uint8_t count,                                                          \
        domain_t target_domain                                                  \
) {                                                                             \
    int(*conv)(masked_##TYPE*) = target_domain == DOMAIN_BOOLEAN                \
        ? dom_conv_atob_##SHORT                                                 \
        : dom_conv_btoa_##SHORT;                                                \
                                                                                \
    for(uint8_t i = 0; i < count; ++i) {                                        \
        masked_##TYPE* mv = mvs[i];                                             \
        if (!mv || (mv->domain != target_domain && conv(mv))) {                 \
            return 1;                                                           \
        }                                                                       \
    }                                                                           \
    return 0;                                                                   \
}                                                                               \

#endif //DOM_CONV


DOM_CONV(uint8_t, u8)
DOM_CONV(uint32_t, u32)
DOM_CONV(uint64_t, u64)
