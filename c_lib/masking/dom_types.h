//
// Created by MattiasAabmets on 18.06.2025.
//

#ifndef DOM_TYPES_H
#define DOM_TYPES_H

#include <limits.h>

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif


    #define N_SHARES 3  // Only 2nd-order DOM is supported

    typedef enum {
        BIT_LENGTH_8 = CHAR_BIT * sizeof(uint8_t),
        BIT_LENGTH_32 = CHAR_BIT * sizeof(uint32_t),
        BIT_LENGTH_64 = CHAR_BIT * sizeof(uint64_t)
    } bit_length_t;

    typedef enum {
        DOMAIN_BOOLEAN = 0,
        DOMAIN_ARITHMETIC = 1
    } domain_t;

    typedef struct {
        uint8_t shares[N_SHARES];
        bit_length_t bit_length;
        uint8_t share_count;
        domain_t domain;
    } masked_uint8_t;

    typedef struct {
        uint32_t shares[N_SHARES];
        bit_length_t bit_length;
        uint8_t share_count;
        domain_t domain;
    } masked_uint32_t;

    typedef struct {
        uint64_t shares[N_SHARES];
        bit_length_t bit_length;
        uint8_t share_count;
        domain_t domain;
    } masked_uint64_t;


#ifdef __cplusplus
}
#endif

#endif //DOM_TYPES_H
