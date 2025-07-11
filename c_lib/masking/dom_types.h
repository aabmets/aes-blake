//
// Created by MattiasAabmets on 18.06.2025.
//

#ifndef DOM_TYPES_H
#define DOM_TYPES_H


#ifdef __cplusplus
#include <cstdint>
#include <climits>
extern "C" {
#else
#include <limits.h>
#include <stdint.h>
#endif


    #define MAX_SEC_ORDER  30  // Limited by share_bytes and fingerprint; higher orders are impractical anyway

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
        uint16_t sig;
        bit_length_t bit_length;
        uint32_t total_bytes;
        domain_t domain;
        uint8_t order;
        uint8_t share_count;
        uint8_t share_bytes;
        uint8_t shares[];
    } masked_uint8_t;

    typedef struct {
        uint16_t sig;
        bit_length_t bit_length;
        uint32_t total_bytes;
        domain_t domain;
        uint8_t order;
        uint8_t share_count;
        uint8_t share_bytes;
        uint32_t shares[];
    } masked_uint32_t;

    typedef struct {
        uint16_t sig;
        bit_length_t bit_length;
        uint32_t total_bytes;
        domain_t domain;
        uint8_t order;
        uint8_t share_count;
        uint8_t share_bytes;
        uint64_t shares[];
    } masked_uint64_t;


#ifdef __cplusplus
}
#endif

#endif //DOM_TYPES_H
