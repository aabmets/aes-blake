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

#include <catch2/catch_all.hpp>
#include "csprng.h"
#include "masking.h"


template<typename T>
struct dom_traits;

#define DEFINE_DOM_TRAITS(TYPE, SHORT_TYPE)                                     \
template<>                                                                      \
struct dom_traits<TYPE> {                                                       \
    using mskd_t = masked_##TYPE;                                               \
    static mskd_t* dom_mask(const TYPE value, const domain_t domain)            \
        { return dom_mask_##SHORT_TYPE(value, domain); }                        \
    static TYPE dom_unmask(mskd_t* mv)                                          \
        { return dom_unmask_##SHORT_TYPE(mv); }                                 \
    static void dom_bool_and(mskd_t* ms_a, mskd_t* ms_b, mskd_t* ms_out)        \
        { dom_bool_and_##SHORT_TYPE(ms_a, ms_b, ms_out); }                      \
    static void dom_bool_or(mskd_t* ms_a, mskd_t* ms_b, mskd_t* ms_out)         \
        { dom_bool_or_##SHORT_TYPE(ms_a, ms_b, ms_out); }                       \
    static void dom_bool_xor(mskd_t* ms_a, mskd_t* ms_b, mskd_t* ms_out)        \
        { dom_bool_xor_##SHORT_TYPE(ms_a, ms_b, ms_out); }                      \
    static void dom_bool_not(mskd_t* ms)                                        \
        { dom_bool_not_##SHORT_TYPE(ms); }                                      \
    static void dom_bool_shr(mskd_t* ms, const uint8_t n)                       \
        { dom_bool_shr_##SHORT_TYPE(ms, n); }                                   \
    static void dom_bool_shl(mskd_t* ms, const uint8_t n)                       \
        { dom_bool_shl_##SHORT_TYPE(ms, n); }                                   \
    static void dom_bool_rotr(mskd_t* ms, const uint8_t n)                      \
        { dom_bool_rotr_##SHORT_TYPE(ms, n); }                                  \
    static void dom_bool_rotl(mskd_t* ms, const uint8_t n)                      \
        { dom_bool_rotl_##SHORT_TYPE(ms, n); }                                  \
    static void dom_arith_add(mskd_t* ms_a, mskd_t* ms_b, mskd_t* ms_out)       \
        { dom_arith_add_##SHORT_TYPE(ms_a, ms_b, ms_out); }                     \
    static void dom_arith_mult(mskd_t* ms_a, mskd_t* ms_b, mskd_t* ms_out)      \
        { dom_arith_mult_##SHORT_TYPE(ms_a, ms_b, ms_out); }                    \
};                                                                              \

DEFINE_DOM_TRAITS(uint8_t, u8)
DEFINE_DOM_TRAITS(uint32_t, u32)
DEFINE_DOM_TRAITS(uint64_t, u64)

#undef DEFINE_DOM_TRAITS


template<typename T>
void test_binary_operation(
        void (*masked_op)(
            typename dom_traits<T>::mskd_t*,
            typename dom_traits<T>::mskd_t*,
            typename dom_traits<T>::mskd_t*
        ),
        std::function<T(T, T)> unmasked_op,
        domain_t domain
) {
    for (int i = 0; i < 100; i++) {
        T expected[2];
        csprng_read_array((uint8_t*)(expected), sizeof(expected));
        auto* mv_a = dom_traits<T>::dom_mask(expected[0], domain);
        auto* mv_b = dom_traits<T>::dom_mask(expected[1], domain);
        auto* mv_out = dom_traits<T>::dom_mask(0, domain);
        masked_op(mv_a, mv_b, mv_out);

        T unmasked_a = dom_traits<T>::dom_unmask(mv_a);
        T unmasked_b = dom_traits<T>::dom_unmask(mv_b);
        T unmasked_out = dom_traits<T>::dom_unmask(mv_out);
        T unmasked_result = unmasked_op(expected[0], expected[1]);
        REQUIRE(unmasked_result == unmasked_out);
    }
}


template<typename T>
void test_unary_operation(
        void (*masked_op)(typename dom_traits<T>::mskd_t*),
        std::function<T(T)> unmasked_op,
        domain_t domain
) {
    for (int i = 0; i < 100; i++) {
        T expected[1];
        csprng_read_array((uint8_t*)(expected), sizeof(expected));
        auto* mv = dom_traits<T>::dom_mask(expected[0], domain);
        masked_op(mv);

        T unmasked = dom_traits<T>::dom_unmask(mv);
        T unmasked_result = unmasked_op(expected[0]);
        REQUIRE(unmasked_result == unmasked);
    }
}


template<typename T>
void test_shift_rotate_operation(
        void (*masked_op)(
            typename dom_traits<T>::mskd_t*,
            uint8_t
        ),
        std::function<T(T, T)> unmasked_op
) {
    for (int i = 0; i < 100; i++) {
        T expected[1];
        csprng_read_array((uint8_t*)(expected), sizeof(expected));
        auto* mv = dom_traits<T>::dom_mask(expected[0], DOMAIN_BOOLEAN);
        uint8_t offset = (uint8_t)(mv->bit_length / 2) - 1;
        masked_op(mv, offset);

        T unmasked = dom_traits<T>::dom_unmask(mv);
        T unmasked_result = unmasked_op(expected[0], offset);
        REQUIRE(unmasked_result == unmasked);
    }
}


TEMPLATE_TEST_CASE("2nd-order DOM boolean AND works correctly",
        "[unittest][dom]", uint8_t, uint32_t, uint64_t
) {
    auto masked_op = dom_traits<TestType>::dom_bool_and;
    auto unmasked_op = [](TestType a, TestType b) { return a & b; };
    test_binary_operation<TestType>(masked_op, unmasked_op, DOMAIN_BOOLEAN);
}


TEMPLATE_TEST_CASE("2nd-order DOM boolean OR works correctly",
        "[unittest][dom]", uint8_t, uint32_t, uint64_t
) {
    auto masked_op = dom_traits<TestType>::dom_bool_or;
    auto unmasked_op = [](TestType a, TestType b) { return a | b; };
    test_binary_operation<TestType>(masked_op, unmasked_op, DOMAIN_BOOLEAN);
}


TEMPLATE_TEST_CASE("2nd-order DOM boolean XOR works correctly",
        "[unittest][dom]", uint8_t, uint32_t, uint64_t
) {
    auto masked_op = dom_traits<TestType>::dom_bool_xor;
    auto unmasked_op = [](TestType a, TestType b) { return a ^ b; };
    test_binary_operation<TestType>(masked_op, unmasked_op, DOMAIN_BOOLEAN);
}


TEMPLATE_TEST_CASE("2nd-order DOM boolean NOT works correctly",
        "[unittest][dom]", uint8_t, uint32_t, uint64_t
) {
    auto masked_op = dom_traits<TestType>::dom_bool_not;
    auto unmasked_op = [](TestType a) { return ~a; };
    test_unary_operation<TestType>(masked_op, unmasked_op, DOMAIN_BOOLEAN);
}


TEMPLATE_TEST_CASE("2nd-order DOM boolean SHR works correctly",
        "[unittest][dom]", uint8_t, uint32_t, uint64_t
) {
    auto masked_op = dom_traits<TestType>::dom_bool_shr;
    auto unmasked_op = [](TestType a, uint8_t b) { return a >> b; };
    test_shift_rotate_operation<TestType>(masked_op, unmasked_op);
}


TEMPLATE_TEST_CASE("2nd-order DOM boolean SHL works correctly",
        "[unittest][dom]", uint8_t, uint32_t, uint64_t
) {
    auto masked_op = dom_traits<TestType>::dom_bool_shl;
    auto unmasked_op = [](TestType a, uint8_t b) { return a << b; };
    test_shift_rotate_operation<TestType>(masked_op, unmasked_op);
}


TEMPLATE_TEST_CASE("2nd-order DOM boolean ROTR works correctly",
        "[unittest][dom]", uint8_t, uint32_t, uint64_t
) {
    auto masked_op = dom_traits<TestType>::dom_bool_rotr;
    auto unmasked_op = [](TestType a, uint8_t b) { return a >> b | a << (sizeof(TestType) * 8 - b); };
    test_shift_rotate_operation<TestType>(masked_op, unmasked_op);
}


TEMPLATE_TEST_CASE("2nd-order DOM boolean ROTL works correctly",
        "[unittest][dom]", uint8_t, uint32_t, uint64_t
) {
    auto masked_op = dom_traits<TestType>::dom_bool_rotl;
    auto unmasked_op = [](TestType a, uint8_t b) { return a << b | a >> (sizeof(TestType) * 8 - b); };
    test_shift_rotate_operation<TestType>(masked_op, unmasked_op);
}


TEMPLATE_TEST_CASE("2nd-order DOM arithmetic ADD works correctly",
        "[unittest][dom]", uint8_t, uint32_t, uint64_t
) {
    auto masked_op = dom_traits<TestType>::dom_arith_add;
    auto unmasked_op = [](TestType a, TestType b) { return a + b; };
    test_binary_operation<TestType>(masked_op, unmasked_op, DOMAIN_ARITHMETIC);
}


TEMPLATE_TEST_CASE("2nd-order DOM arithmetic MULT works correctly",
        "[unittest][dom]", uint8_t, uint32_t, uint64_t
) {
    auto masked_op = dom_traits<TestType>::dom_arith_mult;
    auto unmasked_op = [](TestType a, TestType b) { return a * b; };
    test_binary_operation<TestType>(masked_op, unmasked_op, DOMAIN_ARITHMETIC);
}
