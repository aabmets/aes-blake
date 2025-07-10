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

#define DEFINE_DOM_TRAITS(TYPE, SHORT_TYPE)                                                                             \
template<>                                                                                                              \
struct dom_traits<TYPE> {                                                                                               \
    using mskd_t = masked_##TYPE;                                                                                       \
                                                                                                                        \
    static void      dom_free         (mskd_t* mv)                        { dom_free_##SHORT_TYPE(mv); }                \
    static mskd_t*   dom_mask         (TYPE v, domain_t d, uint8_t o)     { return dom_mask_##SHORT_TYPE(v, d, o); }    \
    static TYPE      dom_unmask       (mskd_t* mv)                        { return dom_unmask_##SHORT_TYPE(mv); }       \
    static void      dom_bool_and     (mskd_t* a, mskd_t* b, mskd_t* o)   { dom_bool_and_##SHORT_TYPE(a, b, o); }       \
    static void      dom_bool_or      (mskd_t* a, mskd_t* b, mskd_t* o)   { dom_bool_or_##SHORT_TYPE(a, b, o); }        \
    static void      dom_bool_xor     (mskd_t* a, mskd_t* b, mskd_t* o)   { dom_bool_xor_##SHORT_TYPE(a, b, o); }       \
    static void      dom_bool_not     (mskd_t* mv)                        { dom_bool_not_##SHORT_TYPE(mv); }            \
    static void      dom_bool_shr     (mskd_t* mv, uint8_t n)             { dom_bool_shr_##SHORT_TYPE(mv, n); }         \
    static void      dom_bool_shl     (mskd_t* mv, uint8_t n)             { dom_bool_shl_##SHORT_TYPE(mv, n); }         \
    static void      dom_bool_rotr    (mskd_t* mv, uint8_t n)             { dom_bool_rotr_##SHORT_TYPE(mv, n); }        \
    static void      dom_bool_rotl    (mskd_t* mv, uint8_t n)             { dom_bool_rotl_##SHORT_TYPE(mv, n); }        \
    static void      dom_arith_add    (mskd_t* a, mskd_t* b, mskd_t* o)   { dom_arith_add_##SHORT_TYPE(a, b, o); }      \
    static void      dom_arith_mult   (mskd_t* a, mskd_t* b, mskd_t* o)   { dom_arith_mult_##SHORT_TYPE(a, b, o); }     \
};                                                                                                                      \

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
        const std::function<T(T, T)>& unmasked_op,
        domain_t domain
) {
    const int order = GENERATE_COPY(range(1, 11));
    INFO("security order = " << order);

    T values[2];
    csprng_read_array(reinterpret_cast<uint8_t*>(values), sizeof(values));
    auto* mv_a = dom_traits<T>::dom_mask(values[0], domain, order);
    auto* mv_b = dom_traits<T>::dom_mask(values[1], domain, order);
    auto* mv_out = dom_traits<T>::dom_mask(0, domain, order);

    masked_op(mv_a, mv_b, mv_out);
    T unmasked = dom_traits<T>::dom_unmask(mv_out);
    T expected = unmasked_op(values[0], values[1]);
    REQUIRE(expected == unmasked);

    dom_traits<T>::dom_free(mv_a);
    dom_traits<T>::dom_free(mv_b);
    dom_traits<T>::dom_free(mv_out);
}


template<typename T>
void test_unary_operation(
        void (*masked_op)(typename dom_traits<T>::mskd_t*),
        const std::function<T(T)>& unmasked_op,
        domain_t domain
) {
    const int order = GENERATE_COPY(range(1, 11));
    INFO("security order = " << order);

    T values[1];
    csprng_read_array(reinterpret_cast<uint8_t*>(values), sizeof(values));
    auto* mv = dom_traits<T>::dom_mask(values[0], domain, order);

    masked_op(mv);
    T unmasked = dom_traits<T>::dom_unmask(mv);
    T expected = unmasked_op(values[0]);
    REQUIRE(expected == unmasked);

    dom_traits<T>::dom_free(mv);
}


template<typename T>
void test_shift_rotate_operation(
        void (*masked_op)(
            typename dom_traits<T>::mskd_t*,
            uint8_t
        ),
        const std::function<T(T, T)>& unmasked_op
) {
    const int order = GENERATE_COPY(range(1, 11));
    INFO("security order = " << order);

    T values[1];
    csprng_read_array(reinterpret_cast<uint8_t*>(values), sizeof(values));
    auto* mv = dom_traits<T>::dom_mask(values[0], DOMAIN_BOOLEAN, order);
    uint8_t offset = static_cast<uint8_t>(mv->bit_length / 2) - 1;

    masked_op(mv, offset);
    T unmasked = dom_traits<T>::dom_unmask(mv);
    T expected = unmasked_op(values[0], offset);
    REQUIRE(expected == unmasked);

    dom_traits<T>::dom_free(mv);
}


TEMPLATE_TEST_CASE("Assert DOM boolean AND works correctly",
        "[unittest][dom]", uint8_t, uint32_t, uint64_t
) {
    auto masked_op = dom_traits<TestType>::dom_bool_and;
    auto unmasked_op = [](TestType a, TestType b) { return a & b; };
    test_binary_operation<TestType>(masked_op, unmasked_op, DOMAIN_BOOLEAN);
}


TEMPLATE_TEST_CASE("Assert DOM boolean OR works correctly",
        "[unittest][dom]", uint8_t, uint32_t, uint64_t
) {
    auto masked_op = dom_traits<TestType>::dom_bool_or;
    auto unmasked_op = [](TestType a, TestType b) { return a | b; };
    test_binary_operation<TestType>(masked_op, unmasked_op, DOMAIN_BOOLEAN);
}


TEMPLATE_TEST_CASE("Assert DOM boolean XOR works correctly",
        "[unittest][dom]", uint8_t, uint32_t, uint64_t
) {
    auto masked_op = dom_traits<TestType>::dom_bool_xor;
    auto unmasked_op = [](TestType a, TestType b) { return a ^ b; };
    test_binary_operation<TestType>(masked_op, unmasked_op, DOMAIN_BOOLEAN);
}


TEMPLATE_TEST_CASE("Assert DOM boolean NOT works correctly",
        "[unittest][dom]", uint8_t, uint32_t, uint64_t
) {
    auto masked_op = dom_traits<TestType>::dom_bool_not;
    auto unmasked_op = [](TestType a) { return ~a; };
    test_unary_operation<TestType>(masked_op, unmasked_op, DOMAIN_BOOLEAN);
}


TEMPLATE_TEST_CASE("Assert DOM boolean SHR works correctly",
        "[unittest][dom]", uint8_t, uint32_t, uint64_t
) {
    auto masked_op = dom_traits<TestType>::dom_bool_shr;
    auto unmasked_op = [](TestType a, uint8_t b) { return a >> b; };
    test_shift_rotate_operation<TestType>(masked_op, unmasked_op);
}


TEMPLATE_TEST_CASE("Assert DOM boolean SHL works correctly",
        "[unittest][dom]", uint8_t, uint32_t, uint64_t
) {
    auto masked_op = dom_traits<TestType>::dom_bool_shl;
    auto unmasked_op = [](TestType a, uint8_t b) { return a << b; };
    test_shift_rotate_operation<TestType>(masked_op, unmasked_op);
}


TEMPLATE_TEST_CASE("Assert DOM boolean ROTR works correctly",
        "[unittest][dom]", uint8_t, uint32_t, uint64_t
) {
    auto masked_op = dom_traits<TestType>::dom_bool_rotr;
    auto unmasked_op = [](TestType a, uint8_t b)
        { return a >> b | a << (sizeof(TestType) * 8 - b); };
    test_shift_rotate_operation<TestType>(masked_op, unmasked_op);
}


TEMPLATE_TEST_CASE("Assert DOM boolean ROTL works correctly",
        "[unittest][dom]", uint8_t, uint32_t, uint64_t
) {
    auto masked_op = dom_traits<TestType>::dom_bool_rotl;
    auto unmasked_op = [](TestType a, uint8_t b)
        { return a << b | a >> (sizeof(TestType) * 8 - b); };
    test_shift_rotate_operation<TestType>(masked_op, unmasked_op);
}


TEMPLATE_TEST_CASE("Assert DOM arithmetic ADD works correctly",
        "[unittest][dom]", uint8_t, uint32_t, uint64_t
) {
    auto masked_op = dom_traits<TestType>::dom_arith_add;
    auto unmasked_op = [](TestType a, TestType b) { return a + b; };
    test_binary_operation<TestType>(masked_op, unmasked_op, DOMAIN_ARITHMETIC);
}


TEMPLATE_TEST_CASE("Assert DOM arithmetic MULT works correctly",
        "[unittest][dom]", uint8_t, uint32_t, uint64_t
) {
    auto masked_op = dom_traits<TestType>::dom_arith_mult;
    auto unmasked_op = [](TestType a, TestType b) { return a * b; };
    test_binary_operation<TestType>(masked_op, unmasked_op, DOMAIN_ARITHMETIC);
}
