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
#include <cmath>
#include <vector>
#include <cstddef>
#include <array>
#include "csprng.h"


// Helper function to read csprng samples only once
std::vector<unsigned char> getCsprngSamples(const std::size_t numSamples) {
    static std::vector<unsigned char> samples;
    if (samples.empty()) {
        constexpr std::size_t TOTAL_SAMPLES = 300000;
        samples.resize(TOTAL_SAMPLES);

        csprng_read_array(
            samples.data(),
            static_cast<uint32_t>(samples.size())
        );
    }

    if (numSamples < samples.size()) {
        using DiffType = std::vector<unsigned char>::difference_type;
        const auto count = static_cast<DiffType>(numSamples);
        return {samples.begin(), samples.begin() + count};
    }
    return samples;
}


TEST_CASE("CSPRNG generated data passes Shannon entropy estimation", "[csprng]") {
    constexpr int N_SAMPLES = 100000;
    constexpr int ALPHABET_SIZE = 256;
    constexpr double MIN_ENTROPY = 7.99;

    const auto &samples = getCsprngSamples(N_SAMPLES);

    unsigned int counts[ALPHABET_SIZE] = {};
    for (const unsigned char sample : samples) {
        counts[sample]++;
    }

    double entropy = 0.0;
    for (const unsigned int count : counts) {
        if (count > 0) {
            const double p = static_cast<double>(count) / N_SAMPLES;
            entropy -= p * (std::log(p) / std::log(2.0));
        }
    }

    INFO("Shannon entropy: " << entropy << " bits per byte");
    REQUIRE(entropy > MIN_ENTROPY);
}


TEST_CASE("CSPRNG generated data passes serial correlation test", "[csprng]") {
    constexpr int N_SAMPLES = 100000;
    constexpr double MAX_SERIAL_CORR = 0.01;

    const auto &samples = getCsprngSamples(N_SAMPLES);

    double sum = 0;
    double sum_sq = 0;
    double sum_prod = 0;
    for (int i = 0; i < N_SAMPLES; ++i) {
        const int xi = samples[i];
        const int x_next = samples[(i + 1) % N_SAMPLES];
        sum += xi;
        sum_sq += xi * xi;
        sum_prod += xi * x_next;
    }

    const double numerator = N_SAMPLES * sum_prod - sum * sum;
    const double denominator = N_SAMPLES * sum_sq - sum * sum;
    const double serial_corr = numerator / denominator;

    INFO("Serial correlation: " << serial_corr);
    REQUIRE(std::fabs(serial_corr) < MAX_SERIAL_CORR);
}


TEST_CASE("CSPRNG generated data passes Maurer's universal statistical test", "[csprng]") {
    constexpr int L = 8;
    constexpr int Q = 2560;  // 10 × 2^L
    constexpr int K = 256000;  // 1000 × 2^L
    constexpr int N_SAMPLES = Q + K;
    constexpr double MIN_P_VALUE = 0.99;

    const auto &samples = getCsprngSamples(N_SAMPLES);

    std::array<int, 1 << L> last{};
    for (int i = 1; i <= Q; ++i) {
        last[samples[i - 1]] = i;
    }

    double sum_log2 = 0.0;
    for (int i = Q + 1; i <= Q + K; ++i) {
        const unsigned char v = samples[i - 1];
        const int dist = i - last[v];
        sum_log2 += std::log2(static_cast<double>(dist));
        last[v] = i;
    }

    const double fn = sum_log2 / K;
    constexpr double expected_mean = 7.1836656;
    constexpr double variance = 3.238;
    const double p_value = std::erfc(
        std::abs(fn - expected_mean) / std::sqrt(2.0 * variance)
    );

    INFO("Maurer fn: " << fn << ", p-value: " << p_value);
    REQUIRE(p_value > MIN_P_VALUE);
}
