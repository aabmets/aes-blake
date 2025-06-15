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

#ifndef BLAKE_KEYGEN_HELPERS_H
#define BLAKE_KEYGEN_HELPERS_H

#include "blake_types.h"


    void run_blake32_derive_keys_test(
        KncFunc32 knc_fn,
        DigestFunc32 digest_fn,
        DeriveFunc32 derive_fn
    );
    void run_blake64_derive_keys_test(
        KncFunc64 knc_fn,
        DigestFunc64 digest_fn,
        DeriveFunc64 derive_fn
    );

    void run_blake32_permutation_test(PermuteFunc32 permute_fn);
    void run_blake64_permutation_test(PermuteFunc64 permute_fn);

    void run_blake32_gmix_test(GmixFunc32 gmix_fn);
    void run_blake64_gmix_test(GmixFunc64 gmix_fn);

    void run_blake32_mix_state_test(MixStateFunc32 mix_state_fn);
    void run_blake64_mix_state_test(MixStateFunc64 mix_state_fn);

    void run_blake32_compute_knc_test(KncFunc32 knc_fn);
    void run_blake64_compute_knc_test(KncFunc64 knc_fn);

    void run_blake32_digest_context_test(DigestFunc32 digest_fn);
    void run_blake64_digest_context_test(DigestFunc64 digest_fn);


#endif // BLAKE_KEYGEN_HELPERS_H
