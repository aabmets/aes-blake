#
#   Apache License 2.0
#
#   Copyright (c) 2024, Mattias Aabmets
#
#   The contents of this file are subject to the terms and conditions defined in the License.
#   You may not use, modify, or distribute this file except in compliance with the License.
#
#   SPDX-License-Identifier: Apache-2.0
#

import secrets
import operator as opr
from src.masked.masked_uint import *

__all__ = [
    "test_masking_unmasking",
    "test_btoa_domain_conversion"
]


def test_masking_unmasking():
    for masked_uint_cls in [MaskedUint8, MaskedUint32, MaskedUint64]:
        for domain in [Domain.BOOLEAN, Domain.ARITHMETIC]:
            for order in range(1, 11):
                bit_count = masked_uint_cls.uint_class().bit_count()
                value = secrets.randbits(bit_count)
                mv = masked_uint_cls(value, order, domain)

                assert len(mv.masks) == order

                mv.refresh_masks()

                unmasked_value = mv.masked_value
                if domain == Domain.BOOLEAN:
                    for mask in mv.masks:
                        unmasked_value ^= mask
                else:  # Domain.ARITHMETIC
                    for mask in mv.masks:
                        unmasked_value += mask

                assert value == unmasked_value == mv.unmask()


def test_btoa_domain_conversion():
    for masked_uint_cls in [MaskedUint8, MaskedUint32, MaskedUint64]:
        for order in range(1, 11):
            bit_count = masked_uint_cls.uint_class().bit_count()
            value = secrets.randbits(bit_count)
            mv = masked_uint_cls(value, order, Domain.BOOLEAN)

            assert mv.domain == Domain.BOOLEAN
            assert mv.masking_fn == opr.xor
            assert mv.unmasking_fn == opr.xor

            unmasked_value = mv.masked_value
            for mask in mv.masks:
                unmasked_value ^= mask

            assert value == unmasked_value == mv.unmask()

            mv.btoa()

            assert mv.domain == Domain.ARITHMETIC
            assert mv.masking_fn == opr.sub
            assert mv.unmasking_fn == opr.add

            unmasked_value = mv.masked_value
            for mask in mv.masks:
                unmasked_value += mask

            assert value == unmasked_value == mv.unmask()
