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

import typing as t
import pytest
import operator as opr
from src.masked.masked_uint import *
from tests.masked.conftest import *

__all__ = [
    "test_masking_unmasking",
    "test_btoa_domain_conversion"
]


@pytest.mark.parametrize("cls", [MaskedUint8, MaskedUint32, MaskedUint64])
@pytest.mark.parametrize("domain", [Domain.BOOLEAN, Domain.ARITHMETIC])
@pytest.mark.parametrize("order", list(range(1, 11)))
def test_masking_unmasking(cls, domain, order):
    value, mv = get_randomly_masked_uint(cls, domain, order)

    def assert_unmasking():
        assert len(mv.masks) == order
        unmasking_fn = opr.xor if domain == Domain.BOOLEAN else opr.add
        unmasked_value = mv.masked_value
        for mask in mv.masks:
            unmasked_value = unmasking_fn(unmasked_value, mask)
        assert value == unmasked_value == mv.unmask()

    assert_unmasking()
    mv.refresh_masks()
    assert_unmasking()


@pytest.mark.parametrize("cls", [MaskedUint8, MaskedUint32, MaskedUint64])
@pytest.mark.parametrize("order", list(range(1, 11)))
def test_btoa_domain_conversion(cls, order):
    value, mv = get_randomly_masked_uint(cls, Domain.BOOLEAN, order)

    def assert_unmasking(domain: Domain, unmasking_fn: t.Callable):
        assert mv.domain == domain
        assert mv.unmasking_fn == unmasking_fn
        unmasked_value = mv.masked_value
        for mask in mv.masks:
            unmasked_value = unmasking_fn(unmasked_value, mask)
        assert value == unmasked_value == mv.unmask()

    assert_unmasking(Domain.BOOLEAN, opr.xor)
    mv.btoa()
    assert_unmasking(Domain.ARITHMETIC, opr.add)


@pytest.mark.parametrize("cls", [MaskedUint8, MaskedUint32, MaskedUint64])
@pytest.mark.parametrize("order", list(range(1, 11)))
def test_boolean_and(cls, order):
    values, mvs = get_many_randomly_masked_uints(cls, Domain.BOOLEAN, order)

    expected = values[0] & values[1] & values[2]
    result = mvs[0] & mvs[1] & mvs[2]
    assert expected == result.unmask()


@pytest.mark.parametrize("cls", [MaskedUint8, MaskedUint32, MaskedUint64])
@pytest.mark.parametrize("order", list(range(1, 11)))
def test_boolean_or(cls, order):
    values, mvs = get_many_randomly_masked_uints(cls, Domain.BOOLEAN, order)

    expected = values[0] | values[1] | values[2]
    result = mvs[0] | mvs[1] | mvs[2]
    assert expected == result.unmask()
