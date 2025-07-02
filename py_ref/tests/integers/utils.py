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
import secrets
from src.integers import *

__all__ = ["get_randomly_masked_uint", "get_many_randomly_masked_uints"]


def get_randomly_masked_uint(
        cls: t.Type[BaseMaskedUint],
        domain: Domain,
        order: int
) -> tuple[BaseUint, BaseMaskedUint]:
    bit_count = cls.uint_class().bit_length()
    value = secrets.randbits(bit_count)
    return cls.uint_class()(value), cls(value, order, domain)


def get_many_randomly_masked_uints(
        cls: t.Type[BaseMaskedUint],
        domain: Domain,
        order: int,
        *,
        count: int = 3
) -> tuple[list[BaseUint], list[BaseMaskedUint]]:
    values, mvs = [], []
    for _ in range(count):
        value, mv = get_randomly_masked_uint(cls, domain, order)
        values.append(value)
        mvs.append(mv)
    return values, mvs
