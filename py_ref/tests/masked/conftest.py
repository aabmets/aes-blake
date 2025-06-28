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
from src.masked.masked_uint import *

__all__ = ["get_randomly_masked_uint"]


def get_randomly_masked_uint(
        masked_uint_cls: t.Type[BaseMaskedUint],
        domain: Domain,
        order: int
) -> tuple[int, BaseMaskedUint]:
    bit_count = masked_uint_cls.uint_class().bit_count()
    value = secrets.randbits(bit_count)
    return value, masked_uint_cls(value, order, domain)
