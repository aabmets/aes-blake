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
from src.integers.base_uint import BaseUint
from src.integers.base_masked_uint import BaseMaskedUint

__all__ = [
    "Uint8",
    "Uint32",
    "Uint64",
    "MaskedUint8",
    "MaskedUint32",
    "MaskedUint64"
]


class Uint8(BaseUint):
    @staticmethod
    def bit_length() -> int:
        return 8

    @staticmethod
    def max_value() -> int:
        return 0x_FF


class Uint32(BaseUint):
    @staticmethod
    def bit_length() -> int:
        return 32

    @staticmethod
    def max_value() -> int:
        return 0x_FF_FF_FF_FF


class Uint64(BaseUint):
    @staticmethod
    def bit_length() -> int:
        return 64

    @staticmethod
    def max_value() -> int:
        return 0x_FF_FF_FF_FF_FF_FF_FF_FF


class MaskedUint8(BaseMaskedUint):
    @staticmethod
    def uint_class() -> t.Type[BaseUint]:
        return Uint8

    @staticmethod
    def bit_length() -> int:
        return Uint8.bit_length()

    @staticmethod
    def max_value() -> int:
        return Uint8.max_value()


class MaskedUint32(BaseMaskedUint):
    @staticmethod
    def uint_class() -> t.Type[BaseUint]:
        return Uint32

    @staticmethod
    def bit_length() -> int:
        return Uint32.bit_length()

    @staticmethod
    def max_value() -> int:
        return Uint32.max_value()


class MaskedUint64(BaseMaskedUint):
    @staticmethod
    def uint_class() -> t.Type[BaseUint]:
        return Uint64

    @staticmethod
    def bit_length() -> int:
        return Uint64.bit_length()

    @staticmethod
    def max_value() -> int:
        return Uint64.max_value()
