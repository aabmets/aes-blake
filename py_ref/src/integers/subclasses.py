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

from __future__ import annotations

import typing as t
from abc import ABC

from src.integers.base_masked_uint import BaseMaskedUint, Domain
from src.integers.base_uint import BaseUint

__all__ = [
    "Uint8",
    "Uint32",
    "Uint64",
    "BaseMaskedWideUint",
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


class BaseMaskedWideUint(BaseMaskedUint, ABC):
    def to_masked_uint8_list(self) -> list[MaskedUint8]:
        out: list[MaskedUint8] = []
        self.atob()
        share_bytes = [v.to_bytes() for v in self.shares]
        template = MaskedUint8(0, domain=Domain.BOOLEAN, order=self.order)
        for i in range(self.bit_length() // 8):
            shares = [Uint8(share_bytes[n][i]) for n in range(self.share_count)]
            clone = template.create(shares, clone=True)
            out.append(clone)
        return out


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


class MaskedUint32(BaseMaskedWideUint):
    @staticmethod
    def uint_class() -> t.Type[BaseUint]:
        return Uint32

    @staticmethod
    def bit_length() -> int:
        return Uint32.bit_length()

    @staticmethod
    def max_value() -> int:
        return Uint32.max_value()


class MaskedUint64(BaseMaskedWideUint):
    @staticmethod
    def uint_class() -> t.Type[BaseUint]:
        return Uint64

    @staticmethod
    def bit_length() -> int:
        return Uint64.bit_length()

    @staticmethod
    def max_value() -> int:
        return Uint64.max_value()
