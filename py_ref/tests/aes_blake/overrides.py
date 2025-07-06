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

from src.aes_blake import MaskedAESBlake256, MaskedAESBlake512
from src.aes_block import MaskedAESBlock
from src.blake_keygen import MaskedBlake32, MaskedBlake64
from src.checksum import MaskedCheckSum
from src.integers import (BaseMaskedUint, Domain, MaskedUint8, MaskedUint32,
                          MaskedUint64)

__all__ = [
    "MockedMaskingMethods",
    "PartiallyMockedMaskedUint8",
    "PartiallyMockedMaskedUint32",
    "PartiallyMockedMaskedUint64",
    "PartiallyMockedMaskedBlake32",
    "PartiallyMockedMaskedBlake64",
    "PartiallyMockedMaskedAESBlock",
    "PartiallyMockedMaskedCheckSum",
    "PartiallyMockedMaskedAESBlake256",
    "PartiallyMockedMaskedAESBlake512"
]


class MockedMaskingMethods(BaseMaskedUint, ABC):
    """
    We have proven in other unittests that btoa and atob algorithms
    behave correctly to their specifications, so we are able to mock
    them here to speed up the testing of the masked AESBlake cipher.
    """
    def btoa(self) -> MockedMaskingMethods:
        if self.domain != Domain.BOOLEAN:
            return self
        value = self.unmask()
        self.__init__(value, Domain.ARITHMETIC)
        return self

    def atob(self) -> MockedMaskingMethods:
        if self.domain != Domain.ARITHMETIC:
            return self
        value = self.unmask()
        self.__init__(value, Domain.BOOLEAN)
        return self


class PartiallyMockedMaskedUint8(MaskedUint8, MockedMaskingMethods):
    pass

class PartiallyMockedMaskedUint32(MaskedUint32, MockedMaskingMethods):
    pass

class PartiallyMockedMaskedUint64(MaskedUint64, MockedMaskingMethods):
    pass

class PartiallyMockedMaskedBlake32(MaskedBlake32):
    @staticmethod
    def uint_class() -> t.Type[BaseMaskedUint]:
        return PartiallyMockedMaskedUint32

    @staticmethod
    def create_uint(value: int) -> BaseMaskedUint:
        return PartiallyMockedMaskedUint32(value, Domain.ARITHMETIC)


class PartiallyMockedMaskedBlake64(MaskedBlake64):
    @staticmethod
    def uint_class() -> t.Type[BaseMaskedUint]:
        return PartiallyMockedMaskedUint64

    @staticmethod
    def create_uint(value: int) -> BaseMaskedUint:
        return PartiallyMockedMaskedUint64(value, Domain.ARITHMETIC)


class PartiallyMockedMaskedAESBlock(MaskedAESBlock):
    @staticmethod
    def uint_class() -> t.Type[BaseMaskedUint]:
        return PartiallyMockedMaskedUint8


class PartiallyMockedMaskedCheckSum(MaskedCheckSum):
    @staticmethod
    def uint_class() -> t.Type[BaseMaskedUint]:
        return PartiallyMockedMaskedUint8


class PartiallyMockedMaskedAESBlake256(MaskedAESBlake256):
    @staticmethod
    def keygen_class() -> t.Type[MaskedBlake32]:
        return PartiallyMockedMaskedBlake32

    @staticmethod
    def aes_class() -> t.Type[MaskedAESBlock]:
        return PartiallyMockedMaskedAESBlock

    @staticmethod
    def checksum_class() -> t.Type[MaskedCheckSum]:
        return PartiallyMockedMaskedCheckSum


class PartiallyMockedMaskedAESBlake512(MaskedAESBlake512):
    @staticmethod
    def keygen_class() -> t.Type[MaskedBlake64]:
        return PartiallyMockedMaskedBlake64

    @staticmethod
    def aes_class() -> t.Type[MaskedAESBlock]:
        return PartiallyMockedMaskedAESBlock

    @staticmethod
    def checksum_class() -> t.Type[MaskedCheckSum]:
        return PartiallyMockedMaskedCheckSum
