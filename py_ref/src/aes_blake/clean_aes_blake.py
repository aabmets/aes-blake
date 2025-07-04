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

from src.aes_block import *
from src.blake_keygen import *
from src.aes_blake.base_aes_blake import BaseAESBlake

__all__ = ["AESBlake256", "AESBlake512"]

from src.checksum import CheckSum


class AESBlake256(BaseAESBlake):
    @staticmethod
    def keygen_class() -> t.Type[Blake32]:
        return Blake32

    @staticmethod
    def aes_class() -> t.Type[AESBlock]:
        return AESBlock

    @staticmethod
    def checksum_class() -> t.Type[CheckSum]:
        return CheckSum

    @staticmethod
    def ex_cols_pattern(inverse: bool = False) -> tuple[list[int], ...]:
        enc = [0, 1, 0, 1], [1, 0, 1, 0]
        dec = [0, 1, 0, 1], [1, 0, 1, 0]
        return dec if inverse else enc


class AESBlake512(BaseAESBlake):
    @staticmethod
    def keygen_class() -> t.Type[Blake64]:
        return Blake64

    @staticmethod
    def aes_class() -> t.Type[AESBlock]:
        return AESBlock

    @staticmethod
    def checksum_class() -> t.Type[CheckSum]:
        return CheckSum

    @staticmethod
    def ex_cols_pattern(inverse: bool = False) -> tuple[list[int], ...]:
        enc = [0, 1, 2, 3], [1, 2, 3, 0], [2, 3, 0, 1], [3, 0, 1, 2]
        dec = [0, 3, 2, 1], [1, 0, 3, 2], [2, 1, 0, 3], [3, 2, 1, 0]
        return dec if inverse else enc
