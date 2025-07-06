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

from src.aes_blake import *
from src.aes_blake.parallel_aes_blake import *
from src.aes_block import *
from src.blake_keygen import *

__all__ = ["MaskedAESBlake256", "MaskedAESBlake512"]

from src.checksum import MaskedCheckSum


class MaskedAESBlake256(ParallelAESBlakeMixin, AESBlake256):
    @staticmethod
    def keygen_class() -> t.Type[MaskedBlake32]:
        return MaskedBlake32

    @staticmethod
    def aes_class() -> t.Type[MaskedAESBlock]:
        return MaskedAESBlock

    @staticmethod
    def checksum_class() -> t.Type[MaskedCheckSum]:
        return MaskedCheckSum


class MaskedAESBlake512(ParallelAESBlakeMixin, AESBlake512):
    @staticmethod
    def keygen_class() -> t.Type[MaskedBlake64]:
        return MaskedBlake64

    @staticmethod
    def aes_class() -> t.Type[MaskedAESBlock]:
        return MaskedAESBlock

    @staticmethod
    def checksum_class() -> t.Type[MaskedCheckSum]:
        return MaskedCheckSum
