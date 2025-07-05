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

from src.blake_keygen.base_blake_keygen import *
from src.blake_keygen.clean_blake_keygen import *
from src.integers import *

__all__ = ["MaskedBlake32", "MaskedBlake64"]


class MaskedBlake32(Blake32):
    @staticmethod
    def uint_class() -> t.Type[BaseMaskedUint]:
        return MaskedUint32

    @staticmethod
    def create_uint(value: int) -> BaseMaskedUint:
        return MaskedUint32(value, Domain.ARITHMETIC)

    @staticmethod
    def bit_length() -> int:
        return MaskedUint32.bit_length()

    @staticmethod
    def add_round_key(keygen: BaseBlake, round_keys: RoundKeys) -> None:
        keygen.mix_into_state(keygen.knc)
        block_rk = []
        for m_uint in keygen.state[4:8]:  # type: MaskedUint32
            block_rk.extend(m_uint.to_masked_uint8_list())
        round_keys.append(block_rk)


class MaskedBlake64(Blake64):
    @staticmethod
    def uint_class() -> t.Type[BaseMaskedUint]:
        return MaskedUint64

    @staticmethod
    def create_uint(value: int) -> BaseMaskedUint:
        return MaskedUint64(value, Domain.ARITHMETIC)

    @staticmethod
    def bit_length() -> int:
        return MaskedUint64.bit_length()

    @staticmethod
    def add_round_key(keygen: BaseBlake, b1_round_keys: RoundKeys, b2_round_keys: RoundKeys) -> None:
        keygen.mix_into_state(keygen.knc)
        block1_rk = []
        block2_rk = []
        for m_uint in keygen.state[4:6]:
            block1_rk.extend(m_uint.to_masked_uint8_list())
        for m_uint in keygen.state[6:8]:
            block2_rk.extend(m_uint.to_masked_uint8_list())
        b1_round_keys.append(block1_rk)
        b2_round_keys.append(block2_rk)
