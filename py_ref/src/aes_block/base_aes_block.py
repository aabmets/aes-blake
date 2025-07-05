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
from abc import ABC, abstractmethod
from collections.abc import Generator
from copy import deepcopy

from src.integers import *
from src.blake_keygen import RoundKeys

__all__ = ["BaseAESBlock"]


class BaseAESBlock(ABC):
    @staticmethod
    @abstractmethod
    def uint_class() -> t.Type[BaseUint] | t.Type[BaseMaskedUint]: ...

    @property
    @abstractmethod
    def output(self) -> bytes: ...

    @abstractmethod
    def sub_bytes(self) -> None: ...

    @abstractmethod
    def inv_sub_bytes(self) -> None: ...

    def __init__(self, data: bytes | t.Iterable[BaseUint], round_keys: RoundKeys) -> None:
        if len(data) != 16:
            raise IndexError(
                "AES block must receive a data block of "
                f"length 16 instead of length {len(data)}"
            )
        uint = self.uint_class()
        self.state = [uint(s) if isinstance(s, int) else s for s in data]
        self.n_rounds = len(round_keys) - 1
        self.round_keys = round_keys

    def encrypt(self) -> Generator[bool, None, None]:
        self.add_round_key(0)
        for i in range(1, self.n_rounds):
            yield True  # exchange columns
            self.sub_bytes()
            self.shift_rows()
            self.mix_columns()
            self.add_round_key(i)
        self.sub_bytes()
        self.shift_rows()
        self.add_round_key(self.n_rounds)
        yield False  # end encryption

    def decrypt(self) -> Generator[bool, None, None]:
        self.add_round_key(self.n_rounds)
        self.inv_shift_rows()
        self.inv_sub_bytes()
        for i in range(self.n_rounds - 1, 0, -1):
            self.add_round_key(i)
            self.inv_mix_columns()
            self.inv_shift_rows()
            self.inv_sub_bytes()
            yield True  # inverse exchange columns
        self.add_round_key(0)
        yield False  # end decryption

    @classmethod
    def xtime(cls, a: Uint8 | MaskedUint8) -> Uint8 | MaskedUint8:
        uint = cls.uint_class()
        x = (a << 1) & uint(0xFF)
        y = -(a >> 7) & uint(0x1B)
        return x ^ y

    def mix_single_column(self, a: int, b: int, c: int, d: int) -> None:
        s = self.state
        x = s[a] ^ s[b] ^ s[c] ^ s[d]
        y = s[a]
        s[a] ^= x ^ self.xtime(s[a] ^ s[b])
        s[b] ^= x ^ self.xtime(s[b] ^ s[c])
        s[c] ^= x ^ self.xtime(s[c] ^ s[d])
        s[d] ^= x ^ self.xtime(s[d] ^ y)

    def mix_columns(self) -> None:
        for i in range(0, 16, 4):
            self.mix_single_column(i, i + 1, i + 2, i + 3)

    def inv_mix_columns(self) -> None:
        s = self.state
        for i in range(0, 16, 4):
            m = s[i] ^ s[i + 2]
            n = s[i + 1] ^ s[i + 3]
            x = self.xtime(self.xtime(m))
            y = self.xtime(self.xtime(n))
            s[i] ^= x
            s[i + 1] ^= y
            s[i + 2] ^= x
            s[i + 3] ^= y
        self.mix_columns()

    def shift_rows(self) -> None:
        s = self.state
        s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]

    def inv_shift_rows(self) -> None:
        s = self.state
        s[1], s[5], s[9], s[13] = s[13], s[1], s[5], s[9]
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        s[3], s[7], s[11], s[15] = s[7], s[11], s[15], s[3]

    def add_round_key(self, index: int) -> None:
        for i, uint8 in enumerate(self.round_keys[index]):
            self.state[i] ^= uint8

    def clone(self) -> BaseAESBlock:
        return deepcopy(self)
