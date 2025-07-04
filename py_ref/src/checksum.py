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
from src.integers import *

__all__ = ["BaseCheckSum", "CheckSum", "MaskedCheckSum"]


class BaseCheckSum(ABC):
    @staticmethod
    @abstractmethod
    def uint_class() -> t.Type[BaseUint] | t.Type[BaseMaskedUint]: ...

    def __init__(self, state_size: int = 16) -> None:
        self.state = [self.uint_class()(0) for _ in range(state_size)]

    def xor_with(self, data: IterNum) -> None:
        for i, b in enumerate(data):
            self.state[i] ^= self.uint_class()(b)

    @classmethod
    def create_many(cls, count: int, state_size: int = 16) -> list[BaseCheckSum]:
        return [cls(state_size) for _ in range(count)]


class CheckSum(BaseCheckSum):
    @staticmethod
    def uint_class() -> t.Type[BaseUint]:
        return Uint8

    def to_bytes(self) -> bytes:  # for pytest only
        return bytes(self.state)


class MaskedCheckSum(BaseCheckSum):
    @staticmethod
    def uint_class() -> t.Type[BaseMaskedUint]:
        return MaskedUint8

    def to_bytes(self) -> bytes:  # for pytest only
        state = t.cast(list[MaskedUint8], self.state)
        unmasked_state = [s.unmask() for s in state]
        return bytes(unmasked_state)
