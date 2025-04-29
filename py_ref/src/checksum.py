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
from abc import ABC, abstractmethod

from src.uint import IterNum, Uint8

__all__ = ["BaseCheckSum", "CheckSum32", "CheckSum64"]


class BaseCheckSum(ABC):
    @staticmethod
    @abstractmethod
    def size() -> int: ...

    def __init__(self) -> None:
        self.state = [Uint8(0) for _ in range(self.size())]

    def xor_with(self, data: IterNum) -> None:
        for i, b in enumerate(data):
            self.state[i] ^= b

    def to_bytes(self) -> bytes:
        return bytes(self.state)

    @classmethod
    def create_many(cls, count: int) -> list[CheckSum]:
        return [cls() for _ in range(count)]


class CheckSum32(BaseCheckSum):
    @staticmethod
    def size() -> int:
        return 32


class CheckSum64(BaseCheckSum):
    @staticmethod
    def size() -> int:
        return 64
