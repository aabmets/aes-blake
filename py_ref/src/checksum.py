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

from src.uint import IterNum, Uint8

__all__ = ["CheckSum"]


class CheckSum:
    def __init__(self, state_size: int = 16) -> None:
        self.state = [Uint8(0) for _ in range(state_size)]

    def xor_with(self, data: IterNum) -> None:
        for i, b in enumerate(data):
            self.state[i] ^= b

    def to_bytes(self) -> bytes:
        return bytes(self.state)

    @classmethod
    def create_many(cls, count: int) -> list[CheckSum]:
        return [cls() for _ in range(count)]
