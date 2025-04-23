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

from typing import TypeVar, Type

from src.uint import BaseUint

__all__ = ["pad_trunc_to_size", "bytes_to_uint_vector"]

T = TypeVar("T", bound=BaseUint)


def pad_trunc_to_size(data: bytes, size: int) -> bytes:
    return (data + b"\x00" * size)[:size]


def bytes_to_uint_vector(data: bytes, uint: Type[T], v_size: int) -> list[T]:
    chunk_size = uint(0).bit_count // 8
    sized_data = pad_trunc_to_size(data, v_size * chunk_size)
    output: list[T] = []
    for i in range(0, len(sized_data), chunk_size):
        chunk = sized_data[i:i+chunk_size]
        output.append(uint.from_bytes(chunk))
    return output
