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

import typing as t
from typing import TypeVar, Type

from src.uint import BaseUint

__all__ = ["pad_trunc_to_size", "split_bytes", "bytes_to_uint_vector"]

T = TypeVar("T", bound=BaseUint)


def pad_trunc_to_size(data: bytes, size: int) -> bytes:
    return (data + b"\x00" * size)[:size]


def split_bytes(data: bytes, chunk_size: int) -> list[bytes]:
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]


def group_by(data: list, size: int) -> list[tuple]:
    n = len(data)
    if not data:
        raise ValueError("Data cannot be an empty list")
    elif size <= 0:
        raise ValueError("Size must be a positive integer")
    elif n % size != 0:
        raise ValueError(f"Cannot divide list of length {n} into groups of {size}")
    return [tuple(data[i:i+size]) for i in range(0, n, size)]


def bytes_to_uint_vector(data: bytes, uint: t.Union[T, Type[T]], v_size: int) -> list[T]:
    chunk_size = uint.bit_count() // 8
    sized_data = pad_trunc_to_size(data, v_size * chunk_size)
    output: list[T] = []
    for i in range(0, len(sized_data), chunk_size):
        chunk = sized_data[i:i+chunk_size]
        output.append(uint.from_bytes(chunk))
    return output
