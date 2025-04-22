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

from src.uint import Uint32

__all__ = ["pad_trunc_to_size", "bytes_to_uint32_vector"]


def pad_trunc_to_size(data: bytes, size: int) -> bytes:
    return (data + b"\x00" * size)[:size]


def bytes_to_uint32_vector(data: bytes, elements: int) -> list[Uint32]:
    sized_data = pad_trunc_to_size(data, elements * 4)
    output: list[Uint32] = []
    for i in range(0, len(sized_data), 4):
        output.append(Uint32.from_bytes(data[i:i+4]))
    return output
