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

__all__ = ["bytes_to_uint32_vector", "pad_trunc_to_size", "pkcs7_pad", "pkcs7_unpad"]


def bytes_to_uint32_vector(data: bytes, size: int) -> list[Uint32]:
    s_len = len(data)
    count = 4 - (s_len % 4)
    data += b"\x00" * count
    output: list[Uint32] = []
    for i in range(0, s_len, 4):
        output.append(Uint32.from_bytes(data=data[i : i + 4], byteorder="little"))
    while len(output) < size:
        output.append(Uint32(0))
    return output


def pad_trunc_to_size(data: bytes, size: int) -> bytes:
    return (data + b"\x00" * size)[:size]


def pkcs7_pad(data: bytes, size: int = 16) -> bytes:
    pad_len = size - (len(data) % size)
    padding = bytes([pad_len] * pad_len)
    return data + padding


def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]
