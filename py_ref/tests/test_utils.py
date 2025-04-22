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
import debug
from src import utils

__all__ = ["test_pad_trunc_to_size", "test_bytes_to_uint32_vector"]


def test_pad_trunc_to_size():
    out = utils.pad_trunc_to_size(b"", size=10)
    assert len(out) == 10
    for b in out:
        assert b == 0

    data = b"\xaa\xbb\xcc\xdd\xee"
    out = utils.pad_trunc_to_size(data, size=10)
    assert len(out) == 10
    for i in range(0, 5):
        assert out[i] == data[i]
    for i in range(5, 10):
        assert out[i] == 0

    data = b"\xaa\xbb\xcc\xdd\xee"
    out = utils.pad_trunc_to_size(data, size=3)
    assert len(out) == 3
    for i in range(0, 3):
        assert out[i] == data[i]


def test_bytes_to_uint32_vector():
    data = bytes()
    vector = utils.bytes_to_uint32_vector(data, elements=16)
    assert len(vector) == 16
    for v in vector:
        assert v == 0

    data = bytes(range(8))
    vector = utils.bytes_to_uint32_vector(data, elements=32)
    assert len(vector) == 32
    assert vector[0] == int.from_bytes(data[:4], byteorder="big")
    assert vector[1] == int.from_bytes(data[4:], byteorder="big")
    for i in range(2, len(vector)):
        assert vector[i] == 0

    data = bytes(range(32))
    vector = utils.bytes_to_uint32_vector(data, elements=8)
    assert len(vector) == 8
    for i, v in enumerate(vector):
        start = i * 4
        end = start + 4
        subset = data[start:end]
        assert v == int.from_bytes(subset, byteorder="big")
