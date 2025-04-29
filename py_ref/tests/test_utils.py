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

import pytest

from src import utils
from src.uint import Uint8, Uint32, Uint64

__all__ = [
    "test_pad_trunc_to_size",
    "split_bytes",
    "test_bytes_to_uint8_vector",
    "test_bytes_to_uint32_vector",
    "test_bytes_to_uint64_vector"
]


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


def split_bytes():
    data = b"Word1Word2Word3Word4Word5"
    chunks = utils.split_bytes(data, chunk_size=5)
    assert chunks == [b'Word1', b'Word2', b'Word3', b'Word4', b'Word5']
    chunks = utils.split_bytes(data, chunk_size=6)
    assert chunks == [b'Word1W', b'ord2Wo', b'rd3Wor', b'd4Word', b'5']


def test_group_by_valid():
    cases = [
        (['abc', 'def', 'ghi', 'jkl'], 2, [('abc', 'def'), ('ghi', 'jkl')]),
        (['abc', 'def', 'ghi'], 3, [('abc', 'def', 'ghi')]),
        (['abc', 'def'], 1, [('abc',), ('def',)])
    ]
    for data, size, expected in cases:
        assert utils.group_by(data, size) == expected


def test_group_by_invalid():
    cases = [
        ([], 1),
        (['abc', 'def'], 0),
        (['abc', 'def'], -1),
        (['abc', 'def', 'ghi'], 2),
    ]
    for data, size in cases:
        with pytest.raises(ValueError):
            utils.group_by(data, size)


def test_bytes_to_uint8_vector():
    data = bytes()
    vector = utils.bytes_to_uint_vector(data, Uint8, v_size=16)
    assert len(vector) == 16
    for v in vector:
        assert v == 0

    data = bytes(range(8))
    vector = utils.bytes_to_uint_vector(data, Uint8, v_size=32)
    assert len(vector) == 32
    for i in range(0, 8):
        assert vector[i] == data[i]
    for i in range(8, len(vector)):
        assert vector[i] == 0

    data = bytes(range(32))
    vector = utils.bytes_to_uint_vector(data, Uint8, v_size=8)
    assert len(vector) == 8
    for i, v in enumerate(vector):
        assert v == data[i]


def test_bytes_to_uint32_vector():
    data = bytes()
    vector = utils.bytes_to_uint_vector(data, Uint32, v_size=16)
    assert len(vector) == 16
    for v in vector:
        assert v == 0

    data = bytes(range(8))
    vector = utils.bytes_to_uint_vector(data, Uint32, v_size=32)
    assert len(vector) == 32
    assert vector[0] == int.from_bytes(data[:4], byteorder="big")
    assert vector[1] == int.from_bytes(data[4:], byteorder="big")
    for i in range(2, len(vector)):
        assert vector[i] == 0

    data = bytes(range(32))
    vector = utils.bytes_to_uint_vector(data, Uint32, v_size=8)
    assert len(vector) == 8
    for i, v in enumerate(vector):
        start = i * 4
        end = start + 4
        subset = data[start:end]
        assert v == int.from_bytes(subset, byteorder="big")


def test_bytes_to_uint64_vector():
    data = bytes()
    vector = utils.bytes_to_uint_vector(data, Uint64, v_size=16)
    assert len(vector) == 16
    for v in vector:
        assert v == 0

    data = bytes(range(16))
    vector = utils.bytes_to_uint_vector(data, Uint64, v_size=32)
    assert len(vector) == 32
    assert vector[0] == int.from_bytes(data[:8], byteorder="big")
    assert vector[1] == int.from_bytes(data[8:], byteorder="big")
    for i in range(2, len(vector)):
        assert vector[i] == 0

    data = bytes(range(32))
    vector = utils.bytes_to_uint_vector(data, Uint64, v_size=8)
    assert len(vector) == 8
    for i, v in enumerate(vector):
        start = i * 8
        end = start + 8
        subset = data[start:end]
        assert v == int.from_bytes(subset, byteorder="big")
