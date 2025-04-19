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

from src import utils

__all__ = [
    "test_bytes_to_uint32_vector",
    "test_pad_trunc_to_size",
    "test_pkcs7_pad_unpad",
]


def test_bytes_to_uint32_vector():
    vector = utils.bytes_to_uint32_vector(b"", size=16)
    assert len(vector) == 16
    for v in vector:
        assert v == 0

    data = b"\x00\x01\x02\x03\x04\x05\x06\x07"
    vector = utils.bytes_to_uint32_vector(data, size=32)
    assert len(vector) == 32
    assert vector[0] == int.from_bytes(data[:4], byteorder="little")
    assert vector[1] == int.from_bytes(data[4:], byteorder="little")


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


def test_pkcs7_pad_unpad():
    data = b"\x01\x02\x03"
    out = utils.pkcs7_pad(data, size=16)
    assert len(out) == 16
    assert out == b"\x01\x02\x03" + (b"\x0d" * 13)
    out = utils.pkcs7_unpad(out)
    assert out == data

    data = b"\x01" * 16
    out = utils.pkcs7_pad(data, size=16)
    assert len(out) == 32
    assert out == data + (b"\x10" * 16)
    out = utils.pkcs7_unpad(out)
    assert out == data

    data = b"\x01" * 128
    out = utils.pkcs7_pad(data, size=128)
    assert len(out) == 256
    assert out == data + (b"\x80" * 128)
    out = utils.pkcs7_unpad(out)
    assert out == data
