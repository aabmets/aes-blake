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
from functools import cache
from multiprocessing import Lock

import pytest

from src.blake_keygen import (Blake32, Blake64, KDFDomain, MaskedBlake32,
                              MaskedBlake64, WithDeriveKeys32,
                              WithDeriveKeys64)

__all__ = [
    "test_blake32_derive_keys_msg_ctr_0",
    "test_blake32_derive_keys_hdr_ctr_1",
    "test_blake32_derive_keys_chk_ctr_2",
    "test_blake64_derive_keys_msg_ctr_0",
    "test_blake64_derive_keys_hdr_ctr_1",
    "test_blake64_derive_keys_chk_ctr_2"
]


LOCK = Lock()
CLASSES_32 = [Blake32, MaskedBlake32]
CLASSES_64 = [Blake64, MaskedBlake64]
WDK = WithDeriveKeys32 | WithDeriveKeys64


@cache
def get_blake_keygen(cls: t.Type[WDK]) -> WDK:
    blake = cls(key=b'', nonce=b'', context=b'')
    blake.digest_context()
    return blake


@pytest.mark.parametrize("cls", CLASSES_32)
def test_blake32_derive_keys_msg_ctr_0(cls):
    with LOCK:
        blake = get_blake_keygen(cls)
    key_count, block_counter = 10, 0

    keys1, keys2 = blake.derive_keys(key_count, block_counter, KDFDomain.MSG)

    assert len(keys1) == len(keys2) == key_count
    assert keys1[0] == [
        0x2C, 0x23, 0xCE, 0x27,
        0xA2, 0xD0, 0x70, 0xBF,
        0xB6, 0x87, 0xF0, 0x6E,
        0x7F, 0x67, 0x09, 0x24,
    ]
    assert keys2[0] == [
        0xBD, 0x5F, 0xA1, 0xB1,
        0x45, 0x57, 0x04, 0x9A,
        0x3B, 0xF9, 0xFD, 0xA4,
        0x3E, 0xEE, 0x4F, 0x5E,
    ]


@pytest.mark.parametrize("cls", CLASSES_32)
def test_blake32_derive_keys_hdr_ctr_1(cls):
    with LOCK:
        blake = get_blake_keygen(cls)
    key_count, block_counter = 10, 1

    keys1, keys2 = blake.derive_keys(key_count, block_counter, KDFDomain.HDR)

    assert len(keys1) == len(keys2) == key_count
    assert keys1[0] == [
        0xC7, 0x06, 0x08, 0xFD,
        0xE3, 0x51, 0x95, 0x2C,
        0xD5, 0x4C, 0xAF, 0x93,
        0xF1, 0x87, 0x7C, 0x92,
    ]
    assert keys2[0] == [
        0x06, 0x3D, 0xFB, 0x16,
        0x96, 0xD3, 0xAC, 0x49,
        0xD4, 0xF7, 0xED, 0x15,
        0xCF, 0x60, 0xB3, 0xD8,
    ]


@pytest.mark.parametrize("cls", CLASSES_32)
def test_blake32_derive_keys_chk_ctr_2(cls):
    with LOCK:
        blake = get_blake_keygen(cls)
    key_count, block_counter = 10, 2

    keys1, keys2 = blake.derive_keys(key_count, block_counter, KDFDomain.CHK)

    assert len(keys1) == len(keys2) == key_count
    assert keys1[0] == [
        0x3A, 0xC7, 0xE0, 0xF4,
        0xD6, 0xAF, 0xA4, 0x6C,
        0x86, 0xEA, 0x34, 0x6D,
        0x3D, 0x75, 0x3D, 0x6B,
    ]
    assert keys2[0] == [
        0x68, 0x6D, 0x15, 0x79,
        0x68, 0x92, 0x3B, 0xBF,
        0xF6, 0xD3, 0x37, 0x32,
        0x13, 0x7F, 0x2C, 0x07,
    ]


@pytest.mark.parametrize("cls", CLASSES_64)
def test_blake64_derive_keys_msg_ctr_0(cls):
    with LOCK:
        blake = get_blake_keygen(cls)
    key_count, block_counter = 10, 0

    keys1, keys2, keys3, keys4 = blake.derive_keys(key_count, block_counter, KDFDomain.MSG)

    assert len(keys1) == len(keys2) == key_count
    assert keys1[0] == [
        0xFB, 0xE5, 0xF3, 0xC3,
        0xC0, 0xD1, 0x09, 0x26,
        0xCF, 0x49, 0x45, 0xC8,
        0x1C, 0x51, 0x5F, 0x0C,
    ]
    assert keys2[0] == [
        0x3D, 0xAF, 0x00, 0x51,
        0x7F, 0x37, 0xCE, 0x3B,
        0x05, 0x83, 0x6F, 0xDF,
        0x50, 0xBD, 0x37, 0x76,
    ]
    assert keys3[0] == [
        0x6E, 0x2E, 0xE5, 0x47,
        0x98, 0x7F, 0x28, 0x4D,
        0x7E, 0xA2, 0xE5, 0xF2,
        0x6E, 0x3A, 0xC3, 0x58,
    ]
    assert keys4[0] == [
        0x4E, 0x64, 0xEE, 0xA4,
        0x6B, 0x1C, 0xC0, 0xE8,
        0x0E, 0x34, 0x6A, 0xF5,
        0x85, 0x69, 0x26, 0xE6,
    ]


@pytest.mark.parametrize("cls", CLASSES_64)
def test_blake64_derive_keys_hdr_ctr_1(cls):
    with LOCK:
        blake = get_blake_keygen(cls)
    key_count, block_counter = 10, 1
    keys1, keys2, keys3, keys4 = blake.derive_keys(key_count, block_counter, KDFDomain.HDR)
    assert len(keys1) == len(keys2) == key_count
    assert keys1[0] == [
        0x97, 0x6A, 0x21, 0x61,
        0xFB, 0x02, 0x0C, 0x84,
        0x4F, 0x8A, 0xE9, 0xBC,
        0xF3, 0xF6, 0x00, 0x6E,
    ]
    assert keys2[0] == [
        0x55, 0x55, 0xBB, 0x9B,
        0xDB, 0xF8, 0x73, 0xF4,
        0xB6, 0x79, 0x54, 0x5C,
        0x28, 0x58, 0x35, 0xC3,
    ]
    assert keys3[0] == [
        0x72, 0xF8, 0x27, 0xBE,
        0x2E, 0x28, 0xE8, 0xBD,
        0x9E, 0xE3, 0x33, 0x4D,
        0x18, 0xEA, 0xC6, 0x28,
    ]
    assert keys4[0] == [
        0xFE, 0x30, 0xDD, 0xCE,
        0x1A, 0xB8, 0x7F, 0x3E,
        0xFF, 0x0D, 0xA7, 0x38,
        0x94, 0xD7, 0x67, 0x1C,
    ]


@pytest.mark.parametrize("cls", CLASSES_64)
def test_blake64_derive_keys_chk_ctr_2(cls):
    with LOCK:
        blake = get_blake_keygen(cls)
    key_count, block_counter = 10, 2

    keys1, keys2, keys3, keys4 = blake.derive_keys(key_count, block_counter, KDFDomain.CHK)

    assert len(keys1) == len(keys2) == key_count
    assert keys1[0] == [
        0xA7, 0x69, 0x6B, 0xE8,
        0x57, 0x12, 0x4B, 0x08,
        0x10, 0xD8, 0xCD, 0x2C,
        0x00, 0x8E, 0xD8, 0xBA,
    ]
    assert keys2[0] == [
        0x9D, 0x2C, 0x55, 0x73,
        0x97, 0x0E, 0xE5, 0xF6,
        0x79, 0xEB, 0x2B, 0xC0,
        0x22, 0x76, 0xD1, 0x18,
    ]
    assert keys3[0] == [
        0xF5, 0x8C, 0x41, 0x02,
        0x20, 0xCA, 0x3A, 0x76,
        0xC4, 0x60, 0xD9, 0x7E,
        0x78, 0xEA, 0xD4, 0x94,
    ]
    assert keys4[0] == [
        0x22, 0x3E, 0x98, 0xC7,
        0x8F, 0x34, 0xF1, 0xCD,
        0x79, 0x97, 0xA0, 0x23,
        0xBA, 0x24, 0x84, 0x6A,
    ]
