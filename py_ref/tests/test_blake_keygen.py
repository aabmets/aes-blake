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
import typing as t
from functools import cache
from copy import deepcopy

from src.blake_keygen import *
from src.integers import *

__all__ = [
    "test_bytes_to_uint_vector",
    "test_compute_key_nonce_composite",
    "test_init_state_vector",
    "test_blake32_mix_into_state",
    "test_blake64_mix_into_state",
    "test_blake32_g_mix",
    "test_blake64_g_mix",
    "test_permute",
    "test_digest_context"
]


CLASSES = [Blake32, Blake64, MaskedBlake32, MaskedBlake64]
CLASSES_32 = [Blake32, MaskedBlake32]
CLASSES_64 = [Blake64, MaskedBlake64]


@pytest.mark.parametrize("cls", CLASSES)
def test_bytes_to_uint_vector(cls):
    byte_count = cls.bit_length() // 8

    data = bytes()
    vector = cls.bytes_to_uint_vector(data, vec_len=16)
    assert len(vector) == 16
    for v in vector:
        assert v == 0

    data = bytes(range(byte_count * 2))
    vector = cls.bytes_to_uint_vector(data, vec_len=32)
    assert len(vector) == 32
    assert vector[0] == int.from_bytes(data[:byte_count], byteorder="big")
    assert vector[1] == int.from_bytes(data[byte_count:], byteorder="big")
    for i in range(2, len(vector)):
        assert vector[i] == 0

    data = bytes(range(32))
    vector = cls.bytes_to_uint_vector(data, vec_len=8)
    assert len(vector) == 8
    for i, v in enumerate(vector):
        start = i * byte_count
        end = start + byte_count
        subset = data[start:end]
        assert v == int.from_bytes(subset, byteorder="big")


@pytest.mark.parametrize("cls", CLASSES)
def test_compute_key_nonce_composite(cls):
    key = b"\xAA" * cls.bit_length()
    nonce = b"\xBB" * cls.bit_length()
    blake = cls(key, nonce, context=b"")
    words = [0xAAAABBBB, 0xBBBBAAAA]
    if cls.bit_length() == 64:
        words = [0xAAAAAAAABBBBBBBBB, 0xBBBBBBBBAAAAAAAA]
    for i in range(len(blake.knc), 2):
        assert blake.knc[i] == words[0]
        assert blake.knc[i+1] == words[1]


@pytest.mark.parametrize("cls", CLASSES)
def test_init_state_vector(cls):
    uint = cls.uint_class()
    v_bits = uint.bit_length()
    v_max = uint.max_value()
    v_bytes = v_bits // 8
    domains = [
        t.cast(KDFDomain, d) for d in
        KDFDomain._member_map_.values()
    ]
    nonce = bytes(range(v_bits))
    n_vector = cls.bytes_to_uint_vector(nonce, vec_len=8)

    blake = cls(key=b'', nonce=b'', context=b'')
    uint32_clamp = cls.create_uint(0xFFFF_FFFF)
    ivs = [blake.create_uint(iv) for iv in cls.ivs()]

    @cache
    def compute_ctr_uints(counter_: int):
        ctr_ = Uint64(counter_).to_bytes()
        ctr_high_ = int.from_bytes(ctr_[4:], byteorder="big", signed=False)
        ctr_low_ = int.from_bytes(ctr_[:4], byteorder="big", signed=False)
        ctr_high_uint_ = cls.create_uint(ctr_high_) & uint32_clamp
        ctr_low_uint_ = cls.create_uint(ctr_low_) & uint32_clamp
        return ctr_high_uint_, ctr_low_uint_

    for domain in domains:
        d_mask = blake.domain_mask(domain)
        d_mask = blake.create_uint(d_mask)

        for counter in [0, v_max // 2, v_max // 3, v_max]:
            nv_copy = deepcopy(n_vector)
            blake.init_state_vector(nv_copy, counter, domain)
            ctr_high_uint, ctr_low_uint = compute_ctr_uints(counter)

            for i, j in enumerate([0, 1, 2, 3, 12, 13, 14, 15]):
                if j >= 12:
                    blake.state[j] ^= d_mask
                assert blake.state[j] == ivs[i]

            for i, j in enumerate(range(4, 12)):
                start = i * v_bytes
                end = start + v_bytes
                n_slice = nonce[start:end]
                int_2 = int.from_bytes(n_slice, byteorder="big", signed=False)
                uint_2 = cls.create_uint(int_2)

                _ctr = ctr_high_uint if j < 8 else ctr_low_uint
                blake.state[j] -= _ctr
                assert blake.state[j] == uint_2


@pytest.mark.parametrize("cls", CLASSES_32)
def test_blake32_mix_into_state(cls):
    uint = cls.uint_class()
    msg = [uint(n) for n in range(0, 16)]
    blake = cls(key=b'', nonce=b'', context=b'')
    blake.mix_into_state(msg)
    assert blake.state == [
        0x952AB9C9, 0x7A41633A, 0x5E47082C, 0xB024987E,
        0x4E2C267A, 0xDB3491DA, 0x19C80149, 0xF331BDEE,
        0x05B20CC7, 0xA631AAD3, 0xCEA858DE, 0x1DAFFE74,
        0xA87276E2, 0xF65026ED, 0x7CB45FD1, 0x83972794,
    ]


@pytest.mark.parametrize("cls", CLASSES_64)
def test_blake64_mix_into_state(cls):
    uint = cls.uint_class()
    msg = [uint(n) for n in range(0, 16)]
    blake = cls(key=b'', nonce=b'', context=b'')
    blake.mix_into_state(msg)
    assert blake.state == [
        0x130E040401080D14, 0x191A081607122722, 0x1F260C18151C2930, 0x0D0200020B06232E,
        0x506E264202402412, 0x3C3E263206381422, 0x786E56521A702402, 0x748E46627E780402,
        0x294B2F3D2A2C1B0F, 0x253713230A260F0D, 0x111B171902180313, 0x2D3F23270A320F09,
        0x272A191202190F01, 0x293C1F281C0D1B03, 0x232E0D0606190F0D, 0x0D10130C000D030F,
    ]


def test_blake32_g_mix():
    blake = Blake32(key=b'', nonce=b'', context=b'')
    for uint in blake.state:
        assert uint == 0

    blake.g_mix(0, 4, 8, 12, Uint32(1), Uint32(2))
    assert blake.state == [
        0x00000013, 0x00000000, 0x00000000, 0x00000000,
        0x20260202, 0x00000000, 0x00000000, 0x00000000,
        0x13010100, 0x00000000, 0x00000000, 0x00000000,
        0x13000100, 0x00000000, 0x00000000, 0x00000000,
    ]

    blake.g_mix(1, 5, 9, 13, Uint32(1), Uint32(2))
    assert blake.state ==  [
        0x00000013, 0x00000013, 0x00000000, 0x00000000,
        0x20260202, 0x20260202, 0x00000000, 0x00000000,
        0x13010100, 0x13010100, 0x00000000, 0x00000000,
        0x13000100, 0x13000100, 0x00000000, 0x00000000,
    ]

    blake.g_mix(2, 6, 10, 14, Uint32(1), Uint32(2))
    assert blake.state == [
        0x00000013, 0x00000013, 0x00000013, 0x00000000,
        0x20260202, 0x20260202, 0x20260202, 0x00000000,
        0x13010100, 0x13010100, 0x13010100, 0x00000000,
        0x13000100, 0x13000100, 0x13000100, 0x00000000,
    ]

    blake.g_mix(3, 7, 11, 15, Uint32(1), Uint32(2))
    assert blake.state ==  [
        0x00000013, 0x00000013, 0x00000013, 0x00000013,
        0x20260202, 0x20260202, 0x20260202, 0x20260202,
        0x13010100, 0x13010100, 0x13010100, 0x13010100,
        0x13000100, 0x13000100, 0x13000100, 0x13000100,
    ]


def test_blake64_g_mix():
    blake = Blake64(key=b'', nonce=b'', context=b'')
    for uint in blake.state:
        assert uint == 0

    blake.g_mix(0, 4, 8, 12, Uint64(1), Uint64(2))
    assert blake.state ==  [
        0x0000000000000103, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0206000200020200, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0103000100010000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0103000000010000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    ]

    blake.g_mix(1, 5, 9, 13, Uint64(1), Uint64(2))
    assert blake.state == [
        0x0000000000000103, 0x0000000000000103, 0x0000000000000000, 0x0000000000000000,
        0x0206000200020200, 0x0206000200020200, 0x0000000000000000, 0x0000000000000000,
        0x0103000100010000, 0x0103000100010000, 0x0000000000000000, 0x0000000000000000,
        0x0103000000010000, 0x0103000000010000, 0x0000000000000000, 0x0000000000000000,
    ]

    blake.g_mix(2, 6, 10, 14, Uint64(1), Uint64(2))
    assert blake.state ==  [
        0x0000000000000103, 0x0000000000000103, 0x0000000000000103, 0x0000000000000000,
        0x0206000200020200, 0x0206000200020200, 0x0206000200020200, 0x0000000000000000,
        0x0103000100010000, 0x0103000100010000, 0x0103000100010000, 0x0000000000000000,
        0x0103000000010000, 0x0103000000010000, 0x0103000000010000, 0x0000000000000000,
    ]

    blake.g_mix(3, 7, 11, 15, Uint64(1), Uint64(2))
    assert blake.state == [
        0x0000000000000103, 0x0000000000000103, 0x0000000000000103, 0x0000000000000103,
        0x0206000200020200, 0x0206000200020200, 0x0206000200020200, 0x0206000200020200,
        0x0103000100010000, 0x0103000100010000, 0x0103000100010000, 0x0103000100010000,
        0x0103000000010000, 0x0103000000010000, 0x0103000000010000, 0x0103000000010000,
    ]


@pytest.mark.parametrize("cls", [Blake32, Blake64])
def test_permute(cls):
    blake = cls(key=b'', nonce=b'', context=b'')
    message = [cls.create_uint(c) for c in b"ABCDEFGHIJKLMNOP"]

    expected = [cls.create_uint(c) for c in b"CGDKHAENBLMFJOPI"]
    message = blake.permute(message)
    assert message == expected

    expected = [cls.create_uint(c) for c in b"DEKMNCHOGFJALPIB"]
    message = blake.permute(message)
    assert message == expected


def test_digest_context():
    blake = Blake32(key=b'', nonce=b'', context=b'')
    blake.digest_context()
    assert blake.state == [
        0xC2EB894F, 0x3B147EEA, 0xAE5A1CB8, 0x904DF606,
        0xC5393EF8, 0x07D4024E, 0x842E23EE, 0x3873ACB2,
        0xA8E23005, 0xDE6C2E0B, 0x3AB21C1B, 0x246BA208,
        0xBD35DCD2, 0x4969FFC6, 0xE03984FA, 0xE4133986,
    ]

    blake = Blake64(key=b'', nonce=b'', context=b'')
    blake.digest_context()
    assert blake.state == [
        0xDC8B3C3143A0D4C1, 0x580998D3DE81A26F, 0x0541A07C357EF61D, 0x0957A6015FDF7732,
        0xA3356F649E3B2A21, 0x4644C796512D7958, 0xFDC0EACA13532EA9, 0xDAFF756C91DDC1C0,
        0xB8E4466483DAF7A4, 0x9A0A4B07A037C39D, 0xE96BF8EBE8E826F2, 0x24B439AE3061969D,
        0xAD5F490B09C82887, 0x4297FEE81F33CBD3, 0x9708FD326FEDDF3D, 0xFF42A3DAE1E43D7C,
    ]


def test_blake32_derive_keys():
    blake = Blake32(key=b'', nonce=b'', context=b'')
    blake.digest_context()
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

    block_counter += 1
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

    block_counter += 1
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


def test_blake64_derive_keys():
    blake = Blake64(key=b'', nonce=b'', context=b'')
    blake.digest_context()
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

    block_counter += 1
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

    block_counter += 1
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
