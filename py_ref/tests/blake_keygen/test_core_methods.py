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

from copy import deepcopy
from functools import cache

import pytest

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
    "test_blake32_digest_context",
    "test_blake64_digest_context"
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
@pytest.mark.parametrize("domain", [d for d in KDFDomain])
def test_init_state_vector(cls, domain):
    uint = cls.uint_class()
    v_bits = uint.bit_length()
    v_max = uint.max_value()
    v_bytes = v_bits // 8
    nonce = bytes(range(v_bits))
    n_vector = cls.bytes_to_uint_vector(nonce, vec_len=8)

    blake = cls(key=b'', nonce=b'', context=b'')
    d_mask = blake.domain_mask(domain)
    d_mask = blake.create_uint(d_mask)
    ivs = [blake.create_uint(iv) for iv in cls.ivs()]

    @cache
    def compute_ctr_uints(counter_: int):
        ctr_ = Uint64(counter_).to_bytes()
        ctr_high_ = int.from_bytes(ctr_[4:], byteorder="big", signed=False)
        ctr_low_ = int.from_bytes(ctr_[:4], byteorder="big", signed=False)
        uint32_clamp = cls.create_uint(0xFFFF_FFFF)
        ctr_high_uint_ = cls.create_uint(ctr_high_) & uint32_clamp
        ctr_low_uint_ = cls.create_uint(ctr_low_) & uint32_clamp
        return ctr_high_uint_, ctr_low_uint_

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


@pytest.mark.parametrize("cls", CLASSES_32)
def test_blake32_g_mix(cls):
    uint = cls.uint_class()
    uint_one, uint_two = uint(1), uint(2)
    blake = cls(key=b'', nonce=b'', context=b'')
    for uint in blake.state:
        assert uint == 0

    blake.g_mix(0, 4, 8, 12, uint_one, uint_two)
    assert blake.state == [
        0x00000013, 0x00000000, 0x00000000, 0x00000000,
        0x20260202, 0x00000000, 0x00000000, 0x00000000,
        0x13010100, 0x00000000, 0x00000000, 0x00000000,
        0x13000100, 0x00000000, 0x00000000, 0x00000000,
    ]

    blake.g_mix(1, 5, 9, 13, uint_one, uint_two)
    assert blake.state ==  [
        0x00000013, 0x00000013, 0x00000000, 0x00000000,
        0x20260202, 0x20260202, 0x00000000, 0x00000000,
        0x13010100, 0x13010100, 0x00000000, 0x00000000,
        0x13000100, 0x13000100, 0x00000000, 0x00000000,
    ]

    blake.g_mix(2, 6, 10, 14, uint_one, uint_two)
    assert blake.state == [
        0x00000013, 0x00000013, 0x00000013, 0x00000000,
        0x20260202, 0x20260202, 0x20260202, 0x00000000,
        0x13010100, 0x13010100, 0x13010100, 0x00000000,
        0x13000100, 0x13000100, 0x13000100, 0x00000000,
    ]

    blake.g_mix(3, 7, 11, 15, uint_one, uint_two)
    assert blake.state ==  [
        0x00000013, 0x00000013, 0x00000013, 0x00000013,
        0x20260202, 0x20260202, 0x20260202, 0x20260202,
        0x13010100, 0x13010100, 0x13010100, 0x13010100,
        0x13000100, 0x13000100, 0x13000100, 0x13000100,
    ]


@pytest.mark.parametrize("cls", CLASSES_64)
def test_blake64_g_mix(cls):
    uint = cls.uint_class()
    uint_one, uint_two = uint(1), uint(2)
    blake = cls(key=b'', nonce=b'', context=b'')
    for uint in blake.state:
        assert uint == 0

    blake.g_mix(0, 4, 8, 12, uint_one, uint_two)
    assert blake.state ==  [
        0x0000000000000103, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0206000200020200, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0103000100010000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0103000000010000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    ]

    blake.g_mix(1, 5, 9, 13, uint_one, uint_two)
    assert blake.state == [
        0x0000000000000103, 0x0000000000000103, 0x0000000000000000, 0x0000000000000000,
        0x0206000200020200, 0x0206000200020200, 0x0000000000000000, 0x0000000000000000,
        0x0103000100010000, 0x0103000100010000, 0x0000000000000000, 0x0000000000000000,
        0x0103000000010000, 0x0103000000010000, 0x0000000000000000, 0x0000000000000000,
    ]

    blake.g_mix(2, 6, 10, 14, uint_one, uint_two)
    assert blake.state ==  [
        0x0000000000000103, 0x0000000000000103, 0x0000000000000103, 0x0000000000000000,
        0x0206000200020200, 0x0206000200020200, 0x0206000200020200, 0x0000000000000000,
        0x0103000100010000, 0x0103000100010000, 0x0103000100010000, 0x0000000000000000,
        0x0103000000010000, 0x0103000000010000, 0x0103000000010000, 0x0000000000000000,
    ]

    blake.g_mix(3, 7, 11, 15, uint_one, uint_two)
    assert blake.state == [
        0x0000000000000103, 0x0000000000000103, 0x0000000000000103, 0x0000000000000103,
        0x0206000200020200, 0x0206000200020200, 0x0206000200020200, 0x0206000200020200,
        0x0103000100010000, 0x0103000100010000, 0x0103000100010000, 0x0103000100010000,
        0x0103000000010000, 0x0103000000010000, 0x0103000000010000, 0x0103000000010000,
    ]


@pytest.mark.parametrize("cls", CLASSES)
def test_permute(cls):
    blake = cls(key=b'', nonce=b'', context=b'')
    message = [cls.create_uint(c) for c in b"ABCDEFGHIJKLMNOP"]

    expected = [cls.create_uint(c) for c in b"CGDKHAENBLMFJOPI"]
    message = blake.permute(message)
    assert message == expected

    expected = [cls.create_uint(c) for c in b"DEKMNCHOGFJALPIB"]
    message = blake.permute(message)
    assert message == expected


@pytest.mark.parametrize("cls", CLASSES_32)
def test_blake32_digest_context(cls):
    blake = cls(key=b'', nonce=b'', context=b'')
    blake.digest_context()
    assert blake.state == [
        0xC2EB894F, 0x3B147EEA, 0xAE5A1CB8, 0x904DF606,
        0xC5393EF8, 0x07D4024E, 0x842E23EE, 0x3873ACB2,
        0xA8E23005, 0xDE6C2E0B, 0x3AB21C1B, 0x246BA208,
        0xBD35DCD2, 0x4969FFC6, 0xE03984FA, 0xE4133986,
    ]

@pytest.mark.parametrize("cls", CLASSES_64)
def test_blake64_digest_context(cls):
    blake = cls(key=b'', nonce=b'', context=b'')
    blake.digest_context()
    assert blake.state == [
        0xDC8B3C3143A0D4C1, 0x580998D3DE81A26F, 0x0541A07C357EF61D, 0x0957A6015FDF7732,
        0xA3356F649E3B2A21, 0x4644C796512D7958, 0xFDC0EACA13532EA9, 0xDAFF756C91DDC1C0,
        0xB8E4466483DAF7A4, 0x9A0A4B07A037C39D, 0xE96BF8EBE8E826F2, 0x24B439AE3061969D,
        0xAD5F490B09C82887, 0x4297FEE81F33CBD3, 0x9708FD326FEDDF3D, 0xFF42A3DAE1E43D7C,
    ]
