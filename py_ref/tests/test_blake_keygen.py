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
from copy import deepcopy

from src import utils
from src.aes_sbox import SBox
from src.blake_keygen import Blake32, Blake64, KDFDomain
from src.uint import Uint32, Uint64
from src import debug

__all__ = [
    "test_compute_key_nonce_composite",
    "test_init_state_vector",
    "test_blake32_mix_into_state",
    "test_blake64_mix_into_state",
    "test_blake32_g_mix",
    "test_blake64_g_mix",
    "test_permute",
    "test_sub_bytes",
    "test_digest_context"
]


def test_compute_key_nonce_composite():
    key = b"\xAA" * Uint32.bit_count()
    nonce = b"\xBB" * Uint32.bit_count()
    blake = Blake32(key, nonce, context=b"")
    assert blake.knc == [
        0xAAAABBBB, 0xBBBBAAAA, 0xAAAABBBB, 0xBBBBAAAA,
        0xAAAABBBB, 0xBBBBAAAA, 0xAAAABBBB, 0xBBBBAAAA,
        0xAAAABBBB, 0xBBBBAAAA, 0xAAAABBBB, 0xBBBBAAAA,
        0xAAAABBBB, 0xBBBBAAAA, 0xAAAABBBB, 0xBBBBAAAA,
    ]


def test_init_state_vector():
    for cls in [Blake32, Blake64]:
        uint, ivs = cls.uint(), cls.ivs()
        v_bits = uint.bit_count()
        v_max = uint.max_value()
        v_bytes = v_bits // 8
        domains = [
            t.cast(KDFDomain, d) for d in
            KDFDomain._member_map_.values()
        ]
        nonce = bytes(range(v_bits))
        n_vector = utils.bytes_to_uint_vector(nonce, uint, v_size=8)

        blake = cls(key=b'', nonce=b'', context=b'')

        for domain in domains:
            for counter in [0, v_max // 2, v_max // 3, v_max]:
                nv_copy = deepcopy(n_vector)
                blake.init_state_vector(nv_copy, counter, domain)
                d_mask = blake.domain_mask(domain)
                ctr = Uint64(counter).to_bytes()

                for i, j in enumerate([0, 1, 2, 3, 12, 13, 14, 15]):
                    if j >= 12:
                        blake.state[j] ^= d_mask
                    assert blake.state[j] == ivs[i]

                for i, j in enumerate(range(4, 12)):
                    start = i * v_bytes
                    end = start + v_bytes
                    n_slice = nonce[start:end]
                    uint_2 = uint.from_bytes(n_slice)

                    _ctr = ctr[4:] if j < 8 else ctr[:4]
                    blake.state[j] -= Uint32.from_bytes(_ctr)
                    assert blake.state[j] == uint_2


def test_blake32_mix_into_state():
    msg = [Uint32(n) for n in range(0, 16)]
    blake = Blake32(key=b'', nonce=b'', context=b'')
    blake.mix_into_state(msg)
    assert blake.state == [
        0x952AB9C9, 0x7A41633A, 0x5E47082C, 0xB024987E,
        0x4E2C267A, 0xDB3491DA, 0x19C80149, 0xF331BDEE,
        0x05B20CC7, 0xA631AAD3, 0xCEA858DE, 0x1DAFFE74,
        0xA87276E2, 0xF65026ED, 0x7CB45FD1, 0x83972794,
    ]


def test_blake64_mix_into_state():
    msg = [Uint64(n) for n in range(0, 16)]
    blake = Blake64(key=b'', nonce=b'', context=b'')
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


def test_permute():
    for cls in [Blake32, Blake64]:
        uint = cls.uint()
        blake = cls(key=b'', nonce=b'', context=b'')
        message = [uint(c) for c in b"ABCDEFGHIJKLMNOP"]

        expected = [uint(c) for c in b"CGDKHAENBLMFJOPI"]
        message = blake.permute(message)
        assert message == expected

        expected = [uint(c) for c in b"DEKMNCHOGFJALPIB"]
        message = blake.permute(message)
        assert message == expected


def test_sub_bytes():
    blake = Blake32(key=b'', nonce=b'', context=b'')
    for uint in blake.state:
        assert uint == 0

    blake.sub_bytes(SBox.ENC)
    for uint in blake.state:
        assert uint == 0x63636363

    blake.sub_bytes(SBox.DEC)
    for uint in blake.state:
        assert uint == 0

    blake = Blake64(key=b'', nonce=b'', context=b'')
    for uint in blake.state:
        assert uint == 0

    blake.sub_bytes(SBox.ENC)
    for uint in blake.state:
        assert uint == 0x6363636363636363

    blake.sub_bytes(SBox.DEC)
    for uint in blake.state:
        assert uint == 0


def test_digest_context():
    blake = Blake32(key=b'', nonce=b'', context=b'')
    blake.digest_context()
    assert blake.state == [
        0x25E9A784, 0xE2FAF387, 0xE4BE9C6C, 0x60E3426F,
        0xA612B241, 0xC548772F, 0x5F312628, 0x078F9137,
        0xC298046B, 0x1D50312B, 0x80379CAF, 0x367F3A30,
        0x7A9686B5, 0x3BF916B4, 0xE1125F2D, 0x697D1244,
    ]

    blake = Blake64(key=b'', nonce=b'', context=b'')
    blake.digest_context()
    assert blake.state == [
        0x863DEBC71AE04878, 0x6A0146661D0C3AA8, 0x6B83E01096F342A4, 0x015B247CCF9EF523,
        0x0A96A8430BE2E5FD, 0x5A1BC690D1D8B66A, 0x54BA87747DED31D3, 0x57169D5081C178BA,
        0x6C695A43EC576849, 0xB867B3C5E09A2E5E, 0x1E7F41E99B9BF789, 0x368D12E404EF905E,
        0x95CF3B2B01E83417, 0x2C88BB9BC0C31F66, 0x88305423A8559E27, 0x162C0A57F8692710,
    ]


def test_blake32_derive_keys():
    blake = Blake32(key=b'', nonce=b'', context=b'')
    blake.digest_context()
    key_count, block_counter = 10, 0

    keys1, keys2 = blake.derive_keys(key_count, block_counter, KDFDomain.MSG)
    assert len(keys1) == len(keys2) == key_count
    assert keys1[0] == [
        0xB3, 0xA6, 0xCD, 0xB0,
        0x1A, 0x95, 0x57, 0x74,
        0x28, 0xE8, 0xE4, 0x87,
        0xE4, 0xEC, 0x45, 0x8E,
    ]
    assert keys2[0] == [
        0xA1, 0xB9, 0x28, 0x0A,
        0x25, 0xD5, 0x62, 0xD9,
        0x7B, 0x2C, 0x69, 0x63,
        0x45, 0xDF, 0xEE, 0x7F,
    ]

    block_counter += 1
    keys1, keys2 = blake.derive_keys(key_count, block_counter, KDFDomain.HDR)
    assert len(keys1) == len(keys2) == key_count
    assert keys1[0] == [
        0x39, 0xA3, 0x42, 0x5C,
        0x5C, 0x25, 0x67, 0x1D,
        0xF0, 0x09, 0x32, 0xA6,
        0xC7, 0x0F, 0xF7, 0xE4,
    ]
    assert keys2[0] == [
        0xC7, 0x21, 0xD5, 0x05,
        0x34, 0xC2, 0x50, 0xD1,
        0xD8, 0x26, 0x2D, 0x2E,
        0x01, 0xB5, 0xA2, 0x11,
    ]

    block_counter += 1
    keys1, keys2 = blake.derive_keys(key_count, block_counter, KDFDomain.CHK)
    assert len(keys1) == len(keys2) == key_count
    assert keys1[0] == [
        0x47, 0x64, 0xEA, 0xEA,
        0x04, 0x9D, 0x16, 0xCD,
        0x42, 0xE7, 0x39, 0x85,
        0x52, 0x46, 0xF8, 0xB5,
    ]
    assert keys2[0] == [
        0x21, 0xE9, 0x52, 0xD6,
        0xF7, 0x9C, 0xE2, 0x12,
        0x62, 0x1A, 0x3D, 0x96,
        0xD6, 0x41, 0x84, 0x6E,
    ]


def test_blake64_derive_keys():
    blake = Blake64(key=b'', nonce=b'', context=b'')
    blake.digest_context()
    key_count, block_counter = 10, 0

    keys1, keys2, keys3, keys4 = blake.derive_keys(key_count, block_counter, KDFDomain.MSG)
    assert len(keys1) == len(keys2) == key_count
    assert keys1[0] == [
        0x00, 0xAA, 0x3C, 0xEE,
        0xB1, 0xB0, 0x6B, 0x31,
        0xA8, 0x96, 0xF5, 0xFC,
        0x99, 0x6F, 0x6A, 0xA8,
    ]
    assert keys2[0] == [
        0x2E, 0x9A, 0xB4, 0x00,
        0x84, 0x28, 0xAD, 0x9B,
        0xEE, 0xD4, 0xEC, 0x6F,
        0xB8, 0xBC, 0xF1, 0x4D,
    ]
    assert keys3[0] == [
        0xEF, 0x8B, 0x07, 0x15,
        0x1D, 0xFF, 0xCF, 0xF8,
        0x8D, 0xDD, 0x46, 0x7E,
        0x03, 0x34, 0x60, 0x56,
    ]
    assert keys4[0] == [
        0x30, 0xE4, 0x06, 0x92,
        0xBE, 0x31, 0x69, 0xFA,
        0x29, 0xF3, 0xB0, 0x3D,
        0x65, 0x9F, 0x2F, 0x60,
    ]

    block_counter += 1
    keys1, keys2, keys3, keys4 = blake.derive_keys(key_count, block_counter, KDFDomain.HDR)
    assert len(keys1) == len(keys2) == key_count
    assert keys1[0] == [
        0xA7, 0x33, 0x26, 0x81,
        0x2D, 0x13, 0xEA, 0xC9,
        0xED, 0xEF, 0x73, 0xDD,
        0xC6, 0xBF, 0x3B, 0x8F,
    ]
    assert keys2[0] == [
        0xA8, 0x4A, 0xC8, 0xDE,
        0xB0, 0x55, 0xBE, 0xA4,
        0xD3, 0x2D, 0x62, 0x65,
        0x39, 0x2F, 0xC5, 0x63,
    ]
    assert keys3[0] == [
        0x2E, 0xA7, 0xFF, 0x38,
        0x7A, 0x06, 0x29, 0x9A,
        0x0B, 0xDF, 0xE9, 0x50,
        0xA6, 0xCD, 0xB0, 0x96,
    ]
    assert keys4[0] == [
        0xFF, 0x6A, 0x7D, 0x2D,
        0x84, 0xCD, 0xB4, 0x9C,
        0x9F, 0x8B, 0xA6, 0x0C,
        0xCA, 0x83, 0x1A, 0xEA,
    ]

    block_counter += 1
    keys1, keys2, keys3, keys4 = blake.derive_keys(key_count, block_counter, KDFDomain.CHK)
    assert len(keys1) == len(keys2) == key_count
    assert keys1[0] == [
        0xFF, 0x70, 0xF1, 0x92,
        0xE7, 0xBD, 0x58, 0x85,
        0x37, 0x23, 0xA7, 0x3B,
        0xBA, 0x6D, 0x55, 0xE6,
    ]
    assert keys2[0] == [
        0xFE, 0xC0, 0xAA, 0x27,
        0x03, 0xBA, 0x02, 0x63,
        0xD3, 0x07, 0x58, 0x90,
        0x8E, 0x6F, 0xB6, 0x2C,
    ]
    assert keys3[0] == [
        0x93, 0x42, 0xC4, 0x88,
        0xB6, 0x5D, 0xD3, 0x9D,
        0xE8, 0x16, 0xB6, 0x0B,
        0x84, 0xF1, 0xC7, 0x1E,
    ]
    assert keys4[0] == [
        0x24, 0xB8, 0xBC, 0x9C,
        0x08, 0x2F, 0x0B, 0xBE,
        0x0B, 0xA9, 0x66, 0x6A,
        0xC5, 0xC4, 0xB8, 0x87,
    ]
