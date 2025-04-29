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

    keys1, keys2 = blake.derive_keys(key_count, block_counter, KDFDomain.CIPHER_BGN)
    assert len(keys1) == len(keys2) == key_count

    assert keys1[0] == [
        0x8B, 0x84, 0x15, 0x3E, 0x50, 0x3E, 0x69, 0xB9,
        0x73, 0xDC, 0x56, 0xE4, 0xD7, 0xA8, 0x46, 0x61
    ]
    assert keys2[0] == [
        0x42, 0xA3, 0x66, 0x8E, 0xB8, 0x43, 0xFB, 0x16,
        0xF0, 0xC2, 0x85, 0x28, 0xA3, 0x2E, 0x0E, 0x91,
    ]

    block_counter += 1
    keys1, keys2 = blake.derive_keys(key_count, block_counter, KDFDomain.CIPHER_MID)
    assert len(keys1) == len(keys2) == key_count

    assert keys1[0] == [
        0x0E, 0xBD, 0x72, 0x2F, 0x5A, 0xAF, 0x47, 0x62,
        0xB2, 0x48, 0x1C, 0xE9, 0x53, 0x83, 0xAE, 0xA8,
    ]
    assert keys2[0] == [
        0x96, 0x2E, 0x56, 0xF3, 0xF1, 0x40, 0x40, 0xF6,
        0x83, 0x37, 0xBD, 0x6A, 0x2D, 0x68, 0x79, 0xD3,
    ]

    block_counter += 1
    keys1, keys2 = blake.derive_keys(key_count, block_counter, KDFDomain.CIPHER_END)
    assert len(keys1) == len(keys2) == key_count

    assert keys1[0] == [
        0xF0, 0x3F, 0x5F, 0xF6, 0xC3, 0x73, 0x85, 0x25,
        0x1B, 0xCF, 0x82, 0x96, 0x06, 0x61, 0xEE, 0xF7,
    ]
    assert keys2[0] == [
        0xC1, 0x59, 0x10, 0x5E, 0xBE, 0x46, 0x2D, 0xCE,
        0xEF, 0x2A, 0xD1, 0xC6, 0xDB, 0x7A, 0x13, 0x38,
    ]

    block_counter += 1
    keys1, keys2 = blake.derive_keys(key_count, block_counter, KDFDomain.HEADER_BGN)
    assert len(keys1) == len(keys2) == key_count

    assert keys1[0] == [
        0x60, 0x97, 0x26, 0x68, 0x0A, 0x12, 0x76, 0xFD,
        0x22, 0xBB, 0x05, 0xDA, 0x11, 0x32, 0xC5, 0xD8,
    ]
    assert keys2[0] == [
        0x89, 0x92, 0x78, 0x5C, 0xAE, 0x7A, 0x06, 0x2B,
        0xB6, 0x08, 0x55, 0xDA, 0x8D, 0x8B, 0x94, 0x37,
    ]

    block_counter += 1
    keys1, keys2 = blake.derive_keys(key_count, block_counter, KDFDomain.HEADER_MID)
    assert len(keys1) == len(keys2) == key_count

    assert keys1[0] == [
        0x59, 0x44, 0xC9, 0x2A, 0x80, 0x1E, 0xA1, 0x49,
        0x3D, 0x55, 0xCC, 0x20, 0xE1, 0x6D, 0x1E, 0x3D,
    ]
    assert keys2[0] == [
        0x62, 0xB7, 0x43, 0x1C, 0x62, 0xDE, 0xD4, 0x6B,
        0x2E, 0x47, 0x17, 0x5D, 0xF7, 0xF4, 0x79, 0xB6,
    ]

    block_counter += 1
    keys1, keys2 = blake.derive_keys(key_count, block_counter, KDFDomain.HEADER_END)
    assert len(keys1) == len(keys2) == key_count

    assert keys1[0] == [
        0x49, 0x3D, 0x68, 0x94, 0x5F, 0x01, 0xC1, 0xE3,
        0x6F, 0x68, 0xA3, 0xC3, 0xA4, 0x9B, 0x68, 0x31,
    ]
    assert keys2[0] == [
        0x55, 0x2F, 0xA9, 0xA8, 0x35, 0x25, 0x09, 0x7A,
        0x29, 0x80, 0x6D, 0x0A, 0x96, 0x48, 0xB6, 0xEA,
    ]


def test_blake64_derive_keys():
    blake = Blake64(key=b'', nonce=b'', context=b'')
    blake.digest_context()
    key_count, block_counter = 10, 0

    keys1, keys2, keys3, keys4 = blake.derive_keys(key_count, block_counter, KDFDomain.CIPHER_BGN)
    assert len(keys1) == len(keys2) == key_count

    assert keys1[0] == [
        0xDD, 0x53, 0xEE, 0xC5, 0x3A, 0xD2, 0xBA, 0x87,
        0x28, 0x58, 0xCF, 0x81, 0x10, 0x77, 0x12, 0x80,
    ]
    assert keys2[0] == [
        0xC2, 0xC0, 0xB5, 0xEB, 0x0A, 0xDA, 0x34, 0xF4,
        0xED, 0x65, 0xCD, 0x62, 0xA9, 0x3F, 0xA2, 0x9D,
    ]
    assert keys3[0] == [
        0x21, 0x4C, 0x59, 0x1B, 0xDA, 0xEE, 0x01, 0x5E,
        0x7B, 0x3E, 0x28, 0xF6, 0xB0, 0x35, 0x04, 0x9D,
    ]
    assert keys4[0] == [
        0x09, 0xE2, 0x9E, 0xF2, 0x35, 0x73, 0x71, 0x64,
        0x0A, 0x1B, 0x27, 0xC1, 0xE7, 0x7D, 0xCF, 0x56,
    ]

    block_counter += 1
    keys1, keys2, keys3, keys4 = blake.derive_keys(key_count, block_counter, KDFDomain.CIPHER_MID)
    assert len(keys1) == len(keys2) == key_count

    assert keys1[0] == [
        0x8C, 0xC7, 0x14, 0x60, 0x43, 0x3B, 0xE5, 0xD2,
        0xDB, 0x60, 0x6C, 0x01, 0x56, 0xB1, 0x42, 0xCE,
    ]
    assert keys2[0] == [
        0x06, 0x62, 0x5E, 0x1C, 0x6C, 0xC3, 0xED, 0x04,
        0x35, 0x80, 0x3B, 0x75, 0x94, 0x61, 0xCE, 0x6C,
    ]
    assert keys3[0] == [
        0x1A, 0x02, 0xE6, 0x31, 0x4A, 0xDE, 0xA2, 0x47,
        0xE6, 0xD1, 0xCC, 0x5B, 0x9C, 0x76, 0x56, 0xF0,
    ]
    assert keys4[0] == [
        0x76, 0xA7, 0x51, 0x6C, 0x16, 0xAB, 0x6B, 0x5C,
        0xCB, 0x9F, 0x59, 0xC5, 0x7B, 0xF9, 0xD5, 0x9A,
    ]

    block_counter += 1
    keys1, keys2, keys3, keys4 = blake.derive_keys(key_count, block_counter, KDFDomain.CIPHER_END)
    assert len(keys1) == len(keys2) == key_count

    assert keys1[0] == [
        0xB4, 0x8B, 0x74, 0x13, 0x79, 0x0F, 0xC5, 0x15,
        0x9D, 0x63, 0xB3, 0x48, 0x38, 0x8B, 0x67, 0xC6,
    ]
    assert keys2[0] == [
        0xC2, 0xFC, 0x40, 0x95, 0x0B, 0x86, 0x8B, 0xC0,
        0xAF, 0xE3, 0x09, 0x5D, 0x4E, 0xA7, 0x21, 0x32,
    ]
    assert keys3[0] == [
        0xC7, 0x6F, 0x8C, 0x10, 0x66, 0x4D, 0x3B, 0x13,
        0x4F, 0xBD, 0x2E, 0x84, 0x51, 0x88, 0xC5, 0xA2,
    ]
    assert keys4[0] == [
        0x24, 0xFE, 0x94, 0x4A, 0xFB, 0x65, 0xFD, 0x69,
        0x4E, 0x44, 0x28, 0xE6, 0xC9, 0xB3, 0x2F, 0xA7,
    ]

    block_counter += 1
    keys1, keys2, keys3, keys4 = blake.derive_keys(key_count, block_counter, KDFDomain.HEADER_BGN)
    assert len(keys1) == len(keys2) == key_count

    assert keys1[0] == [
        0x4E, 0x89, 0x90, 0xD9, 0x80, 0x91, 0x3A, 0x41,
        0x73, 0x48, 0xDA, 0x81, 0x3F, 0xEA, 0x52, 0x20,
    ]
    assert keys2[0] == [
        0xEE, 0x0E, 0x9A, 0x5B, 0x83, 0xAE, 0xDE, 0xD0,
        0xFF, 0xD1, 0x89, 0x45, 0x70, 0xEC, 0xFD, 0x2C,
    ]
    assert keys3[0] == [
        0x61, 0x35, 0x2E, 0xAF, 0xED, 0xE0, 0xDF, 0x27,
        0xD7, 0x14, 0x50, 0x0E, 0x7E, 0xE2, 0x1E, 0x6A,
    ]
    assert keys4[0] == [
        0xBF, 0xFB, 0xA2, 0x16, 0x39, 0xB1, 0xD4, 0x1E,
        0x4E, 0xA6, 0x82, 0x8A, 0x78, 0xAE, 0xFC, 0xF8,
    ]

    block_counter += 1
    keys1, keys2, keys3, keys4 = blake.derive_keys(key_count, block_counter, KDFDomain.HEADER_MID)
    assert len(keys1) == len(keys2) == key_count

    assert keys1[0] == [
        0x60, 0x8B, 0x91, 0x10, 0x16, 0x5D, 0x20, 0x57,
        0xE1, 0xE8, 0x62, 0x6D, 0xCA, 0xF0, 0x92, 0x75,
    ]
    assert keys2[0] == [
        0x2B, 0x9E, 0x13, 0x90, 0xAA, 0x86, 0x6D, 0xE2,
        0xDF, 0xBE, 0x46, 0x2E, 0x44, 0x06, 0xE9, 0x2E,
    ]
    assert keys3[0] == [
        0x6F, 0xF5, 0x97, 0x8F, 0x20, 0x94, 0xA0, 0xBD,
        0xD6, 0x3B, 0x18, 0xA0, 0x74, 0xC9, 0xE5, 0x91,
    ]
    assert keys4[0] == [
        0x41, 0x50, 0xC4, 0x4B, 0x68, 0x65, 0x7C, 0xA5,
        0x49, 0x38, 0x11, 0xB6, 0x22, 0xA1, 0x46, 0xF4,
    ]

    block_counter += 1
    keys1, keys2, keys3, keys4 = blake.derive_keys(key_count, block_counter, KDFDomain.HEADER_END)
    assert len(keys1) == len(keys2) == key_count

    assert keys1[0] == [
        0x05, 0x0D, 0xB3, 0xAB, 0x35, 0xC5, 0xEC, 0x91,
        0x39, 0x3E, 0x59, 0x95, 0xBA, 0x2A, 0xCE, 0x26,
    ]
    assert keys2[0] == [
        0x47, 0x9F, 0x24, 0x7C, 0x41, 0xEF, 0x80, 0xA2,
        0x5B, 0xEB, 0x0B, 0x38, 0xFA, 0x56, 0x6F, 0x61,
    ]
    assert keys3[0] == [
        0xEB, 0xDD, 0x2A, 0x02, 0x92, 0xB9, 0x57, 0x83,
        0x65, 0x02, 0x9A, 0x34, 0x6F, 0xCE, 0x67, 0x14,
    ]
    assert keys4[0] == [
        0x72, 0xF4, 0xC7, 0x8D, 0x08, 0xC0, 0x6F, 0x23,
        0x0D, 0x8E, 0x57, 0xB1, 0xF3, 0x18, 0x7B, 0x41,
    ]
