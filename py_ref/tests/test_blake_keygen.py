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
    "test_sub_bytes"
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
        0xA7B66833, 0x6926D56D, 0xE501C9F7, 0x1FC1DFCB,
        0xC184E2FB, 0xD135215E, 0x48E13590, 0x4560DAB6,
        0xA0831E7A, 0x8D2D9475, 0xDC7C6D11, 0x5B3C0565,
        0x43FC1B04, 0xE3FEBC43, 0xFE7564AF, 0x52188341,
    ]


def test_blake64_mix_into_state():
    msg = [Uint64(n) for n in range(0, 16)]
    blake = Blake64(key=b'', nonce=b'', context=b'')
    blake.mix_into_state(msg)
    assert blake.state == [
        0x6AF7BF05144BB647, 0x8AE62C2BA7E6FAB0, 0x3F26D5E1E6DEE922, 0xDF80907FAB22F43C,
        0x836D4B302327AE87, 0x9102A352AB1DBB7E, 0x1F80B45A7C707C29, 0x54F001FD3A7E6359,
        0xE0E0E202A8FD899D, 0x6545152385879AA8, 0x7689843CA36FD20E, 0x05E578E6034A4CC0,
        0xDC37558DDEF5B17B, 0xAA1EFD2DBCF21D3A, 0x07B441B2C60A8720, 0x47C378952513C57A,
    ]


def test_blake32_g_mix():
    blake = Blake32(key=b'', nonce=b'', context=b'')
    assert blake.state == [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ]

    blake.g_mix(0, 4, 8, 12, Uint32(1), Uint32(2))
    assert blake.state == [
        0x1A8527DD, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0xA07D7D18, 0x00000000, 0x00000000, 0x00000000,
        0x8EC5CD23, 0x00000000, 0x00000000, 0x00000000,
        0xDAAE921C, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ]

    blake.g_mix(1, 5, 9, 13, Uint32(1), Uint32(2))
    assert blake.state ==  [
        0x1A8527DD, 0xC1940F2A, 0x3C6EF372, 0xA54FF53A,
        0xA07D7D18, 0x66107BBC, 0x00000000, 0x00000000,
        0x8EC5CD23, 0x0E11BE91, 0x00000000, 0x00000000,
        0xDAAE921C, 0x48079E2F, 0x1F83D9AB, 0x5BE0CD19,
    ]

    blake.g_mix(2, 6, 10, 14, Uint32(1), Uint32(2))
    assert blake.state == [
        0x1A8527DD, 0xC1940F2A, 0x7B41A0F7, 0xA54FF53A,
        0xA07D7D18, 0x66107BBC, 0xE4F7F621, 0x00000000,
        0x8EC5CD23, 0x0E11BE91, 0x4529BD70, 0x00000000,
        0xDAAE921C, 0x48079E2F, 0x1A519983, 0x5BE0CD19,
    ]

    blake.g_mix(3, 7, 11, 15, Uint32(1), Uint32(2))
    assert blake.state ==  [
        0x1A8527DD, 0xC1940F2A, 0x7B41A0F7, 0x9043776C,
        0xA07D7D18, 0x66107BBC, 0xE4F7F621, 0x2E2271C4,
        0x8EC5CD23, 0x0E11BE91, 0x4529BD70, 0xFBCB6038,
        0xDAAE921C, 0x48079E2F, 0x1A519983, 0xC3A86189,
    ]


def test_blake64_g_mix():
    blake = Blake64(key=b'', nonce=b'', context=b'')
    assert blake.state == [
        0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
        0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
    ]

    blake.g_mix(0, 4, 8, 12, Uint64(1), Uint64(2))
    assert blake.state ==  [
        0x71BDFEC64E08A146, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
        0xE818C7C354DBE238, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x73B87BBFF0262927, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x155E2FE7B51E750F, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
    ]

    blake.g_mix(1, 5, 9, 13, Uint64(1), Uint64(2))
    assert blake.state == [
        0x71BDFEC64E08A146, 0x1E2DB8357995CA5E, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
        0xE818C7C354DBE238, 0xBD14EAA6CF640641, 0x0000000000000000, 0x0000000000000000,
        0x73B87BBFF0262927, 0xBC4C7CFC93792000, 0x0000000000000000, 0x0000000000000000,
        0x155E2FE7B51E750F, 0x0C57B1D9731659F7, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
    ]

    blake.g_mix(2, 6, 10, 14, Uint64(1), Uint64(2))
    assert blake.state ==  [
        0x71BDFEC64E08A146, 0x1E2DB8357995CA5E, 0x2999CC78D3DA3F51, 0xA54FF53A5F1D36F1,
        0xE818C7C354DBE238, 0xBD14EAA6CF640641, 0xECEF512CF0D0B867, 0x0000000000000000,
        0x73B87BBFF0262927, 0xBC4C7CFC93792000, 0x1B5D7193AD2D1B10, 0x0000000000000000,
        0x155E2FE7B51E750F, 0x0C57B1D9731659F7, 0x15882C4C893FF037, 0x5BE0CD19137E2179,
    ]

    blake.g_mix(3, 7, 11, 15, Uint64(1), Uint64(2))
    assert blake.state == [
        0x71BDFEC64E08A146, 0x1E2DB8357995CA5E, 0x2999CC78D3DA3F51, 0x54881886C234C2F2,
        0xE818C7C354DBE238, 0xBD14EAA6CF640641, 0xECEF512CF0D0B867, 0xD0182676DD57FE81,
        0x73B87BBFF0262927, 0xBC4C7CFC93792000, 0x1B5D7193AD2D1B10, 0x473430770DBC74BE,
        0x155E2FE7B51E750F, 0x0C57B1D9731659F7, 0x15882C4C893FF037, 0xFAD118EB0F0D3C9B,
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
    init_state = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ]
    assert blake.state == init_state

    blake.sub_bytes(SBox.ENC)
    assert blake.state == [
        0x02018E85, 0xEA85E497, 0xEB9F0D40, 0x0684E680,
        0x63636363, 0x63636363, 0x63636363, 0x63636363,
        0x63636363, 0x63636363, 0x63636363, 0x63636363,
        0xD1AB00D2, 0x146B4564, 0xC0EC3562, 0x39E1BDD4,
    ]

    blake.sub_bytes(SBox.DEC)
    assert blake.state == init_state

    blake = Blake64(key=b'', nonce=b'', context=b'')
    init_state = [
        0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
        0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
    ]
    assert blake.state == init_state

    blake.sub_bytes(SBox.ENC)
    assert blake.state == [
        0x02018E850D65DD30, 0xEA85E4975F745CE2, 0xEB9F0D40BB2241F1, 0x0684E680CFA405A1,
        0x6363636363636363, 0x6363636363636363, 0x6363636363636363, 0x6363636363636363,
        0x6363636363636363, 0x6363636363636363, 0x6363636363636363, 0x6363636363636363,
        0xD1AB00D2958E133E, 0x146B4564F1B250C0, 0xC0EC35620F837A7F, 0x39E1BDD47DF3FDB6,
    ]

    blake.sub_bytes(SBox.DEC)
    assert blake.state == init_state
