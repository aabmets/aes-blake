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
from src.blake_keygen import BlakeKeyGen, KDFDomain
from src.uint import Uint32
from src import debug

__all__ = [
    "create_keygen",
    "fixture_set_domain_test",
    "fixture_compress_domain_test",
    "test_mix_method",
    "test_mix_into_state",
    "test_permute",
    "test_set_params",
    "test_secret_counter_offset",
    "test_digest_context",
    "test_compress_domains",
    "test_normal_use_case",
    "test_compute_cipher_ops_round_keys",
    "test_compute_header_chk_round_keys"
]


def create_keygen(key: bytes = None, nonce: bytes = None, context: bytes = None):
    key = utils.pad_trunc_to_size(key or b"\x00", size=64)
    nonce = utils.pad_trunc_to_size(nonce or b"\x00", size=32)
    keygen = BlakeKeyGen(key, nonce)
    if context is not None:
        keygen.digest_context(context)
    return keygen


@pytest.fixture(name="set_domain_test", scope="function")
def fixture_set_domain_test():
    def closure(domain: KDFDomain) -> None:
        keygen = create_keygen()
        keygen.set_params(domain=domain)
        for idx in range(4):
            expected = domain.value ^ keygen.ivs[idx]
            assert keygen.state[idx + 8].value == expected
    return closure


@pytest.fixture(name="compress_domain_test", scope="function")
def fixture_compress_domain_test():
    def closure(domain: KDFDomain, expected: list[int]) -> None:
        keygen = create_keygen()
        message = utils.bytes_to_uint32_vector(data=b"", size=16)
        keygen.compress(message, counter=0xABCDEF, domain=domain)
        for i in range(16):
            assert keygen.state[i].value == expected[i]
    return closure


def test_mix_method():
    keygen = create_keygen()
    one, zero = Uint32(1), Uint32(0)

    keygen.mix(0, 4, 8, 12, one, zero)
    assert keygen.state[0].value == 0x775BC884
    assert keygen.state[4].value == 0x1A63ED2B
    assert keygen.state[8].value == 0x46AD5D0E
    assert keygen.state[12].value == 0x8A252599

    keygen.mix(0, 4, 8, 12, one, zero)
    assert keygen.state[0].value == 0xE9FC8109
    assert keygen.state[4].value == 0x3664D90A
    assert keygen.state[8].value == 0x6A504E42
    assert keygen.state[12].value == 0x9379D59A


def test_mix_into_state():
    keygen = create_keygen()
    message = [Uint32(1)] + [Uint32(0)] * 15

    keygen.mix_into_state(message)
    expected = [
        0xE4956CBE, 0xA2855E81, 0x6E5A4364, 0xCC106FD6,
        0x35B59AD3, 0xFB9F5EAF, 0x1CBB4EAC, 0x1638E583,
        0x2567DEFA, 0x7AC8358C, 0x58904051, 0x3811C86A,
        0x6A4701E8, 0xD1630D37, 0x2B25AE61, 0x340FFA54,
    ]
    for i in range(16):
        assert keygen.state[i].value == expected[i]

    keygen.mix_into_state(message)
    expected = [
        0xE8E7D892, 0xFC8943FE, 0x706C30F3, 0xD32F55D6,
        0xBFFD818A, 0x81AEF3FC, 0x8F395494, 0x7C3CDFAC,
        0xCA8EEEF3, 0x7E02273A, 0xA03F24E7, 0xF03611CD,
        0x63F260CF, 0x8C7ED7D1, 0xEB3FD38D, 0x0890BD3F,
    ]
    for i in range(16):
        assert keygen.state[i].value == expected[i]


def test_permute():
    keygen = create_keygen()
    message = [Uint32(c) for c in b"ABCDEFGHIJKLMNOP"]

    expected = [c for c in b"CGDKHAENBLMFJOPI"]
    message = keygen.permute(message)
    assert message == expected

    expected = [c for c in b"DEKMNCHOGFJALPIB"]
    message = keygen.permute(message)
    assert message == expected


def test_set_params(set_domain_test):
    set_domain_test(KDFDomain.DIGEST_CTX)
    set_domain_test(KDFDomain.CIPHER_OPS)
    set_domain_test(KDFDomain.HEADER_CHK)
    set_domain_test(KDFDomain.LAST_ROUND)

    keygen = create_keygen()
    keygen.set_params(counter=0xAABBCCDDEEFFAABB)
    for idx in range(4):
        assert keygen.state[idx].value == 0x52630E1E + idx


def test_secret_counter_offset():
    keygen = create_keygen()

    sco = keygen.secret_counter_offset(key=b"", nonce=b"")
    assert sco.value == 0x6363_6363_6363_6363

    sco = keygen.secret_counter_offset(key=b"abcdefgh", nonce=b"12345678")
    assert sco.value == 0xDE98_C877_7805_B27D


def test_digest_context():
    keygen = create_keygen(context=b"")
    expected = [
        0x399D1620, 0xA2621AC0, 0x29F51A04, 0x1F13F7AF,
        0x8D776B1C, 0x0244D549, 0x70A116B3, 0x3F66E539,
        0xE0691A2C, 0x6535B547, 0xFF49BA9B, 0x8E13452A,
        0x0F08BB82, 0xCA21768B, 0x6FCC0BEE, 0x1790216F,
    ]
    for i in range(16):
        assert keygen.state[i].value == expected[i]


def test_compress_domains(compress_domain_test):
    compress_domain_test(KDFDomain.DIGEST_CTX, [
        0xEBF49ABC, 0x4B200B26, 0xFCF7637E, 0xA6FE256D,
        0x88740987, 0x0F6900EB, 0xC9DA2C00, 0x2DFACD66,
        0x89C99BF0, 0xCC469E0C, 0x7E796336, 0x1391F5C8,
        0x024B8EC1, 0xC7A606F8, 0xED2C41DB, 0x85807658,
    ])
    compress_domain_test(KDFDomain.CIPHER_OPS, [
        0x5C8EF04B, 0x75CD610B, 0xDB6DDFBE, 0xF715591C,
        0x36F580F7, 0xB94220F3, 0x9F1EDD4C, 0x127883F1,
        0x2A8C9271, 0xAB9EA989, 0xC2869952, 0x5FD2E167,
        0x30F70FE6, 0x37AF48F4, 0x84B18399, 0x7DCF4A9A,
    ])
    compress_domain_test(KDFDomain.HEADER_CHK, [
        0x370496E5, 0x7D3A3DD0, 0x19E886BE, 0xEF1DB362,
        0xE3ADEFDB, 0xCC09BDC5, 0x38840FF5, 0x44786B93,
        0x5D35BC5B, 0x1A9702FC, 0x4A55A88D, 0x33A358F1,
        0xA5AE192A, 0x891F6FD2, 0x78254469, 0xF2519F6D,
    ])


def test_normal_use_case():
    keygen = create_keygen(key=b"\x00", nonce=b"\x00", context=b"\x00")
    expected = [
        0x399D1620, 0xA2621AC0, 0x29F51A04, 0x1F13F7AF,
        0x8D776B1C, 0x0244D549, 0x70A116B3, 0x3F66E539,
        0xE0691A2C, 0x6535B547, 0xFF49BA9B, 0x8E13452A,
        0x0F08BB82, 0xCA21768B, 0x6FCC0BEE, 0x1790216F,
    ]
    for i in range(16):
        assert keygen.state[i].value == expected[i]

    keygen = create_keygen(key=b"\x00", nonce=b"\x01", context=b"\x00")
    expected = [
        0x8A58A08C, 0x40A1CC53, 0x546B524E, 0x6C7711B5,
        0xA8C48F0A, 0xDB5FD5FB, 0xDB59D518, 0x760707B2,
        0xE3613B78, 0x4E996AB7, 0x0C257323, 0xA8F997E5,
        0xFA431A69, 0xF0BA71F3, 0x9BE0C557, 0x81865058,
    ]
    for i in range(16):
        assert keygen.state[i].value == expected[i]

    keygen = create_keygen(key=b"\x01", nonce=b"\x00", context=b"\x00")
    expected = [
        0x2A9B4872, 0x18DAF922, 0xD6AB255A, 0x785DFD6A,
        0xB968FB68, 0x4FD4BB15, 0x5160FD6D, 0x3C8FD4CB,
        0x3C458F06, 0x65FD2C8A, 0xB536B2C0, 0x78CC4A18,
        0x1A0680D6, 0x22C889DA, 0xDE69F585, 0x610EE907,
    ]
    for i in range(16):
        assert keygen.state[i].value == expected[i]

    keygen = create_keygen(key=b"\x01", nonce=b"\x01", context=b"\x00")
    expected = [
        0x0AE60292, 0x60DC7584, 0x83576090, 0x7E07FD41,
        0x89742A93, 0xEB70BE8D, 0x9DFBD88A, 0xDDBAC832,
        0xB88D8FD8, 0x3E40B66F, 0xD0787539, 0x0F7BFCB2,
        0x6987608C, 0xF83C8438, 0x2EFFD192, 0xD1AD2DF5,
    ]
    for i in range(16):
        assert keygen.state[i].value == expected[i]


def test_compute_cipher_ops_round_keys():
    keygen = create_keygen(context=b"\x00")
    expected = [
        0x399D1620, 0xA2621AC0, 0x29F51A04, 0x1F13F7AF,
        0x8D776B1C, 0x0244D549, 0x70A116B3, 0x3F66E539,
        0xE0691A2C, 0x6535B547, 0xFF49BA9B, 0x8E13452A,
        0x0F08BB82, 0xCA21768B, 0x6FCC0BEE, 0x1790216F,
    ]
    assert keygen.state == expected
    round_keys = keygen.compute_round_keys(counter=0x0, domain=KDFDomain.CIPHER_OPS)
    assert keygen.state == expected

    assert round_keys[0] == [
        0x5E, 0x07, 0x57, 0xAF,
        0xD3, 0x89, 0xDF, 0x42,
        0x17, 0x00, 0xA9, 0x23,
        0x5B, 0xF6, 0xA1, 0xBF,
    ]
    assert round_keys[1] == [
        0x61, 0x13, 0x46, 0x3E,
        0x98, 0xFB, 0x26, 0x34,
        0x2A, 0xC0, 0x5D, 0xF4,
        0x1A, 0xE9, 0x7D, 0xA3,
    ]
    assert round_keys[2] == [
        0x63, 0x80, 0x45, 0xB8,
        0x77, 0x50, 0x24, 0xB6,
        0x70, 0x66, 0x68, 0x43,
        0x52, 0xE6, 0x49, 0xD6,
    ]
    assert round_keys[3] == [
        0xAE, 0xDE, 0x7E, 0xFE,
        0xBE, 0x77, 0x40, 0x01,
        0x21, 0xD2, 0xA9, 0xEF,
        0xCC, 0x00, 0x69, 0x4E,
    ]
    assert round_keys[4] == [
        0x89, 0x50, 0xC6, 0xC8,
        0xEA, 0x0C, 0xA2, 0xEC,
        0x30, 0x04, 0x84, 0x0A,
        0x85, 0xFC, 0x1D, 0x3A,
    ]
    assert round_keys[5] == [
        0x90, 0xA6, 0x15, 0x46,
        0x67, 0x95, 0x88, 0x92,
        0x29, 0x7F, 0x6D, 0x4C,
        0x0F, 0xBC, 0x50, 0x85,
    ]
    assert round_keys[6] == [
        0x1D, 0xA1, 0xD3, 0xAE,
        0xCB, 0x6E, 0x1E, 0x1E,
        0xE4, 0xFA, 0xE6, 0x72,
        0xF7, 0x08, 0x2B, 0x90,
    ]
    assert round_keys[7] == [
        0x54, 0x2B, 0xE9, 0x6F,
        0x47, 0x67, 0xE3, 0xCD,
        0x74, 0xAF, 0x19, 0x98,
        0xC0, 0x2E, 0x0C, 0x4E,
    ]
    assert round_keys[8] == [
        0x49, 0xA3, 0x8F, 0xD2,
        0x65, 0x34, 0x4E, 0x3F,
        0x2B, 0x46, 0x36, 0xC8,
        0x56, 0x99, 0x62, 0x80,
    ]
    assert round_keys[9] == [
        0xCF, 0x55, 0x40, 0x82,
        0x58, 0xC2, 0x52, 0xD4,
        0x6C, 0x71, 0xD3, 0x22,
        0x78, 0x72, 0x87, 0x51,
    ]
    assert round_keys[10] == [
        0x37, 0xDE, 0xB9, 0x4D,
        0xCA, 0x96, 0xDB, 0xDD,
        0xBA, 0x87, 0x64, 0x3C,
        0x88, 0xEC, 0xFC, 0x9D,
    ]


def test_compute_header_chk_round_keys():
    keygen = create_keygen(context=b"\x00")
    expected = [
        0x399D1620, 0xA2621AC0, 0x29F51A04, 0x1F13F7AF,
        0x8D776B1C, 0x0244D549, 0x70A116B3, 0x3F66E539,
        0xE0691A2C, 0x6535B547, 0xFF49BA9B, 0x8E13452A,
        0x0F08BB82, 0xCA21768B, 0x6FCC0BEE, 0x1790216F,
    ]
    assert keygen.state == expected
    round_keys = keygen.compute_round_keys(counter=0x0, domain=KDFDomain.HEADER_CHK)
    assert keygen.state == expected

    assert round_keys[0] == [
        0x41, 0xD5, 0x89, 0xD5,
        0x11, 0xCB, 0x64, 0x56,
        0xA9, 0x5D, 0x44, 0x40,
        0x83, 0xC6, 0xF9, 0x35,
    ]
    assert round_keys[1] ==  [
        0x65, 0x15, 0x7B, 0x35,
        0xC4, 0x98, 0x87, 0x2E,
        0x0E, 0x46, 0x46, 0x45,
        0xC9, 0x45, 0x27, 0x6F,
    ]
    assert round_keys[2] == [
        0xAD, 0x7F, 0xCE, 0x89,
        0x71, 0x3E, 0xFA, 0x41,
        0x93, 0x85, 0x1B, 0x66,
        0x9A, 0x60, 0x3E, 0xB9,
    ]
    assert round_keys[3] == [
        0x02, 0x14, 0x7D, 0x96,
        0x07, 0x70, 0x36, 0x24,
        0x43, 0x8A, 0xF7, 0xD0,
        0x71, 0x18, 0xEB, 0x3D,
    ]
    assert round_keys[4] == [
        0x64, 0x30, 0xBB, 0xB2,
        0x87, 0xC9, 0x8F, 0xD6,
        0x0C, 0x8D, 0x07, 0xF8,
        0x65, 0x01, 0x6A, 0x8B,
    ]
    assert round_keys[5] == [
        0x30, 0xD7, 0xEF, 0x36,
        0x23, 0x9A, 0x1A, 0x79,
        0xE3, 0x1A, 0x66, 0xCE,
        0x45, 0xB9, 0x22, 0xA7,
    ]
    assert round_keys[6] == [
        0xC2, 0x56, 0xF3, 0x35,
        0x4F, 0x5E, 0xA2, 0x97,
        0xC9, 0x78, 0x2F, 0xBC,
        0xF4, 0x8E, 0xDE, 0x03,
    ]
    assert round_keys[7] == [
        0x03, 0x8C, 0x68, 0xE2,
        0xD2, 0xE4, 0x24, 0x51,
        0xB5, 0xB4, 0x79, 0x59,
        0x24, 0xFD, 0x24, 0xB4,
    ]
    assert round_keys[8] == [
        0x53, 0x10, 0xDD, 0xF7,
        0x7D, 0xB4, 0xF2, 0x0E,
        0xD2, 0x90, 0x75, 0x4F,
        0x59, 0xB1, 0xC0, 0x73,
    ]
    assert round_keys[9] == [
        0x63, 0x38, 0x51, 0x67,
        0x8F, 0x6B, 0xDF, 0xE9,
        0x80, 0x26, 0x4F, 0x78,
        0x88, 0x92, 0x6A, 0xBC,
    ]
    assert round_keys[10] == [
        0x50, 0xDA, 0xDF, 0x45,
        0xD7, 0x4A, 0x3A, 0xE6,
        0x18, 0x8C, 0xBA, 0xE0,
        0xA4, 0x9F, 0x77, 0x17,
    ]
