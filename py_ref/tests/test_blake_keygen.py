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
    "test_compute_block_counter_base",
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
        for _ in keygen.compress(message, counter=0xABCDEF, domain=domain):
            pass
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
    for i, val in enumerate([0x1E0E6352] * 4):
        assert keygen.state[i].value == val + i


def test_compute_block_counter_base():
    keygen = create_keygen()

    bib = keygen.compute_block_counter_base(key=b"", nonce=b"")
    assert bib.value == 0x6363_6363_6363_6363

    bib = keygen.compute_block_counter_base(key=b"abcdefgh", nonce=b"12345678")
    assert bib.value == 0x7DB2_0578_77C8_98DE


def test_digest_context():
    keygen = create_keygen(context=b"")
    expected = [
        0x954FF7F5, 0xA3C2B154, 0xD1260253, 0x5BAB6CA8,
        0x6093B341, 0x5C3F6DD7, 0x25966A3F, 0x0D433E36,
        0x3C3A589D, 0x94619DCC, 0xACAD2391, 0x39C36159,
        0xBA7710A2, 0x7AFDD1F2, 0xC314A707, 0xA13B483C,
    ]
    for i in range(16):
        assert keygen.state[i].value == expected[i]


def test_compress_domains(compress_domain_test):
    compress_domain_test(KDFDomain.DIGEST_CTX, [
        0x14291D2D, 0x49758B83, 0xDF546A03, 0x32D30148,
        0x3AA0D214, 0x8E3F71E7, 0xE7ECD9BF, 0xEE9DAABE,
        0xE7DBF6E4, 0xA996F33F, 0xDE4D1BEF, 0x57800D98,
        0x662E5C80, 0x48C73389, 0x62BAF283, 0x3FAD1054,
    ])
    compress_domain_test(KDFDomain.CIPHER_OPS, [
        0xA43B3C25, 0xEFDAC7AE, 0x6E763286, 0x673DE76F,
        0x3387861B, 0x51A22F97, 0xA8BA43F0, 0xC565AFC6,
        0xFC4EA6CA, 0xC63904AB, 0xC05D2999, 0xBAFC4A57,
        0x6B044B52, 0x6AC5E004, 0x6F4A64BA, 0x7EC84436,
    ])
    compress_domain_test(KDFDomain.HEADER_CHK, [
        0x74AAC388, 0xD875BFC0, 0xF460423B, 0xFF8667D0,
        0x095C9770, 0x1AC4F86F, 0xCF2B291A, 0xF9E37227,
        0x30A38833, 0x4554D789, 0xE39FBCE4, 0xB9818A92,
        0x366B7A20, 0x5EDE2EC2, 0xFB0E76D8, 0xC6958D32,
    ])


def test_normal_use_case():
    keygen = create_keygen(key=b"\x00", nonce=b"\x00", context=b"\x00")
    expected = [
        0x954FF7F5, 0xA3C2B154, 0xD1260253, 0x5BAB6CA8,
        0x6093B341, 0x5C3F6DD7, 0x25966A3F, 0x0D433E36,
        0x3C3A589D, 0x94619DCC, 0xACAD2391, 0x39C36159,
        0xBA7710A2, 0x7AFDD1F2, 0xC314A707, 0xA13B483C,
    ]
    for i in range(16):
        assert keygen.state[i].value == expected[i]

    keygen = create_keygen(key=b"\x00", nonce=b"\x01", context=b"\x00")
    expected = [
        0xAB3C693A, 0x82972393, 0x5213C433, 0xB497B7E7,
        0x9320D367, 0xD9097FD0, 0x8B384DF7, 0xC45DF2CF,
        0x52A36318, 0x7CAE2710, 0x8E53047B, 0xC3B46B3D,
        0xE21C0CAE, 0xE5BB150B, 0x21A1871F, 0x71BF3EB7,
    ]
    for i in range(16):
        assert keygen.state[i].value == expected[i]

    keygen = create_keygen(key=b"\x01", nonce=b"\x00", context=b"\x00")
    expected = [
        0xE97C598E, 0xBCEE8B6D, 0x7B638B99, 0x49763240,
        0xBEDEB1D6, 0x859FED28, 0xFEB78E78, 0x0AD48901,
        0x583D0CDC, 0xDB2F9161, 0x432D6960, 0x9EEE76EE,
        0x00B8ED22, 0xDBB077DF, 0x497184AA, 0xC4F83168,
    ]
    for i in range(16):
        assert keygen.state[i].value == expected[i]

    keygen = create_keygen(key=b"\x01", nonce=b"\x01", context=b"\x00")
    expected = [
        0x6C306393, 0xFC1C03F2, 0x90987C8E, 0xF135BA7A,
        0xED8223B2, 0x18B1B232, 0x3ADDB36E, 0xAFC559F6,
        0x7433527F, 0xA50A36DA, 0xA8D6F5CB, 0xA0081CFB,
        0xDD915CCB, 0xEA3D5372, 0x7A287376, 0x111D2012,
    ]
    for i in range(16):
        assert keygen.state[i].value == expected[i]


def test_compute_cipher_ops_round_keys():
    keygen = create_keygen(context=b"\x00")
    expected_keygen_state = [
        0x954FF7F5, 0xA3C2B154, 0xD1260253, 0x5BAB6CA8,
        0x6093B341, 0x5C3F6DD7, 0x25966A3F, 0x0D433E36,
        0x3C3A589D, 0x94619DCC, 0xACAD2391, 0x39C36159,
        0xBA7710A2, 0x7AFDD1F2, 0xC314A707, 0xA13B483C,
    ]
    assert keygen.state == expected_keygen_state
    round_keys = keygen.compute_round_keys(counter=0x0, domain=KDFDomain.CIPHER_OPS)
    assert keygen.state == expected_keygen_state

    assert round_keys[0] == [
        0x1C, 0x2E, 0x3B, 0xAC,
        0xE0, 0x06, 0xA0, 0xC3,
        0xBF, 0x67, 0x46, 0xE0,
        0x9D, 0xF7, 0xE5, 0xF9,
    ]
    assert round_keys[1] == [
        0x4B, 0x8F, 0x33, 0x7F,
        0x21, 0x03, 0xD6, 0xE0,
        0xD6, 0x61, 0x79, 0xCF,
        0x02, 0x26, 0xA8, 0xB1,
    ]
    assert round_keys[2] == [
        0x5F, 0xA3, 0x87, 0x1D,
        0x51, 0x41, 0x84, 0x09,
        0x28, 0xD6, 0xCC, 0x37,
        0x42, 0xEE, 0xE2, 0x0D,
    ]
    assert round_keys[3] == [
        0xB8, 0xB0, 0xB3, 0x3D,
        0x7E, 0x91, 0x04, 0x71,
        0xA4, 0xF1, 0x1F, 0x8B,
        0x1C, 0x28, 0x74, 0xA5,
    ]
    assert round_keys[4] == [
        0x64, 0x3D, 0x32, 0x74,
        0x9D, 0xE2, 0xC3, 0x0A,
        0x7C, 0x44, 0x74, 0x17,
        0x54, 0x95, 0x74, 0x43,
    ]
    assert round_keys[5] == [
        0x80, 0x75, 0xB2, 0x22,
        0x99, 0x83, 0x87, 0xC3,
        0xD5, 0x24, 0xD2, 0x18,
        0x8B, 0x6E, 0x73, 0x7D,
    ]
    assert round_keys[6] == [
        0xA3, 0x7B, 0x47, 0xDA,
        0x93, 0x6C, 0x1C, 0xF7,
        0xC7, 0x92, 0x78, 0xD2,
        0x97, 0x90, 0xD6, 0x28,
    ]
    assert round_keys[7] == [
        0x82, 0x07, 0xD8, 0x65,
        0x0F, 0xEF, 0x4D, 0x43,
        0x24, 0x2C, 0xF5, 0xD6,
        0xD9, 0x1D, 0x77, 0x6D,
    ]
    assert round_keys[8] == [
        0x09, 0xBF, 0xCD, 0x69,
        0x3D, 0x41, 0xC0, 0x33,
        0x43, 0x38, 0x28, 0xF7,
        0xEB, 0x02, 0x75, 0xA3,
    ]
    assert round_keys[9] == [
        0x0F, 0x48, 0x13, 0x8A,
        0xF8, 0x5D, 0x43, 0x12,
        0x16, 0x3B, 0x87, 0xF1,
        0x39, 0x8B, 0x5B, 0x50,
    ]
    assert round_keys[10] == [
        0x9C, 0x83, 0xE1, 0x0B,
        0x24, 0x3B, 0x84, 0xDB,
        0x50, 0xAD, 0xCB, 0xCE,
        0x72, 0xC0, 0x6C, 0x2B,
    ]


def test_compute_header_chk_round_keys():
    keygen = create_keygen(context=b"\x00")
    expected_keygen_state = [
        0x954FF7F5, 0xA3C2B154, 0xD1260253, 0x5BAB6CA8,
        0x6093B341, 0x5C3F6DD7, 0x25966A3F, 0x0D433E36,
        0x3C3A589D, 0x94619DCC, 0xACAD2391, 0x39C36159,
        0xBA7710A2, 0x7AFDD1F2, 0xC314A707, 0xA13B483C,
    ]
    assert keygen.state == expected_keygen_state
    round_keys = keygen.compute_round_keys(counter=0x0, domain=KDFDomain.HEADER_CHK)
    assert keygen.state == expected_keygen_state

    assert round_keys[0] == [
        0xEE, 0x13, 0xEE, 0x80,
        0xFD, 0xE0, 0x87, 0x1E,
        0x13, 0x6B, 0xD4, 0x24,
        0x4A, 0xFB, 0xEF, 0xBA,
    ]
    assert round_keys[1] == [
        0xA6, 0x16, 0xB5, 0x55,
        0xC9, 0x88, 0xEE, 0x70,
        0x9C, 0xEA, 0xCA, 0x88,
        0x8B, 0x64, 0x52, 0xD1,
    ]
    assert round_keys[2] == [
        0xCB, 0xE9, 0xD0, 0xBD,
        0x9A, 0x8D, 0x64, 0x5E,
        0x2F, 0x3B, 0x84, 0x0B,
        0x48, 0x09, 0x41, 0x92,
    ]
    assert round_keys[3] == [
        0x1A, 0xF9, 0x62, 0x72,
        0x1F, 0x8C, 0xDA, 0xCB,
        0xDC, 0x20, 0xC4, 0xD8,
        0x1A, 0x47, 0xF0, 0xE7,
    ]
    assert round_keys[4] == [
        0xE3, 0xA6, 0xB8, 0x5C,
        0xD0, 0xA3, 0xC6, 0x52,
        0x6B, 0xC6, 0x4E, 0x59,
        0x21, 0x5D, 0xF9, 0x1C,
    ]
    assert round_keys[5] == [
        0xE3, 0xD9, 0xB8, 0x37,
        0x9B, 0xD2, 0xA4, 0x6D,
        0x4D, 0x35, 0x93, 0xD3,
        0x3B, 0x1D, 0x58, 0xF9,
    ]
    assert round_keys[6] == [
        0x5C, 0xF5, 0x4C, 0x5F,
        0x9E, 0x41, 0x5B, 0x99,
        0x7E, 0x8A, 0x49, 0x46,
        0x62, 0xF3, 0x1E, 0x50,
    ]
    assert round_keys[7] == [
        0x30, 0x8F, 0x4D, 0xEC,
        0x28, 0x0C, 0x94, 0xB2,
        0x39, 0x3E, 0x92, 0xBC,
        0x37, 0x9F, 0x99, 0x75,
    ]
    assert round_keys[8] == [
        0xCB, 0xB2, 0x47, 0xA2,
        0x58, 0xB4, 0x96, 0x6C,
        0xDA, 0x72, 0x31, 0xD0,
        0x94, 0xAE, 0x13, 0x59,
    ]
    assert round_keys[9] == [
        0x97, 0x8A, 0x7E, 0xB3,
        0x2E, 0x74, 0x89, 0x82,
        0x6C, 0x94, 0x78, 0x76,
        0xB0, 0x9F, 0x91, 0xAC,
    ]
    assert round_keys[10] == [
        0xC3, 0xDF, 0xE4, 0x1D,
        0x90, 0xD4, 0x44, 0xBE,
        0x9E, 0xB3, 0xEB, 0x0A,
        0x7F, 0x7A, 0xBC, 0x01,
    ]
