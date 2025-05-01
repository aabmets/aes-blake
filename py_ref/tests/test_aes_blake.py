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
import secrets
import typing as t

from src.blake_keygen import KDFDomain
from src.aes_blake import AESBlake256, AESBlake512, BaseAESBlake

__all__ = [
    "fixture_aes_block_data",
    "normal_usage_tester",
    "bad_data_tester",
    "test_aesblake256_normal_usage",
    "test_aesblake512_normal_usage",
    "test_aesblake256_bad_key",
    "test_aesblake512_bad_key",
    "test_aesblake256_bad_nonce",
    "test_aesblake512_bad_nonce",
    "test_aesblake256_bad_context",
    "test_aesblake512_bad_context",
    "test_aesblake256_bad_ciphertext",
    "test_aesblake512_bad_ciphertext",
    "test_aesblake256_bad_header",
    "test_aesblake512_bad_header",
    "test_aesblake256_bad_auth_tag",
    "test_aesblake512_bad_auth_tag",
    "test_aesblake256_ex_cols",
    "test_aesblake512_ex_cols",
    "test_aesblake256_reference_inputs",
    "test_aesblake512_reference_inputs"
]


@pytest.fixture(name="aes_block_data", scope="function")
def fixture_aes_block_data() -> tuple[bytes, ...]:
    chunk1 = bytes([b for b in [0x1A, 0x2A, 0x3A, 0x4A] for _ in range(4)])
    chunk2 = bytes([b for b in [0x1B, 0x2B, 0x3B, 0x4B] for _ in range(4)])
    chunk3 = bytes([b for b in [0x1C, 0x2C, 0x3C, 0x4C] for _ in range(4)])
    chunk4 = bytes([b for b in [0x1D, 0x2D, 0x3D, 0x4D] for _ in range(4)])
    return chunk1, chunk2, chunk3, chunk4


def normal_usage_tester(cls: t.Type[BaseAESBlake]):
    data_len = cls.keygen_class().uint().bit_count()  # interpret as byte count
    plaintext = header = bytes(range(data_len))
    cipher = cls(b"", b"", b"")
    ciphertext, auth_tag = cipher.encrypt(plaintext, header)
    _plaintext = cipher.decrypt(ciphertext, header, auth_tag)
    assert len(plaintext) == data_len
    assert len(ciphertext) == data_len
    assert len(auth_tag) == data_len
    assert len(_plaintext) == data_len
    assert _plaintext == plaintext


def bad_data_tester(cls: t.Type[BaseAESBlake], corrupt_field: str):
    data_len = cls.keygen_class().uint().bit_count()
    key = nonce = context = header = plaintext = bytes(range(data_len))

    cipher = cls(key, nonce, context)
    ciphertext, auth_tag = cipher.encrypt(plaintext, header)

    data = dict(
        key=key,
        nonce=nonce,
        context=context,
        ciphertext=ciphertext,
        header=header,
        auth_tag=auth_tag,
    )
    for k, v in data.items():
        if k == corrupt_field:
            data[k] = bytes([v[0] ^ 0x01]) + v[1:]  # flip bit

    key, nonce, context, ciphertext, header, auth_tag = data.values()
    cipher = cls(key, nonce, context)
    with pytest.raises(ValueError, match="Failed to verify auth tag"):
        cipher.decrypt(ciphertext, header, auth_tag)


def test_aesblake256_normal_usage():
    normal_usage_tester(AESBlake256)


def test_aesblake512_normal_usage():
    normal_usage_tester(AESBlake512)


def test_aesblake256_bad_key():
    bad_data_tester(AESBlake256, "key")


def test_aesblake512_bad_key():
    bad_data_tester(AESBlake512, "key")


def test_aesblake256_bad_nonce():
    bad_data_tester(AESBlake256, "nonce")


def test_aesblake512_bad_nonce():
    bad_data_tester(AESBlake512, "nonce")


def test_aesblake256_bad_context():
    bad_data_tester(AESBlake256, "context")


def test_aesblake512_bad_context():
    bad_data_tester(AESBlake512, "context")


def test_aesblake256_bad_ciphertext():
    bad_data_tester(AESBlake256, "ciphertext")


def test_aesblake512_bad_ciphertext():
    bad_data_tester(AESBlake512, "ciphertext")


def test_aesblake256_bad_header():
    bad_data_tester(AESBlake256, "header")


def test_aesblake512_bad_header():
    bad_data_tester(AESBlake512, "header")


def test_aesblake256_bad_auth_tag():
    bad_data_tester(AESBlake256, "auth_tag")


def test_aesblake512_bad_auth_tag():
    bad_data_tester(AESBlake512, "auth_tag")


def test_aesblake256_ex_cols(aes_block_data):
    chunks = aes_block_data[:2]
    cipher = AESBlake256(b'', b'', b'')
    aes_blocks = cipher.create_aes_blocks(chunks, KDFDomain.CHK)

    cipher.exchange_columns(aes_blocks)
    assert aes_blocks[0].state == [
        0x1A, 0x1A, 0x1A, 0x1A,  # 1A
        0x2B, 0x2B, 0x2B, 0x2B,  # 2B
        0x3A, 0x3A, 0x3A, 0x3A,  # 3A
        0x4B, 0x4B, 0x4B, 0x4B,  # 4B
    ]
    assert aes_blocks[1].state == [
        0x1B, 0x1B, 0x1B, 0x1B,  # 1B
        0x2A, 0x2A, 0x2A, 0x2A,  # 2A
        0x3B, 0x3B, 0x3B, 0x3B,  # 3B
        0x4A, 0x4A, 0x4A, 0x4A,  # 4A
    ]

    cipher.exchange_columns(aes_blocks, inverse=True)
    assert bytes(aes_blocks[0].state) == chunks[0]
    assert bytes(aes_blocks[1].state) == chunks[1]


def test_aesblake512_ex_cols(aes_block_data):
    chunks = aes_block_data
    cipher = AESBlake512(b'', b'', b'')
    aes_blocks = cipher.create_aes_blocks(chunks, KDFDomain.CHK)

    cipher.exchange_columns(aes_blocks)
    assert aes_blocks[0].state == [
        0x1A, 0x1A, 0x1A, 0x1A,  # 1A
        0x2B, 0x2B, 0x2B, 0x2B,  # 2B
        0x3C, 0x3C, 0x3C, 0x3C,  # 3C
        0x4D, 0x4D, 0x4D, 0x4D,  # 4D
    ]
    assert aes_blocks[1].state == [
        0x1B, 0x1B, 0x1B, 0x1B,  # 1B
        0x2C, 0x2C, 0x2C, 0x2C,  # 2C
        0x3D, 0x3D, 0x3D, 0x3D,  # 3D
        0x4A, 0x4A, 0x4A, 0x4A,  # 4A
    ]
    assert aes_blocks[2].state == [
        0x1C, 0x1C, 0x1C, 0x1C,  # 1C
        0x2D, 0x2D, 0x2D, 0x2D,  # 2D
        0x3A, 0x3A, 0x3A, 0x3A,  # 3A
        0x4B, 0x4B, 0x4B, 0x4B,  # 4B
    ]
    assert aes_blocks[3].state == [
        0x1D, 0x1D, 0x1D, 0x1D,  # 1D
        0x2A, 0x2A, 0x2A, 0x2A,  # 2A
        0x3B, 0x3B, 0x3B, 0x3B,  # 3B
        0x4C, 0x4C, 0x4C, 0x4C,  # 4C
    ]

    cipher.exchange_columns(aes_blocks, inverse=True)
    assert bytes(aes_blocks[0].state) == chunks[0]
    assert bytes(aes_blocks[1].state) == chunks[1]
    assert bytes(aes_blocks[2].state) == chunks[2]
    assert bytes(aes_blocks[3].state) == chunks[3]


def test_aesblake256_reference_inputs():
    key = bytes.fromhex(
        "3ACCABE8 119ECD4F BF8550CC C48B67FD"
        "43B36240 C924B4CC B2AC2376 47AC4A8E"
    )  # secrets.token_bytes(32)

    nonce = bytes.fromhex(
        "69B9A59E F9FB3425 4EF73465 4B5CBAA4"
        "ED361722 FF3D2F85 4779D7E1 2EB0A63C"
    )  # secrets.token_bytes(32)

    context = bytes.fromhex(
        "40424446 484A4C4E 50525456 585A5C5E"
        "60626466 686A6C6E 70727476 787A7C7E"
        "80828486 888A8C8E 90929496 989A9C9E"
        "A0A2A4A6 A8AAACAE B0B2B4B6 B8BABCBE"
    )  # bytes(range(64, 192, 2))

    plaintext = bytes.fromhex(
        "00010203 04050607 08090A0B 0C0D0E0F"
        "10111213 14151617 18191A1B 1C1D1E1F"
        "20212223 24252627 28292A2B 2C2D2E2F"
        "30313233 34353637 38393A3B 3C3D3E3F"
        "40414243 44454647 48494A4B 4C4D4E4F"
        "50515253 54555657 58595A5B 5C5D5E5F"
        "60616263 64656667 68696A6B 6C6D6E6F"
        "70717273 74757677 78797A7B 7C7D7E7F"
    )  # bytes(range(0, 128)

    header = bytes.fromhex(
        "80818283 84858687 88898A8B 8C8D8E8F"
        "90919293 94959697 98999A9B 9C9D9E9F"
        "A0A1A2A3 A4A5A6A7 A8A9AAAB ACADAEAF"
        "B0B1B2B3 B4B5B6B7 B8B9BABB BCBDBEBF"
        "C0C1C2C3 C4C5C6C7 C8C9CACB CCCDCECF"
        "D0D1D2D3 D4D5D6D7 D8D9DADB DCDDDEDF"
        "E0E1E2E3 E4E5E6E7 E8E9EAEB ECEDEEEF"
        "F0F1F2F3 F4F5F6F7 F8F9FAFB FCFDFEFF"
    )  # bytes(range(128, 256)

    cipher = AESBlake256(key, nonce, context)
    ciphertext, auth_tag = cipher.encrypt(plaintext, header)

    assert ciphertext == bytes.fromhex(
        "227ACD91 8DB836C9 247D0A59 10132227"
        "DFE13B3B F65DF7C4 F56FCB48 E7B80302"
        "B107FE95 46D92FA7 1C26BC30 C5E998E0"
        "4893677B 3B8E0D61 72C35E33 86515A32"
        "0ACF97D3 1A3BEBC4 0B62EABE A60BA4C3"
        "CE27242E A9C365AC AD2F2A76 4AA81B99"
        "1686FDA4 B90337B8 58AFCC65 F6F03585"
        "F66CACD7 BC87B7A1 DEED851E 58C63F07"
    )
    assert auth_tag == bytes.fromhex(
        "2246938A 23B92CAB 776FC452 7D5EC961"
        "7A07FF4C 75F0B09E 4A342E43 F3CA2BF1"
    )

    _plaintext = cipher.decrypt(ciphertext, header, auth_tag)
    assert _plaintext == plaintext


def test_aesblake512_reference_inputs():
    key = bytes.fromhex(
        "F1483309 CDB94036 B2782F5F CD48428C"
        "CBBBF8B0 085544AE 411086E3 778BD9F6"
        "F012C784 0F879908 801EA3FB D1D148CF"
        "6D16E2E3 A39EE27C 3152CEEB 74BCD268"
    )  # secrets.token_bytes(64)

    nonce = bytes.fromhex(
        "87F2B30B 47ACC97A C092220D BAFBF2DC"
        "CDA5665B E8DC7C1B FCFC9612 8DE57BFF"
        "356772E3 99146EFC B072857D 87E05859"
        "92C82F66 436631B5 6565CC16 40CE88A8"
    )  # secrets.token_bytes(64)

    context = bytes.fromhex(
        "40424446 484A4C4E 50525456 585A5C5E"
        "60626466 686A6C6E 70727476 787A7C7E"
        "80828486 888A8C8E 90929496 989A9C9E"
        "A0A2A4A6 A8AAACAE B0B2B4B6 B8BABCBE"
    )  # bytes(range(64, 192, 2))

    plaintext = bytes.fromhex(
        "00010203 04050607 08090A0B 0C0D0E0F"
        "10111213 14151617 18191A1B 1C1D1E1F"
        "20212223 24252627 28292A2B 2C2D2E2F"
        "30313233 34353637 38393A3B 3C3D3E3F"
        "40414243 44454647 48494A4B 4C4D4E4F"
        "50515253 54555657 58595A5B 5C5D5E5F"
        "60616263 64656667 68696A6B 6C6D6E6F"
        "70717273 74757677 78797A7B 7C7D7E7F"
    )  # bytes(range(0, 128)

    header = bytes.fromhex(
        "80818283 84858687 88898A8B 8C8D8E8F"
        "90919293 94959697 98999A9B 9C9D9E9F"
        "A0A1A2A3 A4A5A6A7 A8A9AAAB ACADAEAF"
        "B0B1B2B3 B4B5B6B7 B8B9BABB BCBDBEBF"
        "C0C1C2C3 C4C5C6C7 C8C9CACB CCCDCECF"
        "D0D1D2D3 D4D5D6D7 D8D9DADB DCDDDEDF"
        "E0E1E2E3 E4E5E6E7 E8E9EAEB ECEDEEEF"
        "F0F1F2F3 F4F5F6F7 F8F9FAFB FCFDFEFF"
    )  # bytes(range(128, 256)

    cipher = AESBlake256(key, nonce, context)
    ciphertext, auth_tag = cipher.encrypt(plaintext, header)

    assert ciphertext == bytes.fromhex(
        "2EA6D40F BF294551 1EF2011B 440269D3"
        "F31FE869 9D126875 8739054D E51C66CC"
        "76047C92 4CD9A02E 2FAF007A 5631C1C1"
        "B0EEF853 F28FC82B BF48F0DE 359861EF"
        "E825E949 35C04671 05C1B287 59A51F80"
        "2148D0EA 1DE1C708 9D3FE4D7 E483F2E0"
        "423EF73F BF4465B8 29137D26 413A5DB8"
        "68E7777F 80E292FF 9569B425 C7881EB4"
    )
    assert auth_tag == bytes.fromhex(
        "E2AF7849 30D1B926 995A94B3 B5A1C8D0"
        "BE7EA6FA F11C650C AC84D5AA 19B98FA1"
    )

    _plaintext = cipher.decrypt(ciphertext, header, auth_tag)
    assert _plaintext == plaintext
