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

from src.aes_blake import AESBlake256, AESBlake512
from tests.aes_blake.overrides import (PartiallyMockedMaskedAESBlake256,
                                       PartiallyMockedMaskedAESBlake512)

__all__ = [
    "test_clean_aesblake256_reference_inputs",
    "test_masked_aesblake256_reference_inputs",
    "test_clean_aesblake512_reference_inputs",
    "test_masked_aesblake512_reference_inputs",
]


@pytest.mark.parametrize("cls", [AESBlake256])
def test_clean_aesblake256_reference_inputs(cls):
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

    cipher = cls(key, nonce, context)
    ciphertext, auth_tag = cipher.encrypt(plaintext, header)

    assert ciphertext == bytes.fromhex(
        "FCB906CA A6DAAD1A 2D09522B 675D85B1"
        "311F541B 4B50E1A4 E88EF5CE 3BC2D0DA"
        "112B5078 68B518F1 76391D8D D79AC09B"
        "236FA1EC 417A4825 463DE790 57DE068A"
        "364426F9 0C803970 28DF5AE3 3D3D33C2"
        "814C2346 A09B8149 9F611379 6A13346A"
        "EB62CA72 B1B85909 EF3B3FF7 36BCEDB1"
        "5F18DA2E EEFE6171 589A2CC2 06337C1E"
    )
    assert auth_tag == bytes.fromhex(
        "743A5EFC 11572DCB CC011607 E4F1C1CE"
        "F26B0062 C38667D7 57FE5034 786E0A31"
    )

    _plaintext = cipher.decrypt(ciphertext, header, auth_tag)
    assert _plaintext == plaintext


@pytest.mark.with_slow_dom
@pytest.mark.parametrize("cls", [PartiallyMockedMaskedAESBlake256])
def test_masked_aesblake256_reference_inputs(cls):
    test_clean_aesblake256_reference_inputs(cls)


@pytest.mark.parametrize("cls", [AESBlake512])
def test_clean_aesblake512_reference_inputs(cls):
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
        "40414243 44454647 48494A4B 4C4D4E4F"
        "50515253 54555657 58595A5B 5C5D5E5F"
        "60616263 64656667 68696A6B 6C6D6E6F"
        "70717273 74757677 78797A7B 7C7D7E7F"
        "80818283 84858687 88898A8B 8C8D8E8F"
        "90919293 94959697 98999A9B 9C9D9E9F"
        "A0A1A2A3 A4A5A6A7 A8A9AAAB ACADAEAF"
        "B0B1B2B3 B4B5B6B7 B8B9BABB BCBDBEBF"
    )  # bytes(range(64, 192))

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

    cipher = cls(key, nonce, context)
    ciphertext, auth_tag = cipher.encrypt(plaintext, header)

    assert ciphertext == bytes.fromhex(
        "D8FCB85C 1F419DDB 62A1C889 3C3E0B31"
        "81164BB1 49046FE4 853D663A 62C9A07D"
        "8C9FD2C8 B55E4A20 88781DD2 6EC2F82F"
        "4EA19BD5 28E6C03C D85D97BE 2295D4EB"
        "A6601CA6 4D69DB0A 17389262 B491F03F"
        "18C1E7C1 DB1501F3 B193EF05 20423978"
        "53A9E732 B250EA5A 2972E08A F99B84D4"
        "D0B920D8 1840C7BC 5977A0BF 6B97F561"
    )
    assert auth_tag == bytes.fromhex(
        "99F162A4 242613FA 4EA45EA3 C3348374"
        "45690F07 21F0FE01 EFF6EA06 36E91F62"
        "2019C66C E4B3671F 06681097 32147D50"
        "2791F5A2 4DDD5B66 63B8333C D779D21E"
    )

    _plaintext = cipher.decrypt(ciphertext, header, auth_tag)
    assert _plaintext == plaintext


@pytest.mark.with_slow_dom
@pytest.mark.parametrize("cls", [PartiallyMockedMaskedAESBlake512])
def test_masked_aesblake512_reference_inputs(cls):
    test_clean_aesblake512_reference_inputs(cls)
