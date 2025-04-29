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

from src.checksum import CheckSum32, CheckSum64
from src.uint import Uint8

__all__ = ["test_checksum"]


def test_checksum():
    for cls in [CheckSum32, CheckSum64]:
        chk, size = cls(), cls.size()

        assert len(chk.state) == size
        for obj in chk.state:
            assert isinstance(obj, Uint8)

        data1 = b"\x27" * size
        data2 = b"\xeb" * size
        data3 = b"\x9a" * size
        data4 = b"\x5c" * size

        chk.xor_with(data1)
        for i in range(0, size):
            assert chk.state[i] == 0x27

        chk.xor_with(data2)
        for i in range(0, size):
            assert chk.state[i] == 0xCC

        chk.xor_with(data3)
        for i in range(0, size):
            assert chk.state[i] == 0x56

        chk.xor_with(data4)
        for i in range(0, size):
            assert chk.state[i] == 0x0A

        assert chk.to_bytes() == b"\x0a" * size

        chk_list = cls.create_many(count=4)
        assert isinstance(chk_list, list)
        assert len(chk_list) == 4

        for obj in chk_list:
            assert isinstance(obj, cls)
