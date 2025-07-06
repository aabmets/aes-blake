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

from src.checksum import *

__all__ = ["test_checksum"]


@pytest.mark.parametrize("cls", [CheckSum, MaskedCheckSum])
def test_checksum(cls):
    chk = cls(state_size=16)
    uint = cls.uint_class()
    for obj in chk.state:
        assert isinstance(obj, uint)

    data1 = b"\x27" * 16
    data2 = b"\xeb" * 16
    data3 = b"\x9a" * 16
    data4 = b"\x5c" * 16

    chk.xor_with(data1)
    for i in range(0, 16):
        assert chk.state[i] == 0x27

    chk.xor_with(data2)
    for i in range(0, 16):
        assert chk.state[i] == 0xCC

    chk.xor_with(data3)
    for i in range(0, 16):
        assert chk.state[i] == 0x56

    chk.xor_with(data4)
    for i in range(0, 16):
        assert chk.state[i] == 0x0A

    assert chk.to_bytes() == b"\x0a" * 16

    chk = cls.create_many(4)
    assert isinstance(chk, list)
    assert len(chk) == 4
    for obj in chk:
        assert isinstance(obj, cls)
