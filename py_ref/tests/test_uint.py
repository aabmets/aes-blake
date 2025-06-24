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

import re
import typing as t

import random
import pytest

from src.uint import BaseUint, Uint8, Uint32, Uint64

__all__ = [
    "test_uint_inheritance",
    "test_uint8",
    "test_uint32",
    "test_uint64",
    "test_to_bytes",
    "test_from_bytes",
    "test_name_allocation",
    "test_name_suffix",
    "test_bitwise_sum_identity",
    "test_equation_and_assignments"
]


def test_uint_inheritance():
    for uint_type in [Uint8, Uint32, Uint64]:
        uint = uint_type()
        assert isinstance(uint, BaseUint)
        assert hasattr(uint, "bit_count")
        assert isinstance(uint.bit_count(), int)
        assert hasattr(uint, "max_value")
        assert isinstance(uint.max_value(), int)


def test_uint8():
    with pytest.raises(TypeError):
        Uint8(t.cast(int, "asdfg"))

    v0 = Uint8()
    v1 = Uint8(0xAA)
    v2 = Uint8(0xCC)

    assert v0.bit_count() == 8
    assert v0.max_value() == 0xFF

    assert v0.value == 0
    assert v1.value == 0xAA
    assert v2.value == 0xCC

    assert (-v1).value == 0x56
    assert (-v2).value == 0x34

    assert (v1 + v2).value == 0x76  # mod 2**8
    assert (v1 - v2).value == 0xDE  # mod 2**8

    assert (v1 & v2).value == 0x88
    assert (v1 | v2).value == 0xEE
    assert (v1 ^ v2).value == 0x66

    assert (v1 == v2) is False
    assert (v1 != v2) is True
    assert (v1 > v2) is False
    assert (v1 < v2) is True
    assert (v1 >= v2) is False
    assert (v1 <= v2) is True

    assert v1.rotr(1).value == 0x55  # rotate right by 1 bit
    assert v1.rotl(1).value == 0x55  # rotate left by 1 bit
    assert v1.rotr(4).value == 0xAA  # switch halves


def test_uint32():
    with pytest.raises(TypeError):
        Uint32(t.cast(int, "asdfg"))

    v0 = Uint32()
    v1 = Uint32(0xAABBCCDD)
    v2 = Uint32(0xCCDDEEFF)

    assert v0.bit_count() == 32
    assert v0.max_value() == 0xFFFFFFFF

    assert v0.value == 0
    assert v1.value == 0xAABBCCDD
    assert v2.value == 0xCCDDEEFF

    assert (-v1).value == 0x55443323
    assert (-v2).value == 0x33221101

    assert (v1 + v2).value == 0x7799BBDC  # mod 2**32
    assert (v1 - v2).value == 0xDDDDDDDE  # mod 2**32

    assert (v1 & v2).value == 0x8899CCDD
    assert (v1 | v2).value == 0xEEFFEEFF
    assert (v1 ^ v2).value == 0x66662222

    assert (v1 == v2) is False
    assert (v1 != v2) is True
    assert (v1 > v2) is False
    assert (v1 < v2) is True
    assert (v1 >= v2) is False
    assert (v1 <= v2) is True

    assert v1.rotr(1).value == 0xD55DE66E  # rotate right by 1 bit
    assert v1.rotl(1).value == 0x557799BB  # rotate left by 1 bit
    assert v1.rotr(16).value == 0xCCDDAABB  # switch halves


def test_uint64():
    with pytest.raises(TypeError):
        Uint64(t.cast(int, "asdfg"))

    v0 = Uint64()
    v1 = Uint64(0xAABBCCDDEEFFAABB)
    v2 = Uint64(0xCCDDEEFFAABBCCDD)

    assert v0.bit_count() == 64
    assert v0.max_value() == 0xFFFFFFFFFFFFFFFF

    assert v0.value == 0
    assert v1.value == 0xAABBCCDDEEFFAABB
    assert v2.value == 0xCCDDEEFFAABBCCDD

    assert (-v1).value == 0x5544332211005545
    assert (-v2).value == 0x3322110055443323

    assert (v1 + v2).value == 0x7799BBDD99BB7798  # mod 2**64
    assert (v1 - v2).value == 0xDDDDDDDE4443DDDE  # mod 2**64

    assert (v1 & v2).value == 0x8899CCDDAABB8899
    assert (v1 | v2).value == 0xEEFFEEFFEEFFEEFF
    assert (v1 ^ v2).value == 0x6666222244446666

    assert (v1 == v2) is False
    assert (v1 != v2) is True
    assert (v1 > v2) is False
    assert (v1 < v2) is True
    assert (v1 >= v2) is False
    assert (v1 <= v2) is True

    assert v1.rotr(1).value == 0xD55DE66EF77FD55D  # rotate right by 1 bit
    assert v1.rotl(1).value == 0x557799BBDDFF5577  # rotate left by 1 bit
    assert v1.rotr(32).value == 0xEEFFAABBAABBCCDD  # switch halves


def test_to_bytes():
    byte_str = Uint8(0xAA).to_bytes(byteorder="big")
    assert byte_str == b"\xaa"

    byte_str = Uint8(0xAA).to_bytes(byteorder="little")
    assert byte_str == b"\xaa"

    byte_str = Uint32(0xAABBCCDD).to_bytes(byteorder="big")
    assert byte_str == b"\xaa\xbb\xcc\xdd"

    byte_str = Uint32(0xAABBCCDD).to_bytes(byteorder="little")
    assert byte_str == b"\xdd\xcc\xbb\xaa"

    byte_str = Uint64(0xAABBCCDDEEFFAABB).to_bytes(byteorder="big")
    assert byte_str == b"\xaa\xbb\xcc\xdd\xee\xff\xaa\xbb"

    byte_str = Uint64(0xAABBCCDDEEFFAABB).to_bytes(byteorder="little")
    assert byte_str == b"\xbb\xaa\xff\xee\xdd\xcc\xbb\xaa"


def test_from_bytes():
    uint = Uint8.from_bytes(b"\xaa", byteorder="big")
    assert uint.value == 0xAA

    uint = Uint8.from_bytes(b"\xaa", byteorder="little")
    assert uint.value == 0xAA

    uint = Uint32.from_bytes(b"\xaa\xbb\xcc\xdd", byteorder="big")
    assert uint.value == 0xAABBCCDD

    uint = Uint32.from_bytes(b"\xaa\xbb\xcc\xdd", byteorder="little")
    assert uint.value == 0xDDCCBBAA

    uint = Uint64.from_bytes(b"\xaa\xbb\xcc\xdd\xee\xff\xaa\xbb", byteorder="big")
    assert uint.value == 0xAABBCCDDEEFFAABB

    uint = Uint64.from_bytes(b"\xaa\xbb\xcc\xdd\xee\xff\xaa\xbb", byteorder="little")
    assert uint.value == 0xBBAAFFEEDDCCBBAA


def test_name_allocation():
    with BaseUint.equations_logger():
        BaseUint._used_names.clear()
        u1 = Uint8()
        u2 = Uint32()
        u3 = Uint64()
        # Names should be uppercase and unique
        assert u1.name.isupper()
        assert u2.name.isupper()
        assert u3.name.isupper()
        assert len({u1.name, u2.name, u3.name}) == 3


def test_name_suffix():
    with BaseUint.equations_logger():
        BaseUint._used_names.clear()
        for uint_type in [Uint8, Uint32, Uint64]:
            u = uint_type(0, suffix='foo')
            base = u.name.split('_')[0]
            assert u.name == f"{base}_foo"
            assert base in BaseUint._used_names


@pytest.mark.parametrize("cls", [Uint8, Uint32, Uint64])
def test_bitwise_sum_identity(cls):
    max_val = cls.max_value()

    with BaseUint.equations_logger():
        # edge cases: zero, one, midpoint, max-1, max
        fixed = [0, 1, max_val // 2, max_val - 1, max_val]
        for a in fixed:
            for b in fixed:
                uint_a = cls(a)
                uint_b = cls(b)
                left = (uint_a + uint_b).evaluate()
                right = ((uint_a ^ uint_b) + ((uint_a & uint_b) << 1)).evaluate()
                assert left == right, (
                    f"{cls.__name__} failed for A={a:#x}, B={b:#x}: "
                    f"(A+B).evaluate()={left:#x} != "
                    f"((A^B)+((A&B)<<1)).evaluate()={right:#x}"
                )

        # 100 random pairs
        random.seed(0)
        for _ in range(100):
            a = random.randint(0, max_val)
            b = random.randint(0, max_val)
            uint_a = cls(a)
            uint_b = cls(b)
            left = (uint_a + uint_b).evaluate()
            right = ((uint_a ^ uint_b) + ((uint_a & uint_b) << 1)).evaluate()
            assert left == right, (
                f"{cls.__name__} failed for A={a:#x}, B={b:#x}: "
                f"{left:#x} != {right:#x}"
            )


def test_equation_and_assignments():
    with BaseUint.equations_logger():
        a = Uint32(123)
        b = Uint32(456)

        left = a + b
        right = (a ^ b) + ((a & b) << 1)

        l_as = left.get_assignments()
        l_eq = left.get_equation()

        pattern = r"[A-Z] = 579, [A-Z] = 123, [A-Z] = 456"
        assert re.match(pattern, l_as) is not None

        pattern = r"[A-Z] = [A-Z] \+ [A-Z]"
        assert re.match(pattern, l_eq) is not None

        r_as = right.get_assignments()
        r_eq = right.get_equation()

        pattern = r"[A-Z] = 579, [A-Z] = 123, [A-Z] = 456"
        assert re.match(pattern, r_as) is not None

        pattern = r"[A-Z] = \([A-Z] \^ [A-Z]\) \+ \(\([A-Z] & [A-Z]\) << 1\)"
        assert re.match(pattern, r_eq) is not None
