#
#   MIT License
#   
#   Copyright (c) 2024, Mattias Aabmets
#   
#   The contents of this file are subject to the terms and conditions defined in the License.
#   You may not use, modify, or distribute this file except in compliance with the License.
#   
#   SPDX-License-Identifier: MIT
#
from __future__ import annotations
import typing as t
from abc import ABC, abstractmethod
from .sbox import SBox


__all__ = ["Uint8", "Uint32"]


class UnsignedIntegerType(ABC):
	@property
	@abstractmethod
	def bit_count(self): ...

	@classmethod
	def from_bytes(cls, value: bytes | bytearray, *, byteorder: t.Literal["little", "big"] = "big"):
		if not isinstance(value, (bytes, bytearray)):
			raise TypeError
		return cls(int.from_bytes(value, byteorder, signed=False))

	def __init__(self, value: int = 0):
		if not isinstance(value, int):
			raise TypeError
		self._max_value = (1 << self.bit_count) - 1
		self._value = value & self._max_value

	@property
	def binary_bytes(self) -> t.List[str]:
		bit_str = format(self._value, f"0{self.bit_count}b")
		return [bit_str[i:i + 8] for i in range(0, len(bit_str), 8)]

	def sub_bytes(self, sbox: SBox):
		bb_list = []
		for bb_str in self.binary_bytes:
			value = int(bb_str, base=2)
			value = sbox.value[value]
			bb_str = format(value, "08b")
			bb_list.append(bb_str)
		concat_bb = ''.join(bb_list)
		self._value = int(concat_bb, base=2)

	def __add__(self, other: UnsignedIntegerType) -> UnsignedIntegerType:
		return self.__class__(self._value + other._value)

	def __and__(self, other: UnsignedIntegerType) -> UnsignedIntegerType:
		return self.__class__(self._value & other._value)

	def __xor__(self, other: UnsignedIntegerType) -> UnsignedIntegerType:
		return self.__class__(self._value ^ other._value)

	def __rshift__(self, other: int) -> UnsignedIntegerType:
		other = other % self.bit_count
		rs = self._value >> other
		ls = self._value << (self.bit_count - other)
		res = (rs | ls) & self._max_value
		return self.__class__(res)

	def __lshift__(self, other: int) -> UnsignedIntegerType:
		other = other % self.bit_count
		rs = self._value >> (self.bit_count - other)
		ls = self._value << other
		res = (rs | ls) & self._max_value
		return self.__class__(res)

	def __int__(self):
		return self._value

	def __str__(self):
		return str(self._value)

	def __index__(self):
		return self._value


class Uint8(UnsignedIntegerType):
	@property
	def bit_count(self):
		return 8


class Uint32(UnsignedIntegerType):
	@property
	def bit_count(self):
		return 32
