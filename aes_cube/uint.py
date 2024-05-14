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
import operator as opr
from abc import ABC, abstractmethod
from .sbox import SBox


__all__ = ["BaseUint", "Uint8", "Uint32"]


class BaseUint(ABC):
	@property
	@abstractmethod
	def bit_count(self): ...

	@property
	@abstractmethod
	def max_value(self): ...

	@property
	def value(self):
		return self._value

	@value.setter
	def value(self, value: int):
		if not isinstance(value, int):
			raise TypeError
		self._value = value & self.max_value

	@classmethod
	def from_bytes(cls, data: bytes | bytearray, *, byteorder: t.Literal["little", "big"] = "big"):
		if not isinstance(data, (bytes, bytearray)):
			raise TypeError
		return cls(int.from_bytes(data, byteorder, signed=False))

	def to_bytes(self, *, byteorder: t.Literal["little", "big"] = "big") -> bytes:
		return self.value.to_bytes(self.bit_count // 8, byteorder)

	@property
	def binary_bytes(self) -> t.List[str]:
		bit_str = format(self._value, f"0{self.bit_count}b")
		return [bit_str[i:i+8] for i in range(0, len(bit_str), 8)]

	def sub_bytes(self, sbox: SBox):
		bb_list = []
		for bb_str in self.binary_bytes:
			value = int(bb_str, base=2)
			value = sbox.value[value]
			bb_str = format(value, "08b")
			bb_list.append(bb_str)
		concat_bb = ''.join(bb_list)
		self._value = int(concat_bb, base=2)

	def __init__(self, value: int = 0):
		self.value = value

	def _operate(self, operator: t.Callable, other: int | BaseUint) -> BaseUint:
		if isinstance(other, BaseUint):
			other = other.value
		value = operator(self._value, other)
		return self.__class__(value)

	def __add__(self, other: int | BaseUint) -> BaseUint:
		return self._operate(opr.add, other)

	def __and__(self, other: int | BaseUint) -> BaseUint:
		return self._operate(opr.and_, other)

	def __xor__(self, other: int | BaseUint) -> BaseUint:
		return self._operate(opr.xor, other)

	def __rshift__(self, other: int) -> BaseUint:
		other = other % self.bit_count
		rs = self._value >> other
		ls = self._value << (self.bit_count - other)
		res = (rs | ls) & self.max_value
		return self.__class__(res)

	def __lshift__(self, other: int) -> BaseUint:
		other = other % self.bit_count
		rs = self._value >> (self.bit_count - other)
		ls = self._value << other
		res = (rs | ls) & self.max_value
		return self.__class__(res)

	def __int__(self):
		return self._value

	def __str__(self):
		return str(self._value)

	def __index__(self):
		return self._value


class Uint8(BaseUint):
	@property
	def bit_count(self):
		return 8

	@property
	def max_value(self):
		return 255


class Uint32(BaseUint):
	@property
	def bit_count(self):
		return 32

	@property
	def max_value(self):
		return 4_294_967_295


class Uint64(BaseUint):
	@property
	def bit_count(self):
		return 64

	@property
	def max_value(self):
		return 18_446_744_073_709_551_615
