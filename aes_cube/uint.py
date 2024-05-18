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


__all__ = ["BaseUint", "Uint8", "Uint32", "Uint64"]


T = t.TypeVar("T", bound="BaseUint")
ByteOrder = t.Literal["little", "big"]
IterNum = t.Union[t.Iterable[t.SupportsIndex], t.SupportsBytes]


class BaseUint(ABC):
	@property
	@abstractmethod
	def bit_count(self) -> int: ...

	@property
	@abstractmethod
	def max_value(self) -> int: ...

	@property
	def value(self) -> int:
		return self._value

	@value.setter
	def value(self, value: int) -> None:
		if not isinstance(value, int):
			raise TypeError
		self._value = value & self.max_value

	def __init__(self, value: int = 0) -> None:
		self.value = value

	@classmethod
	def from_bytes(cls: t.Type[T], data: IterNum, *, byteorder: ByteOrder = "big") -> T:
		return cls(int.from_bytes(data, byteorder, signed=False))

	def to_bytes(self, *, byteorder: ByteOrder = "big") -> bytes:
		return self.value.to_bytes(self.bit_count // 8, byteorder)

	def sub_bytes(self, sbox: SBox) -> BaseUint:
		sb = [sbox.value[b] for b in self.to_bytes()]
		self._value = int.from_bytes(sb)
		return self

	def _operate(self, operator: t.Callable, other: int | BaseUint, cls: t.Type = None) -> t.Any:
		if isinstance(other, BaseUint):
			other = other.value
		if cls is None:
			cls = self.__class__
		value = operator(self._value, other)
		return cls(value)

	def __add__(self, other: int | BaseUint) -> BaseUint:
		return self._operate(opr.add, other)

	def __sub__(self, other: int | BaseUint) -> BaseUint:
		return self._operate(opr.sub, other)

	def __and__(self, other: int | BaseUint) -> BaseUint:
		return self._operate(opr.and_, other)

	def __or__(self, other: int | BaseUint) -> BaseUint:
		return self._operate(opr.or_, other)

	def __xor__(self, other: int | BaseUint) -> BaseUint:
		return self._operate(opr.xor, other)

	def __eq__(self, other: int | BaseUint) -> bool:
		return self._operate(opr.eq, other, bool)

	def __ne__(self, other: int | BaseUint) -> bool:
		return self._operate(opr.ne, other, bool)

	def __gt__(self, other: int | BaseUint) -> bool:
		return self._operate(opr.gt, other, bool)

	def __lt__(self, other: int | BaseUint) -> bool:
		return self._operate(opr.lt, other, bool)

	def __ge__(self, other: int | BaseUint) -> bool:
		return self._operate(opr.ge, other, bool)

	def __le__(self, other: int | BaseUint) -> bool:
		return self._operate(opr.le, other, bool)

	def __neg__(self) -> BaseUint:
		return Uint8(-self.value & self.max_value)

	def __rshift__(self, other: int) -> BaseUint:
		"""Rotates bits out from right and back into left"""
		other = other % self.bit_count
		rs = self._value >> other
		ls = self._value << (self.bit_count - other)
		res = (rs | ls) & self.max_value
		return self.__class__(res)

	def __lshift__(self, other: int) -> BaseUint:
		"""Rotates bits out from left and back into right"""
		other = other % self.bit_count
		rs = self._value >> (self.bit_count - other)
		ls = self._value << other
		res = (rs | ls) & self.max_value
		return self.__class__(res)

	def __index__(self) -> int:
		return self._value

	def __int__(self) -> int:
		return self._value

	def __str__(self) -> str:
		return str(self._value)


class Uint8(BaseUint):
	@property
	def bit_count(self):
		return 8

	@property
	def max_value(self):
		return 0xFF


class Uint32(BaseUint):
	@property
	def bit_count(self):
		return 32

	@property
	def max_value(self):
		return 0xFFFFFFFF


class Uint64(BaseUint):
	@property
	def bit_count(self):
		return 64

	@property
	def max_value(self):
		return 0xFFFFFFFFFFFFFFFF
