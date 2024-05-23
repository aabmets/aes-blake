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
from .uint import IterNum, Uint8, Uint32


__all__ = ["CheckSum"]


class CheckSum:
	def __init__(self) -> None:
		self.checksum = [Uint8(0) for _ in range(32)]
		self.pointer = 0

	def xor_with(self, data: IterNum) -> None:
		for i, b in enumerate(data):
			j = i + self.pointer
			self.checksum[j] ^= b
		self.pointer ^= 16

	def to_uint32_list(self) -> list[Uint32]:
		out = []
		for i in range(0, 32, 4):
			chunk = self.checksum[i:i + 4]
			obj = Uint32.from_bytes(chunk)
			out.append(obj)
		return out
