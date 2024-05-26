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
from .uint import IterNum, Uint8


__all__ = ["CheckSum"]


class CheckSum:
	def __init__(self) -> None:
		self.checksum = [Uint8(0) for _ in range(16)]

	def xor_with(self, data: IterNum) -> None:
		for i, b in enumerate(data):
			self.checksum[i] ^= b

	def to_bytes(self) -> bytes:
		return bytes(self.checksum)
