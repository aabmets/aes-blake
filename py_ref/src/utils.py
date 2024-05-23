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
from .uint import Uint32


__all__ = [
	"bytes_to_uint32_vector",
	"pkcs7_pad",
	"pkcs7_unpad"
]


def bytes_to_uint32_vector(data: bytes, size: int) -> list[Uint32]:
	s_len = len(data)
	count = 4 - (s_len % 4)
	data += b'\x00' * count
	output: list[Uint32] = []
	for i in range(0, s_len, 4):
		output.append(Uint32.from_bytes(
			data=data[i:i + 4],
			byteorder="little"
		))
	while len(output) < size:
		output.append(Uint32(0))
	return output


def pkcs7_pad(data):
	pad_len = 16 - (len(data) % 16)
	padding = bytes([pad_len] * pad_len)
	return data + padding


def pkcs7_unpad(data):
	pad_len = data[-1]
	return data[:-pad_len]
