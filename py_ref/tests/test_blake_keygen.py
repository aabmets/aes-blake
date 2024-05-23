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
import pytest
from src.blake_keygen import BlakeKeyGen, KDFDomain
from src.uint import Uint32, Uint64
from src import utils


@pytest.fixture(name="blank_keygen", scope="module")
def fixture_blank_keygen():
	keygen = BlakeKeyGen(key=b'', nonce=b'', context=b'')
	keygen.block_index_base = Uint64(0)
	keygen.state = [Uint32(0)] * 16
	keygen.key = [Uint32(0)] * 16
	return keygen


def test_mix_method(blank_keygen):
	keygen = blank_keygen.clone()
	one, zero = Uint32(1), Uint32(0)

	keygen.mix(0, 4, 8, 12, one, zero)
	assert keygen.state[0].value == 0x00000011   # 0000 0000 0000 0000 0000 0000 0001 0001
	assert keygen.state[4].value == 0x20220202   # 0010 0000 0010 0010 0000 0010 0000 0010
	assert keygen.state[8].value == 0x11010100   # 0001 0001 0000 0001 0000 0001 0000 0000
	assert keygen.state[12].value == 0x11000100  # 0001 0001 0000 0000 0000 0001 0000 0000

	keygen.mix(0, 4, 8, 12, one, zero)
	assert keygen.state[0].value == 0x22254587   # 0010 0010 0010 0101 0100 0101 1000 0111
	assert keygen.state[4].value == 0xCB766A41   # 1100 1011 0111 0110 0110 1010 0100 0001
	assert keygen.state[8].value == 0xB9366396   # 1011 1001 0011 0110 0110 0011 1001 0110
	assert keygen.state[12].value == 0xA5213174  # 1010 0101 0010 0001 0011 0001 0111 0100

	for i in [1, 2, 3, 5, 6, 7, 9, 10, 11, 13, 14, 15]:
		assert keygen.state[i].value == 0


def test_mix_into_state(blank_keygen):
	keygen = blank_keygen.clone()
	message = [Uint32(0)] * 16
	message[0] = Uint32(1)

	keygen.mix_into_state(message)
	assert keygen.state[0].value == 0x00000121  # 0000 0000 0000 0000 0000 0001 0010 0001
	assert keygen.state[1].value == 0x10001001  # 0001 0000 0000 0000 0001 0000 0000 0001
	assert keygen.state[2].value == 0x10011010  # 0001 0000 0000 0001 0001 0000 0001 0000
	assert keygen.state[3].value == 0x42242404  # 0100 0010 0010 0100 0010 0100 0000 0100

	keygen.mix_into_state(message)
	assert keygen.state[0].value == 0xCA362DD6  # 1100 1010 0011 0110 0010 1101 1101 0110
	assert keygen.state[1].value == 0x137F4EC0  # 0001 0011 0111 1111 0100 1110 1100 0000
	assert keygen.state[2].value == 0xC494A2BB  # 1100 0100 1001 0100 1010 0010 1011 1011
	assert keygen.state[3].value == 0x646EF8F0  # 0110 0100 0110 1110 1111 1000 1111 0000

	for i in range(4, 16):
		assert keygen.state[i].value != 0


def test_permute(blank_keygen):
	keygen = blank_keygen.clone()
	message = [Uint32(c) for c in b"ABCDEFGHIJKLMNOP"]

	expected = [c for c in b"CGDKHAENBLMFJOPI"]
	message = keygen.permute(message)
	assert message == expected

	expected = [c for c in b"DEKMNCHOGFJALPIB"]
	message = keygen.permute(message)
	assert message == expected


def test_set_params_digest_ctx_domain(blank_keygen):
	keygen = blank_keygen.clone()
	keygen.set_params(domain=KDFDomain.DIGEST_CTX)
	for i in range(8, 12):
		assert keygen.state[i].value == 0x20
	for i in [0, 1, 2, 3, 4, 5, 6, 7, 12, 13, 14, 15]:
		assert keygen.state[i].value == 0x0


def test_set_params_derive_keys_domain(blank_keygen):
	keygen = blank_keygen.clone()
	keygen.set_params(domain=KDFDomain.DERIVE_KEY)
	for i in range(8, 12):
		assert keygen.state[i].value == 0x40
	for i in [0, 1, 2, 3, 4, 5, 6, 7, 12, 13, 14, 15]:
		assert keygen.state[i].value == 0x0


def test_set_params_last_round_domain(blank_keygen):
	keygen = blank_keygen.clone()
	keygen.set_params(domain=KDFDomain.LAST_ROUND)
	for i in range(8, 12):
		assert keygen.state[i].value == 0x80
	for i in [0, 1, 2, 3, 4, 5, 6, 7, 12, 13, 14, 15]:
		assert keygen.state[i].value == 0x0


def test_set_params_block_index(blank_keygen):
	keygen = blank_keygen.clone()
	keygen.set_params(block_index=0xAABBCCDDEEFFAABB)
	for i in range(4):
		assert keygen.state[i].value == 0xBBAAFFEE + i
		assert keygen.state[i + 4].value == 0
		assert keygen.state[i + 8].value == 0
		assert keygen.state[i + 12].value == 0xDDCCBBAA


def test_compute_bib(blank_keygen):
	clone = blank_keygen.clone()
	clone.key[0] = Uint32(0xAABBCCDD)
	clone.key[1] = Uint32(0x11223344)
	bib = clone.compute_bib()
	assert bib.value == 0x44332211DDCCBBAA


def test_digest_context(blank_keygen):
	keygen = blank_keygen.clone()
	state = keygen.digest_context(b'')
	for i in range(4):
		assert state[0].value == 0x668F50FF  # 0110 0110 1000 1111 0101 0000 1111 1111
		assert state[1].value == 0xDBF71E3C  # 1101 1011 1111 0111 0001 1110 0011 1100
		assert state[2].value == 0x5AB31C59  # 0101 1010 1011 0011 0001 1100 0101 1001
		assert state[3].value == 0x63997B7A  # 0110 0011 1001 1001 0111 1011 0111 1010
	for i in range(4, 16):
		assert state[i].value != 0


def test_compress(blank_keygen):
	keygen = blank_keygen.clone()
	vector = utils.bytes_to_uint32_vector(data=b'', size=16)
	keygen.compress(vector, index=0)
	for i in range(4):
		assert keygen.state[0].value == 0xF8D374A2  # 1111 1000 1101 0011 0111 0100 1010 0010
		assert keygen.state[1].value == 0x8159CAF7  # 1000 0001 0101 1001 1100 1010 1111 0111
		assert keygen.state[2].value == 0x8A917AD3  # 1000 1010 1001 0001 0111 1010 1101 0011
		assert keygen.state[3].value == 0x335959CF  # 0011 0011 0101 1001 0101 1001 1100 1111
	keygen.compress(vector, index=1)
	for i in range(4):
		assert keygen.state[0].value == 0x668F50FF  # 0110 0110 1000 1111 0101 0000 1111 1111
		assert keygen.state[1].value == 0xDBF71E3C  # 1101 1011 1111 0111 0001 1110 0011 1100
		assert keygen.state[2].value == 0x5AB31C59  # 0101 1010 1011 0011 0001 1100 0101 1001
		assert keygen.state[3].value == 0x63997B7A  # 0110 0011 1001 1001 0111 1011 0111 1010


def test_normal_init():
	keygen = BlakeKeyGen(key=b'\x00', nonce=b'', context=b'')
	expected_vector = [
		0x7CC478F8, 0x83600387, 0x05978CFF, 0xF262DFA2,
		0xF4827C0B, 0xD3486425, 0x3BDAF984, 0x4872FA2D,
		0x35F67271, 0xC92E4CD4, 0x0C2630FB, 0x890E7575,
		0xDCE1B748, 0x9299A71D, 0xB2F854DF, 0x5EF83F1B,
	]
	for i in range(16):
		assert keygen.state[i].value == expected_vector[i]

	keygen = BlakeKeyGen(key=b'\x01', nonce=b'', context=b'')
	expected_vector = [
		0x461001DD, 0x7ED3C892, 0x8E06803F, 0xED5723C2,
		0x154CBC66, 0x1F240F4D, 0x967197D5, 0x182F80B1,
		0x5E648A63, 0xFFB6FB92, 0x21B14993, 0x9F8DCD64,
		0x9DAECC3A, 0xA0766278, 0xA3F5FA55, 0x0F9546AD,
	]
	for i in range(16):
		assert keygen.state[i].value == expected_vector[i]
