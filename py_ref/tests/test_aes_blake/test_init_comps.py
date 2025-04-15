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

from src import utils
from src.aes_blake import AESBlake, BlockSize, Operation
from src.blake_keygen import BlakeKeyGen

__all__ = [
    "fixture_get_padded_text",
    "fixture_init_components",
    "test_init_components_128",
    "test_init_components_256",
    "test_init_components_386",
    "test_init_components_512",
]


@pytest.fixture(name="get_padded_text", scope="module")
def fixture_get_padded_text():
    def closure(size: int):
        text = bytes(x for x in range(128))
        return utils.pkcs7_pad(text, size)

    return closure


@pytest.fixture(name="init_components", scope="function")
def fixture_init_components(get_padded_text):
    def closure(block_size: BlockSize, operation: Operation, pointer: int):
        key, nonce, context = b"", b"", b""
        keygen = BlakeKeyGen(key, nonce, context)
        cipher = AESBlake(key, context, block_size=block_size)
        size = cipher.block_size.value * 16
        text = get_padded_text(size)
        args = (keygen, text, pointer, 0, operation)
        chunks, blocks, gens = cipher.init_components(*args)
        return chunks, blocks, gens

    return closure


def test_init_components_128(init_components, get_padded_text):
    block_size = BlockSize.BITS_128
    size = block_size.value * 16
    text = get_padded_text(size)

    for operation in [Operation.ENC, Operation.DEC]:
        for pointer in range(0, len(text), size):
            args = (block_size, operation, pointer)
            chunks, blocks, gens = init_components(*args)

            assert len(chunks) == len(blocks) == len(gens) == 1
            assert chunks[0] == text[pointer : pointer + 16]

            for block, chunk, gen in zip(blocks, chunks, gens, strict=True):
                assert len(chunk) == 16
                assert bytes(block.state) == chunk
                assert gen.gi_frame.f_code.co_name == f"{operation.value}_generator"


def test_init_components_256(init_components, get_padded_text):
    block_size = BlockSize.BITS_256
    size = block_size.value * 16
    text = get_padded_text(size)

    for operation in [Operation.ENC, Operation.DEC]:
        for pointer in range(0, len(text), size):
            args = (block_size, operation, pointer)
            chunks, blocks, gens = init_components(*args)

            assert len(chunks) == len(blocks) == len(gens) == 2
            assert chunks[0] == text[pointer : pointer + 16]
            assert chunks[1] == text[pointer + 16 : pointer + 32]

            for block, chunk, gen in zip(blocks, chunks, gens, strict=True):
                assert len(chunk) == 16
                assert bytes(block.state) == chunk
                assert gen.gi_frame.f_code.co_name == f"{operation.value}_generator"


def test_init_components_386(init_components, get_padded_text):
    block_size = BlockSize.BITS_384
    size = block_size.value * 16
    text = get_padded_text(size)

    for operation in [Operation.ENC, Operation.DEC]:
        for pointer in range(0, len(text), size):
            args = (block_size, operation, pointer)
            chunks, blocks, gens = init_components(*args)

            assert len(chunks) == len(blocks) == len(gens) == 3
            assert chunks[0] == text[pointer : pointer + 16]
            assert chunks[1] == text[pointer + 16 : pointer + 32]
            assert chunks[2] == text[pointer + 32 : pointer + 48]

            for block, chunk, gen in zip(blocks, chunks, gens, strict=True):
                assert len(chunk) == 16
                assert bytes(block.state) == chunk
                assert gen.gi_frame.f_code.co_name == f"{operation.value}_generator"


def test_init_components_512(init_components, get_padded_text):
    block_size = BlockSize.BITS_512
    size = block_size.value * 16
    text = get_padded_text(size)

    for operation in [Operation.ENC, Operation.DEC]:
        for pointer in range(0, len(text), size):
            args = (block_size, operation, pointer)
            chunks, blocks, gens = init_components(*args)

            assert len(chunks) == len(blocks) == len(gens) == 4
            assert chunks[0] == text[pointer : pointer + 16]
            assert chunks[1] == text[pointer + 16 : pointer + 32]
            assert chunks[2] == text[pointer + 32 : pointer + 48]
            assert chunks[3] == text[pointer + 48 : pointer + 64]

            for block, chunk, gen in zip(blocks, chunks, gens, strict=True):
                assert len(chunk) == 16
                assert bytes(block.state) == chunk
                assert gen.gi_frame.f_code.co_name == f"{operation.value}_generator"
