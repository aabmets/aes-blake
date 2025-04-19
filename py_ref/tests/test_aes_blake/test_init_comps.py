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

from blake_keygen import KDFDomain
from src import utils
from src.aes_blake import AESBlake, BlockSize
from src.aes_block import AESBlock, Operation

__all__ = [
    "get_padded_text",
    "init_components",
    "fixture_init_components_tester",
    "test_init_components_128",
    "test_init_components_256",
    "test_init_components_384",
    "test_init_components_512",
]


def get_padded_text(size: int) -> bytes:
    text = bytes(x for x in range(128))
    return utils.pkcs7_pad(text, size)


def init_components(
        text: bytes, pointer: int, operation: Operation, block_size: BlockSize
) -> tuple[list[bytes], list[AESBlock]]:
    key, nonce, context = bytes(64), bytes(32), bytes(128)
    cipher = AESBlake(key, context, block_size)
    cipher.reset(nonce)
    args = (text, pointer, 0, operation, KDFDomain.CIPHER_OPS)
    return cipher.init_components(*args)


@pytest.fixture(name="init_components_tester", scope="function")
def fixture_init_components_tester():
    def closure(block_size: BlockSize):
        aes_total_bytes = block_size.value * AESBlake.aes_block_size
        text = get_padded_text(aes_total_bytes)

        for operation in [Operation.ENCRYPT, Operation.DECRYPT]:
            for pointer in range(0, len(text), aes_total_bytes):
                data_chunks, aes_blocks = init_components(text, pointer, operation, block_size)

                assert len(data_chunks) == len(aes_blocks) == block_size.value
                for chunk, block in zip(data_chunks, aes_blocks, strict=True):
                    assert len(chunk) == AESBlake.aes_block_size
                    assert bytes(block.state) == chunk
                    gen_name = f"{operation.value}_generator"
                    assert block.generator.__name__ == gen_name
    return closure


def test_init_components_128(init_components_tester):
    init_components_tester(BlockSize.BITS_128)


def test_init_components_256(init_components_tester):
    init_components_tester(BlockSize.BITS_256)


def test_init_components_384(init_components_tester):
    init_components_tester(BlockSize.BITS_384)


def test_init_components_512(init_components_tester):
    init_components_tester(BlockSize.BITS_512)
