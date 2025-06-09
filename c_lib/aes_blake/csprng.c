/*
 *   Apache License 2.0
 *
 *   Copyright (c) 2024, Mattias Aabmets
 *
 *   The contents of this file are subject to the terms and conditions defined in the License.
 *   You may not use, modify, or distribute this file except in compliance with the License.
 *
 *   SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>


#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#include <wincrypt.h>

void csprng_read_array(uint8_t* buffer, const uint32_t length) {
    const NTSTATUS status = BCryptGenRandom(
        NULL, buffer, length, BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    if (status != 0) {
        fprintf(stderr, "BCryptGenRandom failed: 0x%lx\n", status);
        exit(EXIT_FAILURE);
    }
}

uint8_t csprng_read(void) {
    uint8_t value;
    csprng_read_array(&value, 1);
    return value;
}

#else
#include <fcntl.h>
#include <unistd.h>

void csprng_read_array(uint8_t* buffer, const uint32_t length) {
    const int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("Failed to open /dev/urandom");
        exit(EXIT_FAILURE);
    }
    const ssize_t ret = read(fd, buffer, length);
    close(fd);
    if (ret != length) {
        perror("Failed to read /dev/urandom");
        exit(EXIT_FAILURE);
    }
}

uint8_t csprng_read(void) {
    uint8_t value;
    csprng_read_array(&value, 1);
    return value;
}

#endif