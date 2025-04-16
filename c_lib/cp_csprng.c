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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
    #include <wincrypt.h>

    static HCRYPTPROV global_csprng_prov;

    void csprng_open(void) {
        if (!CryptAcquireContext(&global_csprng_prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            fprintf(stderr, "CryptAcquireContext failed: %lu\n", GetLastError());
            exit(EXIT_FAILURE);
        }
    }

    uint8_t csprng_read(void) {
        uint8_t value;
        if (!CryptGenRandom(global_csprng_prov, sizeof(value), &value)) {
            fprintf(stderr, "CryptGenRandom failed: %lu\n", GetLastError());
            exit(EXIT_FAILURE);
        }
        return value;
    }

    void csprng_close(void) {
        CryptReleaseContext(global_csprng_prov, 0);
    }
#else
    #include <fcntl.h>
    #include <unistd.h>

    static int global_csprng_fd;

    void csprng_open(void) {
        global_csprng_fd = open("/dev/random", O_RDONLY);
        if (global_csprng_fd < 0) {
            perror("Failed to open /dev/random");
            exit(EXIT_FAILURE);
        }
    }

    uint8_t csprng_read(void) {
        uint8_t value;
        ssize_t ret = read(global_csprng_fd, &value, sizeof(value));
        if (ret != sizeof(value)) {
            perror("Failed to read /dev/random");
            exit(EXIT_FAILURE);
        }
        return value;
    }

    void csprng_close(void) {
        close(global_csprng_fd);
    }
#endif
