// SPDX-License-Identifier: Apache-2.0
//
// libc function shims for MicroPython natmod.
//
// Vendored libraries (micro-ecc, mbedTLS) call standard C library functions
// which aren't available in the natmod environment.  This file provides
// implementations that forward to MicroPython's function table.

#include "py/dynruntime.h"

// dynruntime.h defines these as macros; undefine so we can provide
// real function symbols for the vendored libraries to link against.
#undef memset
#undef memcpy
#undef memmove

void *memset(void *s, int c, size_t n) {
    return mp_fun_table.memset_(s, c, n);
}

void *memcpy(void *dest, const void *src, size_t n) {
    // mp_fun_table has no memcpy_; memmove_ is a safe superset
    return mp_fun_table.memmove_(dest, src, n);
}

void *memmove(void *dest, const void *src, size_t n) {
    return mp_fun_table.memmove_(dest, src, n);
}

int memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *p1 = s1, *p2 = s2;
    for (size_t i = 0; i < n; i++) {
        if (p1[i] != p2[i]) {
            return p1[i] - p2[i];
        }
    }
    return 0;
}

size_t strlen(const char *s) {
    const char *p = s;
    while (*p) {
        p++;
    }
    return p - s;
}

int strcmp(const char *s1, const char *s2) {
    while (*s1 && *s1 == *s2) {
        s1++;
        s2++;
    }
    return (unsigned char)*s1 - (unsigned char)*s2;
}

// Memory allocation: forward to MicroPython's GC allocator via mp_fun_table.
void *calloc(size_t nmemb, size_t size) {
    size_t total = nmemb * size;
    // m_malloc maps to mp_fun_table.realloc_(NULL, total, true)
    void *ptr = m_malloc(total);
    if (ptr) {
        mp_fun_table.memset_(ptr, 0, total);
    }
    return ptr;
}

void free(void *ptr) {
    if (ptr) {
        // m_free maps to mp_fun_table.realloc_(ptr, 0, false)
        m_free(ptr);
    }
}

// Compiler builtins for byte swapping (needed on xtensa for GCM).
uint32_t __bswapsi2(uint32_t x) {
    return ((x >> 24) & 0xffu) | ((x >> 8) & 0xff00u) |
           ((x << 8) & 0xff0000u) | ((x << 24) & 0xff000000u);
}

uint64_t __bswapdi2(uint64_t x) {
    return ((uint64_t)__bswapsi2((uint32_t)x) << 32) |
           __bswapsi2((uint32_t)(x >> 32));
}

// mbedTLS platform_util.c calls explicit_bzero for secure zeroing.
void explicit_bzero(void *s, size_t n) {
    volatile unsigned char *p = s;
    while (n--) {
        *p++ = 0;
    }
}
