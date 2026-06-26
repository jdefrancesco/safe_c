#ifndef SAFE_C_HELPERS_H
#define SAFE_C_HELPERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

static inline bool
safe_size_add(size_t a, size_t b, size_t *out)
{
    if (out == NULL)
        return false;

    if (a > SIZE_MAX - b)
        return false;

    *out = a + b;
    return true;
}

static inline bool
safe_size_sub(size_t a, size_t b, size_t *out)
{
    if (out == NULL)
        return false;

    if (a < b)
        return false;

    *out = a - b;
    return true;
}


static inline bool
safe_size_mul(size_t a, size_t b, size_t *out)
{
    if (out == NULL)
        return false;

    if (a != 0 && b > SIZE_MAX / a)
        return false;

    *out = a * b;
    return true;
}


/*
 * Checks whether [offset, offset + len) fits inside [0, total).
 *
 * Avoids:
 *
 *     if (offset + len > total)
 *
 * because offset + len can wrap.
 */
static inline bool
safe_size_range(size_t offset, size_t len, size_t total)
{
    if (offset > total)
        return false;

    if (len > total - offset)
        return false;

    return true;
}


/*
 * Safe count * element_size helper.
 */
static inline bool
safe_array_bytes(size_t count, size_t elem_size, size_t *out)
{
    return safe_size_mul(count, elem_size, out);
}



static inline bool
safe_u64_add(uint64_t a, uint64_t b, uint64_t *out)
{
    if (out == NULL)
        return false;

    if (a > UINT64_MAX - b)
        return false;

    *out = a + b;
    return true;
}


static inline bool
safe_u64_sub(uint64_t a, uint64_t b, uint64_t *out)
{
    if (out == NULL)
        return false;

    if (a < b)
        return false;

    *out = a - b;
    return true;
}


static inline bool
safe_u64_mul(uint64_t a, uint64_t b, uint64_t *out)
{
    if (out == NULL)
        return false;

    if (a != 0 && b > UINT64_MAX / a)
        return false;

    *out = a * b;
    return true;
}


/*
 * Left shift that rejects invalid shift counts and rejects lost bits.
 *
 * Example:
 *
 *     safe_u64_lshift(1, 63, &out)  => true
 *     safe_u64_lshift(1, 64, &out)  => false
 *     safe_u64_lshift(UINT64_MAX, 1, &out) => false
 */
static inline bool
safe_u64_lshift(uint64_t value, unsigned shift, uint64_t *out)
{
    if (out == NULL)
        return false;

    if (shift >= 64)
        return false;

    if (shift != 0 && value > (UINT64_MAX >> shift))
        return false;

    *out = value << shift;
    return true;
}

/*
 * Create a low-bit mask.
 *
 * bits = 0  => 0
 * bits = 1  => 0x1
 * bits = 8  => 0xff
 * bits = 64 => UINT64_MAX
 */
static inline bool
safe_u64_mask(unsigned bits, uint64_t *out)
{

    if (out == NULL)
        return false;

    if (bits > 64)
        return false;

    if (bits == 64) {
        *out = UINT64_MAX;
        return true;
    }

    if (bits == 0) {
        *out = 0;
        return true;
    }

    *out = (UINT64_C(1) << bits) - 1;
    return true;
}

static inline bool
safe_i64_add(int64_t a, int64_t b, int64_t *out)
{

    if (out == NULL)
        return false;

    if (b > 0 && a > INT64_MAX - b)
        return false;

    if (b < 0 && a < INT64_MIN - b)
        return false;

    *out = a + b;
    return true;
}

static inline bool
safe_i64_sub(int64_t a, int64_t b, int64_t *out)
{

    if (out == NULL)
        return false;

    if (b > 0 && a < INT64_MIN + b)
        return false;

    if (b < 0 && a > INT64_MAX + b)
        return false;

    *out = a - b;
    return true;
}

static inline bool
safe_i64_mul(int64_t a, int64_t b, int64_t *out)
{

    if (out == NULL)
        return false;

    if (a == 0 || b == 0) {
        *out = 0;
        return true;
    }

    if (a == -1 && b == INT64_MIN)
        return false;

    if (b == -1 && a == INT64_MIN)
        return false;

    if (a > 0) {
        if (b > 0) {
            if (a > INT64_MAX / b)
                return false;
        } else {
            if (b < INT64_MIN / a)
                return false;
        }
    } else {
        if (b > 0) {
            if (a < INT64_MIN / b)
                return false;
        } else {
            if (b < INT64_MAX / a)
                return false;
        }
    }

    *out = a * b;
    return true;
}


static inline bool
safe_int_to_size(int value, size_t *out)
{
    if (out == NULL)
        return false;

    if (value < 0)
        return false;

    if ((uintmax_t)value > (uintmax_t)SIZE_MAX)
        return false;

    *out = (size_t)value;
    return true;
}


static inline bool
safe_i64_to_size(int64_t value, size_t *out)
{
    if (out == NULL)
        return false;

    if (value < 0)
        return false;

    if ((uintmax_t)value > (uintmax_t)SIZE_MAX)
        return false;

    *out = (size_t)value;
    return true;
}


static inline bool
safe_u64_to_size(uint64_t value, size_t *out)
{
    if (out == NULL)
        return false;

    if ((uintmax_t)value > (uintmax_t)SIZE_MAX)
        return false;

    *out = (size_t)value;
    return true;
}


static inline bool
safe_size_to_int(size_t value, int *out)
{
    if (out == NULL)
        return false;

    if ((uintmax_t)value > (uintmax_t)INT_MAX)
        return false;

    *out = (int)value;
    return true;
}


static inline bool
safe_i64_to_int(int64_t value, int *out)
{
    if (out == NULL)
        return false;

    if (value < (int64_t)INT_MIN || value > (int64_t)INT_MAX)
        return false;

    *out = (int)value;
    return true;
}


static inline bool
safe_size_to_u32(size_t value, uint32_t *out)
{
    if (out == NULL)
        return false;

    if ((uintmax_t)value > (uintmax_t)UINT32_MAX)
        return false;

    *out = (uint32_t)value;
    return true;
}


static inline bool
safe_size_to_u16(size_t value, uint16_t *out)
{
    if (out == NULL)
        return false;

    if ((uintmax_t)value > (uintmax_t)UINT16_MAX)
        return false;

    *out = (uint16_t)value;
    return true;
}


static inline bool
safe_malloc_array(size_t count, size_t elem_size, void **out)
{

    if (out == NULL)
        return false;

    *out = NULL;

    size_t bytes;
    if (!safe_array_bytes(count, elem_size, &bytes))
        return false;

    /*
     * malloc(0) behavior is implementation-defined-ish from a usability
     * perspective, so allocate 1 byte for zero-length requests.
     */
    if (bytes == 0)
        bytes = 1;

    void *ptr = malloc(bytes);
    if (ptr == NULL)
        return false;

    *out = ptr;
    return true;
}


static inline bool safe_calloc_array(size_t count, size_t elem_size, void **out)
{
    if (out == NULL)
        return false;

    *out = NULL;

    size_t bytes;
    if (!safe_array_bytes(count, elem_size, &bytes))
        return false;

    if (bytes == 0)
        bytes = 1;

    /*
     * calloc(1, bytes) gives us zeroed memory after we already checked
     * count * elem_size ourselves.
     */
    void *ptr = calloc(1, bytes);
    if (ptr == NULL)
        return false;

    *out = ptr;
    return true;
}


static inline bool
safe_realloc_array(void **ptr, size_t count, size_t elem_size)
{
    if (ptr == NULL)
        return false;

    size_t bytes;
    if (!safe_array_bytes(count, elem_size, &bytes))
        return false;

    if (bytes == 0)
        bytes = 1;

    void *new_ptr = realloc(*ptr, bytes);
    if (new_ptr == NULL)
        return false;

    *ptr = new_ptr;
    return true;
}


static inline bool
safe_memcpy_into(void *dst, size_t dst_size, const void *src, size_t n)
{
    if (n > dst_size)
        return false;

    if (n == 0)
        return true;

    if (dst == NULL || src == NULL)
        return false;

    memcpy(dst, src, n);
    return true;
}


static inline bool
safe_memmove_into(void *dst, size_t dst_size, const void *src, size_t n)
{
    if (n > dst_size)
        return false;

    if (n == 0)
        return true;

    if (dst == NULL || src == NULL)
        return false;

    memmove(dst, src, n);
    return true;
}

#endif
