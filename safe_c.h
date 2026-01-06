/**
 * @file safe_c.h
 * @brief Defensive C utility helpers aligned with CERT C guidelines.
 *
 *
 * @author J. DeFrancesco
 */

#ifndef __SAFE_C_H
#define __SAFE_C_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <stdbool.h>

#ifndef SAFE_C_POISON_VALUE
    #define SAFE_C_POISON_VALUE 0xDEADBEEF
#endif

#ifndef SAFE_C_ENABLE_POISON
    #define SAFE_C_ENABLE_POISON 1
#endif

#ifndef SAFE_C_ABORT_ON_ERROR
    #define SAFE_C_ABORT_ON_ERROR 0
#endif

#ifndef SAFE_C_ENABLE_LOGGING
    #define SAFE_C_ENABLE_LOGGING 1
#endif

#ifndef SAFE_C_ENABLE_COLOR
    #define SAFE_C_ENABLE_COLOR 1
#endif

#ifndef SAFE_C_MAX_STR
    #define SAFE_C_MAX_STR (1UL << 20)
#endif

#if SAFE_C_ENABLE_POISON
extern int safe_c_poison_sentinel_;
#define SAFE_C_POISON_PTR ((void *)&safe_c_poison_sentinel_)
#endif

#if SAFE_C_ENABLE_COLOR
    #define SAFE_C_COLOR_RED    "\033[31m"
    #define SAFE_C_COLOR_YELLOW "\033[33m"
    #define SAFE_C_COLOR_GREEN  "\033[32m"
    #define SAFE_C_COLOR_BLUE   "\033[34m"
    #define SAFE_C_COLOR_RESET  "\033[0m"
#else
    #define SAFE_C_COLOR_RED    ""
    #define SAFE_C_COLOR_YELLOW ""
    #define SAFE_C_COLOR_GREEN  ""
    #define SAFE_C_COLOR_BLUE   ""
    #define SAFE_C_COLOR_RESET  ""
#endif

static inline void
safe_c_log_impl(const char *level, const char *color, const char *fmt, va_list ap)
{
#if SAFE_C_ENABLE_LOGGING
    fprintf(stderr, "%s[safe_c][%s] ", color, level);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "%s\n", SAFE_C_COLOR_RESET);
#else
    (void)level; (void)color; (void)fmt; (void)ap;
#endif
}

static inline void 
safe_c_log_error(const char *fmt, ...)
{
    va_list ap; 
    va_start(ap, fmt);
    safe_c_log_impl("ERROR", SAFE_C_COLOR_RED, fmt, ap);
    va_end(ap);
}

static inline void 
safe_c_log_warn(const char *fmt, ...)
{
    va_list ap; 
    va_start(ap, fmt);
    safe_c_log_impl("WARN", SAFE_C_COLOR_YELLOW, fmt, ap);
    va_end(ap);
}

static inline void 
safe_c_log_info(const char *fmt, ...)
{
    va_list ap; 
    va_start(ap, fmt);
    safe_c_log_impl("INFO", SAFE_C_COLOR_GREEN, fmt, ap);
    va_end(ap);
}

static inline void 
safe_c_log_debug(const char *fmt, ...)
{
    va_list ap; 
    va_start(ap, fmt);
    safe_c_log_impl("DEBUG", SAFE_C_COLOR_BLUE, fmt, ap);
    va_end(ap);
}

#define SAFE_C_LOG_ERROR(...) safe_c_log_error(__VA_ARGS__)
#define SAFE_C_LOG_WARN(...)  safe_c_log_warn(__VA_ARGS__)
#define SAFE_C_LOG_INFO(...)  safe_c_log_info(__VA_ARGS__)
#define SAFE_C_LOG_DEBUG(...) safe_c_log_debug(__VA_ARGS__)

/**
 * @brief Computes the length of a string up to a maximum number of characters.
 *
 * @param s Pointer to the null-terminated string to measure.
 * @param maxlen Maximum number of characters to examine.
 * @return The number of characters before the null terminator or @p maxlen if no null terminator is found.
 */
static inline size_t
safe_strnlen(const char *s, size_t maxlen)
{
    if (!s || maxlen == 0) {
        return 0;
    }
    const char *end = memchr(s, '\0', maxlen);
    return end ? (size_t)(end - s) : maxlen;
}


/**
 * Safely multiplies two size_t values, reporting overflow.
 *
 * Performs the multiplication of @p a and @p b, writing the product to @p result.
 * Returns true on success. If @p result is null, sets errno to EINVAL and logs an error.
 * If the multiplication would overflow, sets errno to EOVERFLOW, logs an error, and fails.
 *
 * @param a First multiplicand.
 * @param b Second multiplicand.
 * @param result Pointer to store the product.
 * @return true if the multiplication succeeds without overflow; otherwise false.
 */
static inline bool
safe_umul(size_t a, size_t b, size_t *result)
{
    if (!result) {
        SAFE_C_LOG_ERROR("safe_umul: result pointer is NULL");
        errno = EINVAL;
#if SAFE_C_ABORT_ON_ERROR
        abort();
#endif
        return false;
    }
    if (a != 0 && b > SIZE_MAX / a) {
        SAFE_C_LOG_ERROR("safe_umul: overflow (%zu * %zu)", a, b);
        errno = EOVERFLOW;
#if SAFE_C_ABORT_ON_ERROR
        abort();
#endif
        return false;
    }
    *result = a * b;
    return true;
}

/**
 * @brief Checks whether the multiplication of two size_t values overflows.
 *
 * @param a First multiplicand.
 * @param b Second multiplicand.
 * @param result Pointer that receives the product when no overflow occurs.
 *
 * @return true if the multiplication results in an overflow; otherwise false.
 */
static inline bool
safe_mul_overflow(size_t a, size_t b, size_t *result)
{
    return safe_umul(a, b, result);
}

#define SAFE_FREE(ptr) do {          \
    if ((ptr) != NULL) {             \
        free(ptr);                   \
        (ptr) = NULL;                \
    }                                \
} while (0)

#define SAFE_FREE_POISON(ptr) do {                 \
    if ((ptr) != NULL) {                           \
        free(ptr);                                 \
        if (SAFE_C_ENABLE_POISON) {                \
            (ptr) = SAFE_C_POISON_PTR;             \
        } else {                                   \
            (ptr) = NULL;                          \
        }                                          \
    }                                              \
} while (0)

/**
 * @brief Allocates memory with additional safety checks and logging.
 *
 * Logs a warning and sets @c errno to @c EINVAL when zero bytes are requested,
 * optionally aborting the program if @c SAFE_C_ABORT_ON_ERROR is enabled,
 * and returns @c NULL in that case. Delegates to @c malloc(size_t) for non-zero
 * sizes, emitting an error log if allocation fails, and returns the allocated
 * memory pointer or @c NULL if the allocation could not be completed.
 *
 * @param n Number of bytes to allocate; must be greater than zero.
 * @return Pointer to the allocated memory on success, or @c NULL on failure.
 */
static inline void *
safe_malloc(size_t n)
{
    if (n == 0) {
        SAFE_C_LOG_WARN("safe_malloc: requested size 0");
        errno = EINVAL;
#if SAFE_C_ABORT_ON_ERROR
        abort();
#endif
        return NULL;
    }
    void *p = malloc(n);
    if (!p) {
        SAFE_C_LOG_ERROR("safe_malloc: malloc(%zu) failed", n);
    }
    return p;
}

/**
 * @brief Allocates zero-initialized memory for an array with overflow checking.
 *
 * This helper verifies that multiplying @p count by @p size does not overflow and
 * that the resulting total is non-zero before calling `calloc`.
 *
 * @param count Number of elements to allocate.
 * @param size  Size of each element in bytes.
 *
 * @return Pointer to the allocated zero-initialized memory on success; otherwise
 *         @c NULL is returned and @c errno is set to @c EOVERFLOW.
 *
 * @note When @c SAFE_C_ABORT_ON_ERROR is enabled, the process aborts on overflow.
 */
static inline void *
safe_calloc(size_t count, size_t size)
{
    size_t total;
    if (safe_umul(count, size, &total) == false || total == 0) {
        SAFE_C_LOG_ERROR("safe_calloc: overflow or zero (%zu * %zu)", count, size);
        errno = EOVERFLOW;
#if SAFE_C_ABORT_ON_ERROR
        abort();
#endif
        return NULL;
    }
    void *p = calloc(count, size);
    if (!p) {
        SAFE_C_LOG_ERROR("safe_calloc: calloc(%zu,%zu) failed", count, size);
    }
    return p;
}

/**
 * @brief Reallocate memory with overflow protection.
 *
 * Attempts to resize the allocation referenced by @p ptr to accommodate
 * @p count elements of @p size bytes each, validating that the product
 * does not overflow and is non-zero before invoking realloc.
 *
 * @param ptr    Pointer to the existing allocation, or nullptr for a new allocation.
 * @param count  Number of elements requested.
 * @param size   Size in bytes of each element.
 *
 * @return Pointer to the resized allocation on success, or nullptr if allocation
 *         fails or an invalid size is requested. On failure, errno is set to EOVERFLOW.
 */
static inline void *
safe_realloc(void *ptr, size_t count, size_t size)
{
    size_t total;
    if (safe_umul(count, size, &total) == false || total == 0) {
        SAFE_C_LOG_ERROR("safe_realloc: overflow or zero (%zu * %zu)", count, size);
        errno = EOVERFLOW;
#if SAFE_C_ABORT_ON_ERROR
        abort();
#endif
        return NULL;
    }
    void *p = realloc(ptr, total);
    if (!p && total != 0) {
        SAFE_C_LOG_ERROR("safe_realloc: realloc(%p, %zu) failed", ptr, total);
    }
    return p;
}

/**
 * @brief Copies a source string into a destination buffer with bounds checking.
 *
 * This function validates the input arguments, calculates the source length up to
 * SAFE_C_MAX_STR, and copies as much data as possible into the destination buffer.
 * It ensures the destination is null-terminated and logs warnings when the source
 * length exceeds SAFE_C_MAX_STR or when truncation occurs.
 *
 * @param dst    Destination buffer to receive the copied string.
 * @param dstsz  Size of the destination buffer in bytes.
 * @param src    Null-terminated source string to copy.
 *
 * @return 0 on success, 1 if truncation occurs, and -1 for invalid input arguments.
 */
static inline int
safe_strcpy(char *dst, size_t dstsz, const char *src)
{
    if (!dst || !src || dstsz == 0) {
        SAFE_C_LOG_ERROR("safe_strcpy: invalid args dst=%p src=%p dstsz=%zu",
                         (void*)dst, (const void*)src, dstsz);
        return -1;
    }

    size_t len = safe_strnlen(src, SAFE_C_MAX_STR);
    int truncated = 0;
    if (len == SAFE_C_MAX_STR) {
        truncated = 1;
        SAFE_C_LOG_WARN("safe_strcpy: src length >= SAFE_C_MAX_STR");
    }

    if (!truncated && len + 1 <= dstsz) {
        memcpy(dst, src, len + 1);
        return 0;
    }

    size_t copy_len = (len < dstsz) ? len : dstsz - 1;
    memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';
    SAFE_C_LOG_WARN("safe_strcpy: truncated (src_len=%zu dstsz=%zu)", len, dstsz);
    return 1;
}

/**
 * @brief Safely copies up to @p n characters from a source string into a destination buffer.
 *
 * Copies from @p src into @p dst ensuring the destination is always NUL-terminated when
 * @p dstsz is nonzero. The routine checks for invalid arguments, computes the bounded length
 * of the source via safe_strnlen, and logs errors or warnings through SAFE_C_LOG macros.
 *
 * @param dst    Destination buffer that will receive the copied characters.
 * @param dstsz  Total size of the destination buffer in bytes.
 * @param src    Source string to copy from.
 * @param n      Maximum number of characters to examine from the source.
 *
 * @return 0 on success, 1 if truncation occurred, or -1 on invalid arguments.
 */
static inline int
safe_strncpy(char *dst, size_t dstsz, const char *src, size_t n)
{
    if (!dst || !src || dstsz == 0) {
        SAFE_C_LOG_ERROR("safe_strncpy: invalid args dst=%p src=%p dstsz=%zu",
                         (void*)dst, (const void*)src, dstsz);
        return -1;
    }

    size_t slen = safe_strnlen(src, n);
    int truncated = 0;

    if (slen == n) {
        truncated = 1;
    }

    size_t copy_len;
    if (slen < dstsz) {               // ensures slen <= dstsz - 1
        copy_len = slen;
    } else {
        truncated = 1;
        copy_len = dstsz ? dstsz - 1 : 0;
    }

    memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';

    if (truncated) {
        SAFE_C_LOG_WARN("safe_strncpy: truncated (n=%zu slen=%zu dstsz=%zu)",
                        n, slen, dstsz);
        return 1;
    }

    return 0;
}

/**
 * Safely concatenates the NUL-terminated string `src` to the end of `dst`
 * without writing past the bounds of the destination buffer.
 *
 * @param dst   Destination buffer containing an existing NUL-terminated string.
 * @param dstsz Total size in bytes of the destination buffer.
 * @param src   Source NUL-terminated string to append to `dst`.
 *
 * @return 0 on success, 1 if truncation occurred, or -1 if invalid arguments
 *         are detected or the destination buffer is not properly terminated.
 */
static inline int
safe_strcat(char *dst, size_t dstsz, const char *src)
{
    if (!dst || !src || dstsz == 0) {
        SAFE_C_LOG_ERROR("safe_strcat: invalid args dst=%p src=%p dstsz=%zu",
                         (void*)dst, (const void*)src, dstsz);
        return -1;
    }

    size_t dlen = safe_strnlen(dst, dstsz);
    if (dlen >= dstsz) {
        SAFE_C_LOG_ERROR("safe_strcat: dst not null terminated");
        return -1;
    }

    size_t avail = dstsz - dlen;      // >= 1 at this point
    size_t slen = safe_strnlen(src, SAFE_C_MAX_STR);
    int truncated = 0;
    if (slen == SAFE_C_MAX_STR) {
        truncated = 1;
        SAFE_C_LOG_WARN("safe_strcat: src length >= SAFE_C_MAX_STR");
    }

    if (!truncated && slen + 1 <= avail) {          // or: if (slen < avail)
        memcpy(dst + dlen, src, slen + 1);
        return 0;
    }
    size_t copy_len = (slen < avail) ? slen : avail - 1;
    memcpy(dst + dlen, src, copy_len);
    dst[dstsz - 1] = '\0';
    SAFE_C_LOG_WARN("safe_strcat: truncated (dlen=%zu slen=%zu dstsz=%zu)",
                    dlen, slen, dstsz);
    return 1;
}

/**
 * @brief Duplicates a C-string using safe memory utilities.
 *
 * Before copying, the source pointer is validated. If it is null, an error is
 * logged, errno is set to EINVAL, and nullptr is returned. The function uses
 * safe_strnlen to cap the length at SAFE_C_MAX_STR, logging a warning when the
 * source length reaches that limit. Memory is allocated via safe_malloc, and
 * on success the null-terminated copy is returned; on allocation failure,
 * nullptr is returned.
 *
 * @param src Pointer to the null-terminated string to duplicate.
 * @return Pointer to the duplicated string on success, or nullptr on failure.
 */
static inline char *
safe_strdup(const char *src)
{
    if (!src) {
        SAFE_C_LOG_ERROR("safe_strdup: src is NULL");
        errno = EINVAL;
        return NULL;
    }
    size_t len = safe_strnlen(src, SAFE_C_MAX_STR);
    if (len == SAFE_C_MAX_STR) {
        SAFE_C_LOG_WARN("safe_strdup: src length >= SAFE_C_MAX_STR");
    }
    char *p = safe_malloc(len + 1);
    if (!p) return NULL;
    memcpy(p, src, len);
    p[len] = '\0';
    return p;
}

/**
 * @brief Safely fills a destination buffer with a specified byte value.
 *
 * Ensures the destination pointer is valid and the requested number of bytes
 * does not exceed the buffer size before invoking memset.
 *
 * @param dst    Pointer to the destination buffer.
 * @param dstsz  Total size of the destination buffer in bytes.
 * @param value  The byte value to be written.
 * @param n      Number of bytes to set in the destination buffer.
 *
 * @return 0 on success, or -1 if the inputs are invalid.
 */
static inline int
safe_memset(void *dst, size_t dstsz, int value, size_t n)
{
    if (!dst || n > dstsz) {
        SAFE_C_LOG_ERROR("safe_memset: invalid args dst=%p dstsz=%zu n=%zu",
                         dst, dstsz, n);
        return -1;
    }
    unsigned char b = (unsigned char)value;
    memset(dst, b, n);
    return 0;
}


/**
 * @brief Safely copies a block of memory from one location to another.
 *
 * Validates that both source and destination pointers are non-null and that the destination buffer
 * is large enough to hold the source data before performing the copy.
 *
 * @param dst Pointer to the destination buffer where data will be copied.
 * @param dstsz Size of the destination buffer in bytes.
 * @param src Pointer to the source data to copy.
 * @param srcsz Number of bytes to copy from the source buffer.
 * @return 0 on success, or -1 if the arguments are invalid (null pointers or insufficient space).
 */
static inline int
safe_memcpy(void *dst, size_t dstsz, const void *src, size_t srcsz)
{
    if (!dst || !src || dstsz < srcsz) {
        SAFE_C_LOG_ERROR("safe_memcpy: invalid args dst=%p src=%p dstsz=%zu srcsz=%zu",
                         dst, src, dstsz, srcsz);
        return -1;
    }
    memcpy(dst, src, srcsz);
    return 0;
}

/**
 * @brief Safely prints formatted data into a destination buffer.
 *
 * Wraps vsnprintf to validate arguments, detect formatting errors, and log issues.
 *
 * @param dst    Destination buffer to receive the formatted string.
 * @param dstsz  Size of the destination buffer in bytes; must be greater than zero.
 * @param fmt    printf-style format string describing the output.
 * @param ...    Additional arguments matching the format specifiers in @p fmt.
 *
 * @return 0 on success, 1 if the output was truncated, or -1 on invalid arguments or formatting failure.
 */
static inline int
safe_snprintf(char *dst, size_t dstsz, const char *fmt, ...)
{
    if (!dst || !fmt || dstsz == 0) {
        SAFE_C_LOG_ERROR("safe_snprintf: invalid args dst=%p fmt=%p dstsz=%zu",
                         (void*)dst, (const void*)fmt, dstsz);
        return -1;
    }
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf(dst, dstsz, fmt, ap);
    va_end(ap);
    if (r < 0) {
        SAFE_C_LOG_ERROR("safe_snprintf: vsnprintf error");
        return -1;
    }
    if ((size_t)r >= dstsz) {
        SAFE_C_LOG_WARN("safe_snprintf: truncated (needed=%d dstsz=%zu)", r, dstsz);
        return 1;
    }
    return 0;
}

/**
 * @brief Validates that accessing a buffer with the given offset and size remains within bounds.
 *
 * @param offset The starting position within the buffer.
 * @param size The number of bytes to access from the starting offset.
 * @param buf_size The total size of the buffer in bytes.
 * @return 0 if the access is within bounds; -1 if the offset exceeds the buffer size or
 *         if the requested range would overflow the buffer.
 */
static inline int
safe_bounds_check(size_t offset, size_t size, size_t buf_size)
{
    if (offset > buf_size) {
        SAFE_C_LOG_ERROR("safe_bounds_check: offset > buf_size (%zu > %zu)",
                         offset, buf_size);
        return -1;
    }
    if (size > buf_size - offset) {
        SAFE_C_LOG_ERROR("safe_bounds_check: size too large (%zu offset=%zu buf_size=%zu)",
                         size, offset, buf_size);
        return -1;
    }
    return 0;
}

#endif /* __SAFE_C_H */
