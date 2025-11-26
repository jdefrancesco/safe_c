
/**
 * @file safe_c.h
 * @brief Defensive C utility helpers aligned with CERT C guidelines.
 *
 * This header centralizes overflow-aware allocation wrappers, string and memory
 * helpers, and lightweight logging primitives intended to make defensive coding
 * patterns ergonomic in C projects.  It exposes:
 * - Safe allocation utilities (`safe_malloc`, `safe_calloc`, `safe_realloc`) with
 *   multiplication overflow checks and zero-length guards.
 * - String helpers (`safe_strcpy`, `safe_strncpy`, `safe_strcat`, `safe_strnlen`,
 *   `safe_strdup`) that validate inputs and provide truncation diagnostics.
 * - Memory utilities (`safe_memset`, `safe_memcpy`) with explicit bounds checks.
 * - A truncation-aware `safe_snprintf` wrapper.
 * - A `safe_bounds_check` routine for offset/length validation.
 * - Logging macros with optional color highlighting and poison-aware free macros.
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

// If you want to disable color.
#ifndef SAFE_C_ENABLE_COLOR
    #define SAFE_C_ENABLE_COLOR 1
#endif

// Basic logging with VT100 color codes.
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
safe_c_log_impl( const char *level, const char *color,
                const char *fmt, va_list ap)
{

#if SAFE_C_ENABLE_LOGGING
    fprintf(stderr, "%s[safe_c][%s] ", color, level);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "%s\n", SAFE_C_COLOR_RESET);
#else
    (void)level;
    (void)color;
    (void)fmt;
    (void)ap;
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
 * @brief Safely multiplies two size_t operands and stores the result.
 *
 * Computes the product of @p a and @p b, storing it in @p result when the
 * multiplication does not overflow. If the output pointer is null, or an
 * overflow would occur, the function logs an error, sets @c errno (to
 * @c EINVAL for a null pointer or @c EOVERFLOW for arithmetic overflow), and
 * returns @c false. On success, the product is written to @p result and the
 * function returns @c true.
 *
 * @param a      First multiplicand.
 * @param b      Second multiplicand.
 * @param result Pointer to the storage location for the product.
 *
 * @retval true  The multiplication completed without overflow.
 * @retval false The result pointer was null or an overflow was detected.
 */
static inline bool
safe_umul(size_t a, size_t b, size_t *result)
{
    if (result == NULL) {
        SAFE_C_LOG_ERROR("safe_umul: result pointer is NULL");
        errno = EINVAL;
#if SAFE_C_ABORT_ON_ERROR
        abort();
#endif
        return false;
    }
    if ((a != 0) && (b > (SIZE_MAX / a))) {
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

// Backward-compatible alias.
static inline bool
safe_mul_overflow(size_t a, size_t b, size_t *result)
{
    return safe_umul(a, b, result);
}


#define SAFE_FREE(ptr) do {                     \
    if ((ptr) != NULL) {                        \
        free(ptr);                              \
        (ptr) = NULL;                           \
    }                                           \
} while (0)

#define SAFE_FREE_POISON(ptr) do {                          \
    if ((ptr) != NULL) {                                    \
        free(ptr);                                          \
        if (SAFE_C_ENABLE_POISON) {                         \
            (ptr) = (void*)(uintptr_t)SAFE_C_POISON_VALUE;  \
        } else {                                            \
            (ptr) = NULL;                                   \
        }                                                   \
    }                                                       \
} while (0)


/**
 * @brief Allocates memory with a non-zero size guard.
 *
 * Requests a block of @p n bytes using @c malloc after rejecting zero-length
 * allocations. When @p n is zero the function logs an error, sets @c errno to
 * @c EINVAL, and returns @c NULL. On allocation failure the underlying
 * allocator is expected to set @c errno (typically to @c ENOMEM).
 *
 * @param n Number of bytes to allocate.
 *
 * @return Pointer to the allocated block on success; otherwise @c NULL.
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
 * @brief Allocates zero-initialized memory with overflow detection.
 *
 * Multiplies @p count and @p size using ::safe_umul. When the multiplication
 * overflows or the total size would be zero, the function logs an error, sets
 * @c errno to @c EOVERFLOW, and returns @c NULL.
 *
 * @param count Number of elements to allocate.
 * @param size  Size of each element in bytes.
 *
 * @return Pointer to the zero-initialized block on success; otherwise @c NULL.
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
        SAFE_C_LOG_ERROR("safe_calloc: calloc(%zu, %zu) failed", count, size);
    }
    return p;
}

/**
 * @brief Reallocates memory with overflow and zero-size checks.
 *
 * Computes @p count * @p size via ::safe_umul before calling @c realloc. When
 * the multiplication overflows or yields zero, the function logs an error,
 * sets @c errno to @c EOVERFLOW, and returns @c NULL. On allocator failure the
 * return value is @c NULL and @c errno is left to the C library.
 *
 * @param ptr   Existing allocation or @c NULL.
 * @param count Number of elements requested.
 * @param size  Size of each element in bytes.
 *
 * @return Pointer to the resized block on success; otherwise @c NULL.
 */
static inline void* safe_realloc(void *ptr, size_t count, size_t size)
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


static inline int
safe_strcpy(char *dst, size_t dstsz, const char *src)
{
    if (!dst || !src || dstsz == 0) {
        SAFE_C_LOG_ERROR("safe_strcpy: invalid args dst=%p src=%p dstsz=%zu",
                         (void*)dst, (const void*)src, dstsz);
        return -1;
    }

    size_t len = strlen(src);
    if (len + 1 <= dstsz) {
        memcpy(dst, src, len + 1);
        return 0;
    }
    memcpy(dst, src, dstsz - 1);
    dst[dstsz - 1] = '\0';
    SAFE_C_LOG_WARN("safe_strcpy: truncated (src_len=%zu dstsz=%zu)", len, dstsz);
    return 1;
}

static inline int
safe_strncpy(char *dst, size_t dstsz, const char *src, size_t n) {
    if (!dst || !src || dstsz == 0) {
        SAFE_C_LOG_ERROR("safe_strncpy: invalid args dst=%p src=%p dstsz=%zu",
                         (void*)dst, (const void*)src, dstsz);
        return -1;
    }

    if (n + 1 <= dstsz) {
        memcpy(dst, src, n);
        dst[n] = '\0';
        return 0;
    }
    memcpy(dst, src, dstsz - 1);
    dst[dstsz - 1] = '\0';
    SAFE_C_LOG_WARN("safe_strncpy: truncated (n=%zu dstsz=%zu)", n, dstsz);
    return 1;
}



static inline size_t
safe_strnlen(const char *s, size_t maxlen)
{
    if (!s || maxlen == 0) {
        return 0;
    }

    const char *end = memchr(s, '\0', maxlen);
    return end ? (size_t)(end - s) : maxlen;
}

static inline int
safe_strcat(char *dst, size_t dstsz, const char *src)
{
    if (!dst || !src || dstsz == 0) {
        SAFE_C_LOG_ERROR("safe_strcat: invalid args dst=%p src=%p dstsz=%zu",
                         (void*)dst, (const void*)src, dstsz);
        return -1;
    }

    size_t dlen = safe_strnlen(dst, dstsz);
    if (dlen == dstsz) {
        SAFE_C_LOG_ERROR("safe_strcat: dst not null terminated within dstsz");
        return -1;
    }

    size_t slen = strlen(src);

    if (dlen + slen + 1 <= dstsz) {
        memcpy(dst + dlen, src, slen + 1);
        return 0;
    }

    size_t copy_len = dstsz - dlen - 1;
    memcpy(dst + dlen, src, copy_len);
    dst[dstsz - 1] = '\0';
    SAFE_C_LOG_WARN("safe_strcat: truncated (dlen=%zu slen=%zu dstsz=%zu)",
                    dlen, slen, dstsz);
    return 1;
}



/**
 * @brief Duplicates a string with argument validation.
 *
 * Uses ::safe_malloc to allocate space for a copy of @p src. When @p src is
 * @c NULL the function logs an error, sets @c errno to @c EINVAL, and returns
 * @c NULL.
 *
 * @param src Null-terminated string to duplicate.
 *
 * @return Newly allocated duplicate on success; otherwise @c NULL.
 */
static inline char*
safe_strdup(const char *src)
{
    if (!src) {
        SAFE_C_LOG_ERROR("safe_strdup: src is NULL");
        errno = EINVAL;
        return NULL;
    }
    size_t len = strlen(src);
    char *p = safe_malloc(len + 1);
    if (!p) return NULL;
    memcpy(p, src, len + 1);
    return p;
}

/*
    safe_memset: verifies bounds, prevents UB on NULL or too-large n
*/
static inline int
safe_memset(void *dst, size_t dstsz, int value, size_t n)
{
    if (!dst || n > dstsz) {
        SAFE_C_LOG_ERROR("safe_memset: invalid args dst=%p dstsz=%zu n=%zu",
                         dst, dstsz, n);
        return -1;
    }
    memset(dst, value, n);
    return 0;
}

/*
    safe_memcpy: validates sizes
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

/*
    safe_snprintf: truncation-aware wrapper
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


static inline int
safe_bounds_check(size_t offset, size_t size, size_t buf_size)
{
    if (offset > buf_size) {
        SAFE_C_LOG_ERROR("safe_bounds_check: offset > buf_size (%zu > %zu)", offset, buf_size);
        return -1;
    }
    if (size > buf_size - offset) {
        SAFE_C_LOG_ERROR("safe_bounds_check: size too large (%zu, offset=%zu buf_size=%zu)",
                         size, offset, buf_size);
        return -1;
    }
    return 0;
}

#endif /* SAFE_C_H */
